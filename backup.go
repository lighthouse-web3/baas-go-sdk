package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const packTargetSize = 256 * 1024 * 1024 // 256 MiB
const defaultConcurrency = 8

type fileEntry struct {
	fullPath     string
	relativePath string
	info         os.FileInfo
}

type prevFileInfo struct {
	mtime   string
	size    int64
	content []string
}

type packBuffer struct {
	chunks    []packChunk
	totalSize int64
}

type packChunk struct {
	hash             string
	data             []byte // stored bytes (possibly compressed)
	chunkTyp         string // "data" or "tree"
	compression      string
	uncompressedSize int
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func walkDirectory(rootPath string) ([]fileEntry, error) {
	var entries []fileEntry
	rootLen := len(rootPath)

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == rootPath {
			return nil
		}
		rel := path[rootLen+1:]
		entries = append(entries, fileEntry{fullPath: path, relativePath: rel, info: info})
		return nil
	})
	return entries, err
}

func parentDir(relPath string) string {
	d := filepath.Dir(relPath)
	if d == "." {
		return ""
	}
	return filepath.ToSlash(d)
}

func toFileNode(entry fileEntry, chunkHashes []string) TreeNode {
	mode := int(entry.info.Mode().Perm())
	size := entry.info.Size()
	mtime := entry.info.ModTime().UTC().Format("2006-01-02T15:04:05.000Z")
	return TreeNode{
		Name:    filepath.Base(entry.relativePath),
		Type:    "file",
		Mode:    &mode,
		Size:    &size,
		Mtime:   mtime,
		Content: chunkHashes,
	}
}

func toDirNode(entry fileEntry, subtreeHash string) TreeNode {
	mode := int(entry.info.Mode().Perm())
	return TreeNode{
		Name:    filepath.Base(entry.relativePath),
		Type:    "dir",
		Mode:    &mode,
		Subtree: subtreeHash,
	}
}

func toSymlinkNode(entry fileEntry) (TreeNode, error) {
	target, err := os.Readlink(entry.fullPath)
	if err != nil {
		return TreeNode{}, err
	}
	return TreeNode{
		Name:   filepath.Base(entry.relativePath),
		Type:   "symlink",
		Target: target,
	}, nil
}

// ── Incremental: build previous file index ──────────────────────────────────

// buildPrevIndex walks a parent snapshot's tree to build an index for
// incremental backup. If the parent snapshot is encrypted, parentDEK must
// be provided to decrypt tree blobs; pass nil for plaintext parents.
func buildPrevIndex(http *HttpClient, snapshotID string, parentDEK []byte) (map[string]prevFileInfo, error) {
	index := make(map[string]prevFileInfo)

	snap, err := http.GetSnapshot(snapshotID)
	if err != nil {
		return nil, err
	}

	encrypted := snap.WrappedDEK != "" && parentDEK != nil

	var walk func(hash, prefix string) error
	walk = func(hash, prefix string) error {
		resp, err := http.RequestDownloadURLs([]string{hash})
		if err != nil {
			return err
		}

		var data []byte
		if len(resp.Packs) > 0 && len(resp.Packs[0].Chunks) > 0 {
			packData, err := S3Get(resp.Packs[0].URL)
			if err != nil {
				return err
			}
			ch := resp.Packs[0].Chunks[0]
			stored := packData[ch.Offset : ch.Offset+ch.Size]
			data = stored
			if encrypted {
				treeKey, terr := DeriveTreeKey(parentDEK, hash)
				if terr != nil {
					return fmt.Errorf("derive tree key %s: %w", hash, terr)
				}
				var derr error
				data, derr = DecryptObject(treeKey, stored)
				if derr != nil {
					return fmt.Errorf("decrypt tree %s: %w", hash, derr)
				}
			}
			var derr error
			data, derr = maybeDecompressStoredOrInferZstd(data, ch.Compression)
			if derr != nil {
				return fmt.Errorf("decompress tree %s: %w", hash, derr)
			}
		} else if len(resp.Standalone) > 0 {
			var serr error
			data, serr = S3Get(resp.Standalone[0].URL)
			if serr != nil {
				return serr
			}
			if encrypted {
				treeKey, terr := DeriveTreeKey(parentDEK, hash)
				if terr != nil {
					return fmt.Errorf("derive tree key %s: %w", hash, terr)
				}
				var derr error
				data, derr = DecryptObject(treeKey, data)
				if derr != nil {
					return fmt.Errorf("decrypt tree %s: %w", hash, derr)
				}
			}
			var derr error
			data, derr = maybeDecompressStoredOrInferZstd(data, "")
			if derr != nil {
				return fmt.Errorf("decompress tree %s: %w", hash, derr)
			}
		} else {
			return nil
		}

		var blob TreeBlob
		if err := json.Unmarshal(data, &blob); err != nil {
			return err
		}

		for _, node := range blob.Nodes {
			rel := node.Name
			if prefix != "" {
				rel = prefix + "/" + node.Name
			}
			if node.Type == "file" && node.Content != nil && node.Mtime != "" && node.Size != nil {
				index[rel] = prevFileInfo{mtime: node.Mtime, size: *node.Size, content: node.Content}
			} else if node.Type == "dir" && node.Subtree != "" {
				if err := walk(node.Subtree, rel); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(snap.RootTreeHash, ""); err != nil {
		return nil, err
	}
	return index, nil
}

// ── Pack management ─────────────────────────────────────────────────────────

func flushPack(http *HttpClient, pack *packBuffer, emit func(ProgressEvent)) error {
	if len(pack.chunks) == 0 {
		return nil
	}

	totalSize := int64(0)
	for _, c := range pack.chunks {
		totalSize += int64(len(c.data))
	}

	resp, err := http.RequestPackUploadURL(totalSize)
	if err != nil {
		return fmt.Errorf("request pack upload URL: %w", err)
	}

	var packData []byte
	for _, c := range pack.chunks {
		packData = append(packData, c.data...)
	}

	if err := S3Put(resp.URL, packData); err != nil {
		return fmt.Errorf("upload pack: %w", err)
	}

	metas := make([]PackChunkMeta, 0, len(pack.chunks))
	offset := 0
	for _, c := range pack.chunks {
		meta := PackChunkMeta{
			Hash:   c.hash,
			Size:   len(c.data),
			Offset: offset,
			Type:   c.chunkTyp,
		}
		if c.compression != "" {
			meta.Compression = c.compression
			meta.UncompressedSize = c.uncompressedSize
		}
		metas = append(metas, meta)
		offset += len(c.data)
	}

	if _, err := http.ConfirmPack(resp.PackID, metas); err != nil {
		return fmt.Errorf("confirm pack: %w", err)
	}

	uncompTotal := int64(0)
	for _, c := range pack.chunks {
		uncompTotal += int64(c.uncompressedSize)
	}
	ratio := 1.0
	if uncompTotal > 0 {
		ratio = float64(totalSize) / float64(uncompTotal)
	}
	saved := uncompTotal - totalSize
	if saved < 0 {
		saved = 0
	}
	emit(ProgressEvent{
		Phase:                 "uploading",
		Bytes:                 totalSize,
		StoredBytes:           totalSize,
		RawBytes:              uncompTotal,
		CompressionSavedBytes: saved,
		CompressionRatio:      ratio,
		Message: fmt.Sprintf("pack %s stored=%d raw=%d ratio=%.1f%% saved=%d",
			resp.PackID[:8], totalSize, uncompTotal, ratio*100, saved),
	})

	pack.chunks = pack.chunks[:0]
	pack.totalSize = 0
	return nil
}

// ── Main backup flow ────────────────────────────────────────────────────────

// PerformBackup runs the full backup pipeline:
// scan → chunk → dedup → pack upload → tree build → snapshot.
func PerformBackup(
	http *HttpClient,
	paths []string,
	chunkOpts ChunkOptions,
	options *BackupOptions,
	concurrency int,
) (*Snapshot, error) {
	if options == nil {
		options = &BackupOptions{}
	}
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	emit := func(e ProgressEvent) {
		if options.OnProgress != nil {
			options.OnProgress(e)
		}
	}

	// ── 0. Encryption setup ────────────────────────────────────────────────
	var dek []byte
	var wrappedDEK string
	var encMeta *EncryptionMeta
	var tmk []byte

	if options.Encryption != nil {
		var err error
		tmk, err = loadTMK(options.Encryption)
		if err != nil {
			return nil, fmt.Errorf("load encryption key: %w", err)
		}
		dek, err = GenerateDEK()
		if err != nil {
			return nil, fmt.Errorf("generate DEK: %w", err)
		}
		wrappedDEK, err = WrapDEK(tmk, dek)
		if err != nil {
			return nil, fmt.Errorf("wrap DEK: %w", err)
		}
		encMeta = newEncryptionMeta()
		emit(ProgressEvent{Phase: "encryption", Message: "Client-side encryption enabled"})
	}

	// ── 1. Scan ─────────────────────────────────────────────────────────────
	emit(ProgressEvent{Phase: "scanning", Message: "Scanning…"})

	var allEntries []fileEntry
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		rootName := filepath.Base(p)

		if info.IsDir() {
			allEntries = append(allEntries, fileEntry{fullPath: p, relativePath: rootName, info: info})
			children, err := walkDirectory(p)
			if err != nil {
				return nil, fmt.Errorf("walk %s: %w", p, err)
			}
			for i := range children {
				children[i].relativePath = filepath.ToSlash(filepath.Join(rootName, children[i].relativePath))
				allEntries = append(allEntries, children[i])
			}
		} else {
			allEntries = append(allEntries, fileEntry{fullPath: p, relativePath: rootName, info: info})
		}
	}

	emit(ProgressEvent{Phase: "scanning", Current: len(allEntries), Total: len(allEntries),
		Message: fmt.Sprintf("%d entries", len(allEntries))})

	// ── 2. Load previous snapshot for incremental ───────────────────────────
	parentSnapshotID := options.ParentSnapshotID
	if parentSnapshotID == "" {
		list, err := http.ListSnapshots("", 1)
		if err == nil && len(list.Snapshots) > 0 {
			parentSnapshotID = list.Snapshots[0].SnapshotID
		}
	}

	var prevIndex map[string]prevFileInfo
	if parentSnapshotID != "" {
		// For encrypted parents we need the TMK to unwrap the parent DEK.
		var parentDEK []byte
		if tmk != nil {
			parentSnap, err := http.GetSnapshot(parentSnapshotID)
			if err == nil && parentSnap.WrappedDEK != "" {
				parentDEK, _ = UnwrapDEK(tmk, parentSnap.WrappedDEK)
			}
		}
		idx, err := buildPrevIndex(http, parentSnapshotID, parentDEK)
		if err == nil {
			prevIndex = idx
			emit(ProgressEvent{Phase: "scanning", Message: fmt.Sprintf("incremental: %d cached files", len(prevIndex))})
		}
	}

	// ── 3. Download bloom filter ────────────────────────────────────────────
	var bloom BloomTester
	bloomResp, err := http.GetBloomFilter()
	if err == nil {
		bf, err2 := NewBloomFilter(bloomResp)
		if err2 == nil {
			bloom = bf
			emit(ProgressEvent{Phase: "dedup", Message: fmt.Sprintf("bloom filter: %d entries", bloomResp.Count)})
		}
	}
	if bloom == nil {
		bloom = NewEmptyBloom()
	}

	// ── 4. Chunk files → pack buffer → upload ───────────────────────────────
	fileChunkHashes := make(map[string][]string)
	knownHashes := make(map[string]bool)
	var totalSize int64
	var totalChunks int

	pack := &packBuffer{}
	var fileEntries []fileEntry
	for _, e := range allEntries {
		if e.info.Mode().IsRegular() {
			fileEntries = append(fileEntries, e)
		}
	}

	for i, entry := range fileEntries {
		relPath := entry.relativePath

		// Incremental: skip unchanged files
		if prevIndex != nil {
			if prev, ok := prevIndex[relPath]; ok {
				entryMtime := entry.info.ModTime().UTC().Format("2006-01-02T15:04:05.000Z")
				if prev.mtime == entryMtime && prev.size == entry.info.Size() {
					fileChunkHashes[relPath] = prev.content
					for _, h := range prev.content {
						knownHashes[h] = true
					}
					emit(ProgressEvent{Phase: "chunking", Current: i + 1, Total: len(fileEntries),
						Message: "skip " + relPath})
					continue
				}
			}
		}

		chunks, err := ChunkFile(entry.fullPath, chunkOpts)
		if err != nil {
			return nil, fmt.Errorf("chunk %s: %w", relPath, err)
		}

		var hashes []string
		for _, chunk := range chunks {
			hashes = append(hashes, chunk.Hash)
			totalSize += int64(chunk.Size)
			totalChunks++

			if knownHashes[chunk.Hash] {
				continue
			}
			knownHashes[chunk.Hash] = true

			if bloom.Test(chunk.Hash) {
				continue
			}

			stored, comp, uncomp := chunk.Data, "", len(chunk.Data)
			if !options.DisablePackCompression {
				stored, comp, uncomp = maybeZstdCompress(chunk.Data)
			}
			if dek != nil {
				objKey, err := DeriveDataKey(dek, chunk.Hash)
				if err != nil {
					return nil, fmt.Errorf("derive data key %s: %w", chunk.Hash, err)
				}
				stored, err = EncryptObject(objKey, stored)
				if err != nil {
					return nil, fmt.Errorf("encrypt chunk %s: %w", chunk.Hash, err)
				}
			}
			pack.chunks = append(pack.chunks, packChunk{
				hash: chunk.Hash, data: stored, chunkTyp: "data",
				compression: comp, uncompressedSize: uncomp,
			})
			pack.totalSize += int64(len(stored))

			if pack.totalSize >= packTargetSize {
				if err := flushPack(http, pack, emit); err != nil {
					return nil, err
				}
			}
		}

		fileChunkHashes[relPath] = hashes
		emit(ProgressEvent{Phase: "chunking", Current: i + 1, Total: len(fileEntries)})
	}

	// ── 5. Build tree structure (bottom-up) ─────────────────────────────────
	emit(ProgressEvent{Phase: "tree", Message: "Building tree…"})

	dirChildren := make(map[string][]fileEntry)
	for _, entry := range allEntries {
		parent := parentDir(entry.relativePath)
		dirChildren[parent] = append(dirChildren[parent], entry)
	}

	dirKeys := make([]string, 0, len(dirChildren))
	for k := range dirChildren {
		dirKeys = append(dirKeys, k)
	}
	sort.Slice(dirKeys, func(i, j int) bool {
		return strings.Count(dirKeys[i], "/") > strings.Count(dirKeys[j], "/") ||
			(strings.Count(dirKeys[i], "/") == strings.Count(dirKeys[j], "/") && dirKeys[i] > dirKeys[j])
	})

	treeHashMap := make(map[string]string)

	for _, dir := range dirKeys {
		children := dirChildren[dir]
		var nodes []TreeNode

		for _, entry := range children {
			if entry.info.Mode().IsRegular() {
				nodes = append(nodes, toFileNode(entry, fileChunkHashes[entry.relativePath]))
			} else if entry.info.IsDir() {
				if sub, ok := treeHashMap[entry.relativePath]; ok {
					nodes = append(nodes, toDirNode(entry, sub))
				}
			} else if entry.info.Mode()&os.ModeSymlink != 0 {
				node, err := toSymlinkNode(entry)
				if err == nil {
					nodes = append(nodes, node)
				}
			}
		}

		sort.Slice(nodes, func(i, j int) bool {
			return nodes[i].Name < nodes[j].Name
		})

		hash, data := HashTree(nodes)
		treeHashMap[dir] = hash

		if !bloom.Test(hash) {
			storedTree, compTree, uncompTree := data, "", len(data)
			if !options.DisablePackCompression {
				storedTree, compTree, uncompTree = maybeZstdCompress(data)
			}
			if dek != nil {
				treeKey, err := DeriveTreeKey(dek, hash)
				if err != nil {
					return nil, fmt.Errorf("derive tree key %s: %w", hash, err)
				}
				storedTree, err = EncryptObject(treeKey, storedTree)
				if err != nil {
					return nil, fmt.Errorf("encrypt tree %s: %w", hash, err)
				}
			}
			pack.chunks = append(pack.chunks, packChunk{
				hash: hash, data: storedTree, chunkTyp: "tree",
				compression: compTree, uncompressedSize: uncompTree,
			})
			pack.totalSize += int64(len(storedTree))

			if pack.totalSize >= packTargetSize {
				if err := flushPack(http, pack, emit); err != nil {
					return nil, err
				}
			}
		}
	}

	// Flush remaining
	if err := flushPack(http, pack, emit); err != nil {
		return nil, err
	}

	emit(ProgressEvent{Phase: "tree", Current: len(dirKeys), Total: len(dirKeys)})

	// ── 6. Create snapshot ──────────────────────────────────────────────────
	rootTreeHash, ok := treeHashMap[""]
	if !ok {
		return nil, fmt.Errorf("failed to build root tree")
	}

	hostname := options.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	snapshot, err := http.CreateSnapshot(SnapshotInput{
		RootTreeHash: rootTreeHash,
		Hostname:     hostname,
		Paths:        paths,
		Description:  options.Description,
		Tags:         options.Tags,
		TotalSize:    totalSize,
		TotalChunks:  totalChunks,
		WrappedDEK:   wrappedDEK,
		Encryption:   encMeta,
	})
	if err != nil {
		return nil, fmt.Errorf("create snapshot: %w", err)
	}

	emit(ProgressEvent{Phase: "snapshot", Current: 1, Total: 1,
		Message: fmt.Sprintf("Snapshot %s created", snapshot.SnapshotID)})

	return &snapshot, nil
}
