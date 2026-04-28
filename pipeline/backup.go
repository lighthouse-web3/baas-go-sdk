package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lighthouse-web3/baas-go-sdk/api"
	"github.com/lighthouse-web3/baas-go-sdk/chunk"
	"github.com/lighthouse-web3/baas-go-sdk/codec"
	"github.com/lighthouse-web3/baas-go-sdk/dedup"
	"github.com/lighthouse-web3/baas-go-sdk/encrypt"
	"github.com/lighthouse-web3/baas-go-sdk/tree"
	sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
)

const packTargetSize = 256 * 1024 * 1024

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
	data             []byte
	chunkTyp         string
	compression      string
	uncompressedSize int
}

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

func toFileNode(entry fileEntry, chunkHashes []string) sdktypes.TreeNode {
	mode := int(entry.info.Mode().Perm())
	size := entry.info.Size()
	mtime := entry.info.ModTime().UTC().Format("2006-01-02T15:04:05.000Z")
	return sdktypes.TreeNode{
		Name:    filepath.Base(entry.relativePath),
		Type:    "file",
		Mode:    &mode,
		Size:    &size,
		Mtime:   mtime,
		Content: chunkHashes,
	}
}

func toDirNode(entry fileEntry, subtreeHash string) sdktypes.TreeNode {
	mode := int(entry.info.Mode().Perm())
	return sdktypes.TreeNode{
		Name:    filepath.Base(entry.relativePath),
		Type:    "dir",
		Mode:    &mode,
		Subtree: subtreeHash,
	}
}

func toSymlinkNode(entry fileEntry) (sdktypes.TreeNode, error) {
	target, err := os.Readlink(entry.fullPath)
	if err != nil {
		return sdktypes.TreeNode{}, err
	}
	return sdktypes.TreeNode{
		Name:   filepath.Base(entry.relativePath),
		Type:   "symlink",
		Target: target,
	}, nil
}

func buildPrevIndex(http *api.HttpClient, snapshotID string, parentDEK []byte) (map[string]prevFileInfo, error) {
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
			packData, err := api.S3Get(resp.Packs[0].URL)
			if err != nil {
				return err
			}
			ch := resp.Packs[0].Chunks[0]
			stored := packData[ch.Offset : ch.Offset+ch.Size]
			data = stored
			if encrypted {
				treeKey, terr := encrypt.DeriveTreeKey(parentDEK, hash)
				if terr != nil {
					return fmt.Errorf("derive tree key %s: %w", hash, terr)
				}
				var derr error
				data, derr = encrypt.DecryptObject(treeKey, stored)
				if derr != nil {
					return fmt.Errorf("decrypt tree %s: %w", hash, derr)
				}
			}
			var derr error
			data, derr = codec.MaybeDecompressStoredOrInferZstd(data, ch.Compression)
			if derr != nil {
				return fmt.Errorf("decompress tree %s: %w", hash, derr)
			}
		} else if len(resp.Standalone) > 0 {
			var serr error
			data, serr = api.S3Get(resp.Standalone[0].URL)
			if serr != nil {
				return serr
			}
			if encrypted {
				treeKey, terr := encrypt.DeriveTreeKey(parentDEK, hash)
				if terr != nil {
					return fmt.Errorf("derive tree key %s: %w", hash, terr)
				}
				var derr error
				data, derr = encrypt.DecryptObject(treeKey, data)
				if derr != nil {
					return fmt.Errorf("decrypt tree %s: %w", hash, derr)
				}
			}
			var derr error
			data, derr = codec.MaybeDecompressStoredOrInferZstd(data, "")
			if derr != nil {
				return fmt.Errorf("decompress tree %s: %w", hash, derr)
			}
		} else {
			return nil
		}
		var blob sdktypes.TreeBlob
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

func flushPack(http *api.HttpClient, pack *packBuffer, emit func(sdktypes.ProgressEvent)) error {
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
	if err := api.S3Put(resp.URL, packData); err != nil {
		return fmt.Errorf("upload pack: %w", err)
	}
	metas := make([]sdktypes.PackChunkMeta, 0, len(pack.chunks))
	offset := 0
	for _, c := range pack.chunks {
		meta := sdktypes.PackChunkMeta{Hash: c.hash, Size: len(c.data), Offset: offset, Type: c.chunkTyp}
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
	emit(sdktypes.ProgressEvent{
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

// PerformBackup runs scan -> chunk -> dedup -> upload -> tree -> snapshot.
func PerformBackup(
	http *api.HttpClient,
	paths []string,
	chunkOpts sdktypes.ChunkOptions,
	options *sdktypes.BackupOptions,
	concurrency int,
) (*sdktypes.Snapshot, error) {
	if options == nil {
		options = &sdktypes.BackupOptions{}
	}
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	emit := func(e sdktypes.ProgressEvent) {
		if options.OnProgress != nil {
			options.OnProgress(e)
		}
	}

	dek, wrappedDEK, encMeta, tmk, err := initBackupEncryption(options, emit)
	if err != nil {
		return nil, err
	}

	allEntries, err := scanBackupEntries(paths, emit)
	if err != nil {
		return nil, err
	}

	prevIndex := loadPreviousIndex(http, options, tmk, emit)
	bloom := buildBloomTester(http, emit)

	pack := &packBuffer{}
	fileChunkHashes, totalSize, totalChunks, err := processFileChunks(
		http, allEntries, prevIndex, bloom, chunkOpts, options, dek, pack, emit,
	)
	if err != nil {
		return nil, err
	}

	treeHashMap, err := buildAndUploadTrees(http, allEntries, fileChunkHashes, bloom, options, dek, pack, emit)
	if err != nil {
		return nil, err
	}

	return createSnapshotRecord(http, treeHashMap, paths, options, totalSize, totalChunks, wrappedDEK, encMeta, emit)
}

func initBackupEncryption(
	options *sdktypes.BackupOptions,
	emit func(sdktypes.ProgressEvent),
) (dek []byte, wrappedDEK string, encMeta *sdktypes.EncryptionMeta, tmk []byte, err error) {
	if options.Encryption == nil {
		return nil, "", nil, nil, nil
	}

	tmk, err = encrypt.LoadTMK(options.Encryption)
	if err != nil {
		return nil, "", nil, nil, fmt.Errorf("load encryption key: %w", err)
	}
	dek, err = encrypt.GenerateDEK()
	if err != nil {
		return nil, "", nil, nil, fmt.Errorf("generate DEK: %w", err)
	}
	wrappedDEK, err = encrypt.WrapDEK(tmk, dek)
	if err != nil {
		return nil, "", nil, nil, fmt.Errorf("wrap DEK: %w", err)
	}
	encMeta = encrypt.NewEncryptionMeta()
	emit(sdktypes.ProgressEvent{Phase: "encryption", Message: "Client-side encryption enabled"})
	return dek, wrappedDEK, encMeta, tmk, nil
}

func scanBackupEntries(paths []string, emit func(sdktypes.ProgressEvent)) ([]fileEntry, error) {
	emit(sdktypes.ProgressEvent{Phase: "scanning", Message: "Scanning..."})
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
	emit(sdktypes.ProgressEvent{
		Phase: "scanning", Current: len(allEntries), Total: len(allEntries), Message: fmt.Sprintf("%d entries", len(allEntries)),
	})
	return allEntries, nil
}

func loadPreviousIndex(
	http *api.HttpClient,
	options *sdktypes.BackupOptions,
	tmk []byte,
	emit func(sdktypes.ProgressEvent),
) map[string]prevFileInfo {
	parentSnapshotID := options.ParentSnapshotID
	if parentSnapshotID == "" {
		list, err := http.ListSnapshots("", 1)
		if err == nil && len(list.Snapshots) > 0 {
			parentSnapshotID = list.Snapshots[0].SnapshotID
		}
	}
	if parentSnapshotID == "" {
		return nil
	}

	var parentDEK []byte
	if tmk != nil {
		parentSnap, err := http.GetSnapshot(parentSnapshotID)
		if err == nil && parentSnap.WrappedDEK != "" {
			parentDEK, _ = encrypt.UnwrapDEK(tmk, parentSnap.WrappedDEK)
		}
	}

	idx, err := buildPrevIndex(http, parentSnapshotID, parentDEK)
	if err != nil {
		return nil
	}
	emit(sdktypes.ProgressEvent{Phase: "scanning", Message: fmt.Sprintf("incremental: %d cached files", len(idx))})
	return idx
}

func buildBloomTester(http *api.HttpClient, emit func(sdktypes.ProgressEvent)) dedup.BloomTester {
	bloomResp, err := http.GetBloomFilter()
	if err == nil {
		bf, err2 := dedup.NewBloomFilter(bloomResp)
		if err2 == nil {
			emit(sdktypes.ProgressEvent{Phase: "dedup", Message: fmt.Sprintf("bloom filter: %d entries", bloomResp.Count)})
			return bf
		}
	}
	return dedup.NewEmptyBloom()
}

func processFileChunks(
	http *api.HttpClient,
	allEntries []fileEntry,
	prevIndex map[string]prevFileInfo,
	bloom dedup.BloomTester,
	chunkOpts sdktypes.ChunkOptions,
	options *sdktypes.BackupOptions,
	dek []byte,
	pack *packBuffer,
	emit func(sdktypes.ProgressEvent),
) (map[string][]string, int64, int, error) {
	fileChunkHashes := make(map[string][]string)
	knownHashes := make(map[string]bool)
	var totalSize int64
	totalChunks := 0

	var fileEntries []fileEntry
	for _, e := range allEntries {
		if e.info.Mode().IsRegular() {
			fileEntries = append(fileEntries, e)
		}
	}

	for i, entry := range fileEntries {
		relPath := entry.relativePath
		if prevIndex != nil {
			if prev, ok := prevIndex[relPath]; ok {
				entryMtime := entry.info.ModTime().UTC().Format("2006-01-02T15:04:05.000Z")
				if prev.mtime == entryMtime && prev.size == entry.info.Size() {
					fileChunkHashes[relPath] = prev.content
					for _, h := range prev.content {
						knownHashes[h] = true
					}
					emit(sdktypes.ProgressEvent{Phase: "chunking", Current: i + 1, Total: len(fileEntries), Message: "skip " + relPath})
					continue
				}
			}
		}

		chunks, err := chunk.ChunkFile(entry.fullPath, chunkOpts)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("chunk %s: %w", relPath, err)
		}
		var hashes []string
		for _, c := range chunks {
			hashes = append(hashes, c.Hash)
			totalSize += int64(c.Size)
			totalChunks++
			if knownHashes[c.Hash] {
				continue
			}
			knownHashes[c.Hash] = true
			if bloom.Test(c.Hash) {
				continue
			}

			stored, comp, uncomp := c.Data, "", len(c.Data)
			if !options.DisablePackCompression {
				stored, comp, uncomp = codec.MaybeZstdCompress(c.Data)
			}
			if dek != nil {
				objKey, err := encrypt.DeriveDataKey(dek, c.Hash)
				if err != nil {
					return nil, 0, 0, fmt.Errorf("derive data key %s: %w", c.Hash, err)
				}
				stored, err = encrypt.EncryptObject(objKey, stored)
				if err != nil {
					return nil, 0, 0, fmt.Errorf("encrypt chunk %s: %w", c.Hash, err)
				}
			}

			pack.chunks = append(pack.chunks, packChunk{
				hash: c.Hash, data: stored, chunkTyp: "data", compression: comp, uncompressedSize: uncomp,
			})
			pack.totalSize += int64(len(stored))
			if pack.totalSize >= packTargetSize {
				if err := flushPack(http, pack, emit); err != nil {
					return nil, 0, 0, err
				}
			}
		}

		fileChunkHashes[relPath] = hashes
		emit(sdktypes.ProgressEvent{Phase: "chunking", Current: i + 1, Total: len(fileEntries)})
	}

	return fileChunkHashes, totalSize, totalChunks, nil
}

func buildAndUploadTrees(
	http *api.HttpClient,
	allEntries []fileEntry,
	fileChunkHashes map[string][]string,
	bloom dedup.BloomTester,
	options *sdktypes.BackupOptions,
	dek []byte,
	pack *packBuffer,
	emit func(sdktypes.ProgressEvent),
) (map[string]string, error) {
	emit(sdktypes.ProgressEvent{Phase: "tree", Message: "Building tree..."})

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
		var nodes []sdktypes.TreeNode
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

		sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
		hash, data := tree.HashTree(nodes)
		treeHashMap[dir] = hash
		if bloom.Test(hash) {
			continue
		}

		storedTree, compTree, uncompTree := data, "", len(data)
		if !options.DisablePackCompression {
			storedTree, compTree, uncompTree = codec.MaybeZstdCompress(data)
		}
		if dek != nil {
			treeKey, err := encrypt.DeriveTreeKey(dek, hash)
			if err != nil {
				return nil, fmt.Errorf("derive tree key %s: %w", hash, err)
			}
			storedTree, err = encrypt.EncryptObject(treeKey, storedTree)
			if err != nil {
				return nil, fmt.Errorf("encrypt tree %s: %w", hash, err)
			}
		}
		pack.chunks = append(pack.chunks, packChunk{
			hash: hash, data: storedTree, chunkTyp: "tree", compression: compTree, uncompressedSize: uncompTree,
		})
		pack.totalSize += int64(len(storedTree))
		if pack.totalSize >= packTargetSize {
			if err := flushPack(http, pack, emit); err != nil {
				return nil, err
			}
		}
	}

	if err := flushPack(http, pack, emit); err != nil {
		return nil, err
	}
	emit(sdktypes.ProgressEvent{Phase: "tree", Current: len(dirKeys), Total: len(dirKeys)})
	return treeHashMap, nil
}

func createSnapshotRecord(
	http *api.HttpClient,
	treeHashMap map[string]string,
	paths []string,
	options *sdktypes.BackupOptions,
	totalSize int64,
	totalChunks int,
	wrappedDEK string,
	encMeta *sdktypes.EncryptionMeta,
	emit func(sdktypes.ProgressEvent),
) (*sdktypes.Snapshot, error) {
	rootTreeHash, ok := treeHashMap[""]
	if !ok {
		return nil, fmt.Errorf("failed to build root tree")
	}
	hostname := options.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	snapshot, err := http.CreateSnapshot(sdktypes.SnapshotInput{
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
	emit(sdktypes.ProgressEvent{
		Phase: "snapshot", Current: 1, Total: 1, Message: fmt.Sprintf("Snapshot %s created", snapshot.SnapshotID),
	})
	return &snapshot, nil
}
