package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lighthouse-web3/baas-go-sdk/api"
	"github.com/lighthouse-web3/baas-go-sdk/chunk"
	"github.com/lighthouse-web3/baas-go-sdk/codec"
	"github.com/lighthouse-web3/baas-go-sdk/encrypt"
	"github.com/lighthouse-web3/baas-go-sdk/pool"
	sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
)

type treeCollections struct {
	trees    map[string]sdktypes.TreeBlob
	fileMap  map[string][]string
	nodeMeta map[string]sdktypes.TreeNode
}

func resolveTree(http *api.HttpClient, hash, basePath string, col *treeCollections, dek []byte) error {
	if _, ok := col.trees[hash]; ok {
		return nil
	}
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
		if dek != nil {
			treeKey, terr := encrypt.DeriveTreeKey(dek, hash)
			if terr != nil {
				return fmt.Errorf("derive tree key %s: %w", hash, terr)
			}
			var derr error
			data, derr = encrypt.DecryptObject(treeKey, stored)
			if derr != nil {
				return fmt.Errorf("decrypt tree %s: %w", hash, derr)
			}
		}
		data, err = codec.MaybeDecompressStoredOrInferZstd(data, ch.Compression)
		if err != nil {
			return fmt.Errorf("decompress tree %s: %w", hash, err)
		}
	} else if len(resp.Standalone) > 0 {
		data, err = api.S3Get(resp.Standalone[0].URL)
		if err != nil {
			return err
		}
		if dek != nil {
			treeKey, terr := encrypt.DeriveTreeKey(dek, hash)
			if terr != nil {
				return fmt.Errorf("derive tree key %s: %w", hash, terr)
			}
			data, err = encrypt.DecryptObject(treeKey, data)
			if err != nil {
				return fmt.Errorf("decrypt tree %s: %w", hash, err)
			}
		}
		data, err = codec.MaybeDecompressStoredOrInferZstd(data, "")
		if err != nil {
			return fmt.Errorf("decompress tree %s: %w", hash, err)
		}
	} else {
		return fmt.Errorf("no download URL for tree %s", hash)
	}
	var t sdktypes.TreeBlob
	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("decode tree %s: %w", hash, err)
	}
	col.trees[hash] = t
	for _, node := range t.Nodes {
		relPath, err := joinTreePath(basePath, node.Name)
		if err != nil {
			return err
		}
		col.nodeMeta[relPath] = node
		if node.Type == "dir" && node.Subtree != "" {
			if err := resolveTree(http, node.Subtree, relPath, col, dek); err != nil {
				return err
			}
		} else if node.Type == "file" && node.Content != nil {
			col.fileMap[relPath] = node.Content
		}
	}
	return nil
}

func restoreMeta(trees map[string]sdktypes.TreeBlob, targetDir, hash, basePath string) error {
	t, ok := trees[hash]
	if !ok {
		return nil
	}
	for _, node := range t.Nodes {
		relPath, err := joinTreePath(basePath, node.Name)
		if err != nil {
			return err
		}
		fullPath, err := safeJoinTarget(targetDir, relPath)
		if err != nil {
			return err
		}
		if node.Type == "dir" {
			os.MkdirAll(fullPath, 0o755)
			if node.Subtree != "" {
				if err := restoreMeta(trees, targetDir, node.Subtree, relPath); err != nil {
					return err
				}
			}
		} else if node.Type == "symlink" && node.Target != "" {
			os.Symlink(node.Target, fullPath)
		}
		applyNodeMeta(fullPath, node)
	}
	return nil
}

func applyNodeMeta(fullPath string, node sdktypes.TreeNode) {
	if node.Mode != nil {
		os.Chmod(fullPath, os.FileMode(*node.Mode)&0o777)
	}
	if node.Mtime != "" {
		if t, err := time.Parse(time.RFC3339Nano, node.Mtime); err == nil {
			os.Chtimes(fullPath, t, t)
		} else if t, err := time.Parse("2006-01-02T15:04:05.000Z", node.Mtime); err == nil {
			os.Chtimes(fullPath, t, t)
		}
	}
}

// PerformRestore downloads and reassembles a snapshot to the target directory.
func PerformRestore(
	http *api.HttpClient,
	snapshotID, targetDir string,
	options *sdktypes.RestoreOptions,
	concurrency int,
) error {
	options, verifyChecksums, concurrency, emit := normalizeRestoreInputs(options, concurrency)

	snapshot, dek, err := loadSnapshotAndDEK(http, snapshotID, options, emit)
	if err != nil {
		return err
	}

	col, err := downloadTreeCollections(http, snapshot.RootTreeHash, dek, emit)
	if err != nil {
		return err
	}

	allDataHashes, hashList := collectDataHashes(col.fileMap)
	if verifyChecksums {
		emit(sdktypes.ProgressEvent{Phase: "verifying", Message: "Checksum verification enabled"})
	}

	chunkCache, err := downloadChunkData(http, hashList, dek, verifyChecksums, concurrency, emit)
	if err != nil {
		return err
	}
	if err := ensureAllChunksPresent(allDataHashes, chunkCache); err != nil {
		return err
	}

	if err := writeRestoredFiles(targetDir, col.fileMap, chunkCache, emit); err != nil {
		return err
	}

	return restoreMeta(col.trees, targetDir, snapshot.RootTreeHash, "")
}

func normalizeRestoreInputs(
	options *sdktypes.RestoreOptions,
	concurrency int,
) (*sdktypes.RestoreOptions, bool, int, func(sdktypes.ProgressEvent)) {
	if options == nil {
		options = &sdktypes.RestoreOptions{}
	}
	verifyChecksums := !options.SkipChecksumVerification
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	emit := func(e sdktypes.ProgressEvent) {
		if options.OnProgress != nil {
			options.OnProgress(e)
		}
	}
	return options, verifyChecksums, concurrency, emit
}

func loadSnapshotAndDEK(
	http *api.HttpClient,
	snapshotID string,
	options *sdktypes.RestoreOptions,
	emit func(sdktypes.ProgressEvent),
) (sdktypes.Snapshot, []byte, error) {
	snapshot, err := http.GetSnapshot(snapshotID)
	if err != nil {
		return sdktypes.Snapshot{}, nil, fmt.Errorf("get snapshot: %w", err)
	}

	var dek []byte
	if snapshot.WrappedDEK == "" {
		return snapshot, dek, nil
	}
	if options.Encryption == nil {
		return sdktypes.Snapshot{}, nil, fmt.Errorf("snapshot is encrypted but no encryption options provided")
	}

	tmk, err := encrypt.LoadTMK(options.Encryption)
	if err != nil {
		return sdktypes.Snapshot{}, nil, fmt.Errorf("load encryption key: %w", err)
	}
	dek, err = encrypt.UnwrapDEK(tmk, snapshot.WrappedDEK)
	if err != nil {
		return sdktypes.Snapshot{}, nil, fmt.Errorf("unwrap DEK (wrong passphrase?): %w", err)
	}
	emit(sdktypes.ProgressEvent{Phase: "encryption", Message: "DEK unwrapped, decryption enabled"})
	return snapshot, dek, nil
}

func downloadTreeCollections(
	http *api.HttpClient,
	rootTreeHash string,
	dek []byte,
	emit func(sdktypes.ProgressEvent),
) (*treeCollections, error) {
	emit(sdktypes.ProgressEvent{Phase: "downloading", Message: "Downloading tree..."})
	col := &treeCollections{
		trees:    make(map[string]sdktypes.TreeBlob),
		fileMap:  make(map[string][]string),
		nodeMeta: make(map[string]sdktypes.TreeNode),
	}
	if err := resolveTree(http, rootTreeHash, "", col, dek); err != nil {
		return nil, fmt.Errorf("resolve tree: %w", err)
	}
	emit(sdktypes.ProgressEvent{
		Phase: "downloading", Current: len(col.trees), Total: len(col.trees),
		Message: fmt.Sprintf("%d tree blobs, %d files", len(col.trees), len(col.fileMap)),
	})
	return col, nil
}

func collectDataHashes(fileMap map[string][]string) (map[string]bool, []string) {
	allDataHashes := make(map[string]bool)
	for _, hashes := range fileMap {
		for _, h := range hashes {
			allDataHashes[h] = true
		}
	}
	hashList := make([]string, 0, len(allDataHashes))
	for h := range allDataHashes {
		hashList = append(hashList, h)
	}
	return allDataHashes, hashList
}

func downloadChunkData(
	http *api.HttpClient,
	hashList []string,
	dek []byte,
	verifyChecksums bool,
	concurrency int,
	emit func(sdktypes.ProgressEvent),
) (map[string][]byte, error) {
	chunkCache := make(map[string][]byte)
	downloaded := 0
	var mu sync.Mutex
	for _, batch := range pool.Batch(hashList, 500) {
		resp, err := http.RequestDownloadURLs(batch)
		if err != nil {
			return nil, fmt.Errorf("request download URLs: %w", err)
		}
		err = pool.Parallel(resp.Packs, concurrency, func(packEntry sdktypes.PackDownloadEntry) error {
			packData, err := api.S3Get(packEntry.URL)
			if err != nil {
				return err
			}
			for _, chMeta := range packEntry.Chunks {
				chunkData, err := decodePackChunk(packData, chMeta, dek, verifyChecksums)
				if err != nil {
					return err
				}
				mu.Lock()
				chunkCache[chMeta.Hash] = chunkData
				mu.Unlock()
			}
			mu.Lock()
			downloaded += len(packEntry.Chunks)
			current := downloaded
			mu.Unlock()
			emit(sdktypes.ProgressEvent{Phase: "downloading", Current: current, Total: len(hashList)})
			return nil
		})
		if err != nil {
			return nil, err
		}

		err = pool.Parallel(resp.Standalone, concurrency, func(entry sdktypes.DownloadURLEntry) error {
			chunkData, err := decodeStandaloneChunk(entry, dek, verifyChecksums)
			if err != nil {
				return err
			}
			mu.Lock()
			chunkCache[entry.Hash] = chunkData
			downloaded++
			current := downloaded
			mu.Unlock()
			emit(sdktypes.ProgressEvent{Phase: "downloading", Current: current, Total: len(hashList)})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return chunkCache, nil
}

func decodePackChunk(
	packData []byte,
	chMeta sdktypes.PackDownloadChunk,
	dek []byte,
	verifyChecksums bool,
) ([]byte, error) {
	stored := make([]byte, chMeta.Size)
	copy(stored, packData[chMeta.Offset:chMeta.Offset+chMeta.Size])
	chunkData := stored
	var err error
	if dek != nil {
		objKey, derr := encrypt.DeriveDataKey(dek, chMeta.Hash)
		if derr != nil {
			return nil, fmt.Errorf("derive data key %s: %w", chMeta.Hash, derr)
		}
		chunkData, err = encrypt.DecryptObject(objKey, stored)
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %s: %w", chMeta.Hash, err)
		}
	}
	chunkData, err = codec.MaybeDecompressStoredOrInferZstd(chunkData, chMeta.Compression)
	if err != nil {
		return nil, fmt.Errorf("decompress chunk %s: %w", chMeta.Hash, err)
	}
	if verifyChecksums {
		actual := chunk.SHA256Hex(chunkData)
		if actual != chMeta.Hash {
			return nil, fmt.Errorf("checksum mismatch for chunk %s: got %s", chMeta.Hash, actual)
		}
	}
	return chunkData, nil
}

func decodeStandaloneChunk(
	entry sdktypes.DownloadURLEntry,
	dek []byte,
	verifyChecksums bool,
) ([]byte, error) {
	data, err := api.S3Get(entry.URL)
	if err != nil {
		return nil, err
	}
	if dek != nil {
		objKey, derr := encrypt.DeriveDataKey(dek, entry.Hash)
		if derr != nil {
			return nil, fmt.Errorf("derive data key %s: %w", entry.Hash, derr)
		}
		data, err = encrypt.DecryptObject(objKey, data)
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %s: %w", entry.Hash, err)
		}
	}
	data, err = codec.MaybeDecompressStoredOrInferZstd(data, "")
	if err != nil {
		return nil, fmt.Errorf("decompress chunk %s: %w", entry.Hash, err)
	}
	if verifyChecksums {
		actual := chunk.SHA256Hex(data)
		if actual != entry.Hash {
			return nil, fmt.Errorf("checksum mismatch for chunk %s: got %s", entry.Hash, actual)
		}
	}
	return data, nil
}

func ensureAllChunksPresent(allDataHashes map[string]bool, chunkCache map[string][]byte) error {
	var missingChunks []string
	for h := range allDataHashes {
		if _, ok := chunkCache[h]; !ok {
			missingChunks = append(missingChunks, h)
		}
	}
	if len(missingChunks) > 0 {
		return fmt.Errorf("restore incomplete: %d chunk(s) missing, first: %s", len(missingChunks), missingChunks[0])
	}
	return nil
}

func writeRestoredFiles(
	targetDir string,
	fileMap map[string][]string,
	chunkCache map[string][]byte,
	emit func(sdktypes.ProgressEvent),
) error {
	written := 0
	totalFiles := len(fileMap)
	for relPath, hashes := range fileMap {
		filePath, err := safeJoinTarget(targetDir, relPath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			return fmt.Errorf("mkdir for %s: %w", relPath, err)
		}
		f, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("create %s: %w", relPath, err)
		}
		for _, h := range hashes {
			data, ok := chunkCache[h]
			if !ok {
				f.Close()
				return fmt.Errorf("missing chunk %s for file %s", h, relPath)
			}
			if _, err := f.Write(data); err != nil {
				f.Close()
				return fmt.Errorf("write %s: %w", relPath, err)
			}
		}
		f.Close()
		written++
		emit(sdktypes.ProgressEvent{Phase: "writing", Current: written, Total: totalFiles})
	}
	return nil
}

func joinTreePath(basePath, name string) (string, error) {
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("invalid tree node name %q", name)
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("invalid tree node name %q", name)
	}
	if basePath == "" {
		return name, nil
	}
	return basePath + "/" + name, nil
}

func safeJoinTarget(targetDir, relPath string) (string, error) {
	cleanRel := filepath.Clean(relPath)
	if cleanRel == "." || cleanRel == "" {
		return "", fmt.Errorf("invalid restore path %q", relPath)
	}
	if filepath.IsAbs(cleanRel) {
		return "", fmt.Errorf("absolute restore path is not allowed: %q", relPath)
	}
	fullPath := filepath.Join(targetDir, cleanRel)
	relFromBase, err := filepath.Rel(targetDir, fullPath)
	if err != nil {
		return "", fmt.Errorf("validate restore path %q: %w", relPath, err)
	}
	if relFromBase == ".." || strings.HasPrefix(relFromBase, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("restore path escapes target directory: %q", relPath)
	}
	return fullPath, nil
}
