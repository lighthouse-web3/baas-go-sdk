package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type treeCollections struct {
	trees    map[string]TreeBlob
	fileMap  map[string][]string
	nodeMeta map[string]TreeNode
}

// resolveTree downloads and parses a tree blob recursively.
func resolveTree(http *HttpClient, hash, basePath string, col *treeCollections, dek []byte) error {
	if _, ok := col.trees[hash]; ok {
		return nil
	}

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
		if dek != nil {
			treeKey, terr := DeriveTreeKey(dek, hash)
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
		if dek != nil {
			treeKey, terr := DeriveTreeKey(dek, hash)
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
		return fmt.Errorf("no download URL for tree %s", hash)
	}

	var tree TreeBlob
	if err := json.Unmarshal(data, &tree); err != nil {
		return fmt.Errorf("decode tree %s: %w", hash, err)
	}
	col.trees[hash] = tree

	for _, node := range tree.Nodes {
		relPath := node.Name
		if basePath != "" {
			relPath = basePath + "/" + node.Name
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

func restoreMeta(trees map[string]TreeBlob, targetDir, hash, basePath string) error {
	tree, ok := trees[hash]
	if !ok {
		return nil
	}

	for _, node := range tree.Nodes {
		relPath := node.Name
		if basePath != "" {
			relPath = basePath + "/" + node.Name
		}
		fullPath := filepath.Join(targetDir, relPath)

		if node.Type == "dir" {
			os.MkdirAll(fullPath, 0o755)
			if node.Subtree != "" {
				restoreMeta(trees, targetDir, node.Subtree, relPath)
			}
		} else if node.Type == "symlink" && node.Target != "" {
			os.Symlink(node.Target, fullPath)
		}

		applyNodeMeta(fullPath, node)
	}
	return nil
}

func applyNodeMeta(fullPath string, node TreeNode) {
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
	http *HttpClient,
	snapshotID string,
	targetDir string,
	options *RestoreOptions,
	concurrency int,
) error {
	if options == nil {
		options = &RestoreOptions{}
	}
	verifyChecksums := true
	if options != nil && options.SkipChecksumVerification {
		verifyChecksums = false
	}
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	emit := func(e ProgressEvent) {
		if options.OnProgress != nil {
			options.OnProgress(e)
		}
	}

	// 1. Fetch snapshot metadata
	snapshot, err := http.GetSnapshot(snapshotID)
	if err != nil {
		return fmt.Errorf("get snapshot: %w", err)
	}

	// 1b. Encryption: unwrap DEK if snapshot is encrypted
	var dek []byte
	if snapshot.WrappedDEK != "" {
		if options.Encryption == nil {
			return fmt.Errorf("snapshot is encrypted but no encryption options provided")
		}
		tmk, err := loadTMK(options.Encryption)
		if err != nil {
			return fmt.Errorf("load encryption key: %w", err)
		}
		dek, err = UnwrapDEK(tmk, snapshot.WrappedDEK)
		if err != nil {
			return fmt.Errorf("unwrap DEK (wrong passphrase?): %w", err)
		}
		emit(ProgressEvent{Phase: "encryption", Message: "DEK unwrapped, decryption enabled"})
	}

	// 2. Recursively download and parse all tree blobs
	emit(ProgressEvent{Phase: "downloading", Message: "Downloading tree…"})

	col := &treeCollections{
		trees:    make(map[string]TreeBlob),
		fileMap:  make(map[string][]string),
		nodeMeta: make(map[string]TreeNode),
	}

	if err := resolveTree(http, snapshot.RootTreeHash, "", col, dek); err != nil {
		return fmt.Errorf("resolve tree: %w", err)
	}

	emit(ProgressEvent{Phase: "downloading", Current: len(col.trees), Total: len(col.trees),
		Message: fmt.Sprintf("%d tree blobs, %d files", len(col.trees), len(col.fileMap))})

	// 3. Collect all unique data-chunk hashes
	allDataHashes := make(map[string]bool)
	for _, hashes := range col.fileMap {
		for _, h := range hashes {
			allDataHashes[h] = true
		}
	}

	hashList := make([]string, 0, len(allDataHashes))
	for h := range allDataHashes {
		hashList = append(hashList, h)
	}
	if verifyChecksums {
		emit(ProgressEvent{Phase: "verifying", Message: "Checksum verification enabled"})
	}

	// 4. Download chunks via packs
	chunkCache := make(map[string][]byte)
	downloaded := 0

	for _, batch := range Batch(hashList, 500) {
		resp, err := http.RequestDownloadURLs(batch)
		if err != nil {
			return fmt.Errorf("request download URLs: %w", err)
		}

		// Download packs in parallel
		err = Parallel(resp.Packs, concurrency, func(packEntry PackDownloadEntry) error {
			packData, err := S3Get(packEntry.URL)
			if err != nil {
				return err
			}
			for _, ch := range packEntry.Chunks {
				stored := make([]byte, ch.Size)
				copy(stored, packData[ch.Offset:ch.Offset+ch.Size])
				chunkData := stored
				var cerr error
				if dek != nil {
					var objKey []byte
					objKey, cerr = DeriveDataKey(dek, ch.Hash)
					if cerr != nil {
						return fmt.Errorf("derive data key %s: %w", ch.Hash, cerr)
					}
					chunkData, cerr = DecryptObject(objKey, stored)
					if cerr != nil {
						return fmt.Errorf("decrypt chunk %s: %w", ch.Hash, cerr)
					}
				}
				chunkData, cerr = maybeDecompressStoredOrInferZstd(chunkData, ch.Compression)
				if cerr != nil {
					return fmt.Errorf("decompress chunk %s: %w", ch.Hash, cerr)
				}
				if verifyChecksums {
					actual := SHA256Hex(chunkData)
					if actual != ch.Hash {
						return fmt.Errorf("checksum mismatch for chunk %s: got %s", ch.Hash, actual)
					}
				}
				chunkCache[ch.Hash] = chunkData
			}
			downloaded += len(packEntry.Chunks)
			emit(ProgressEvent{Phase: "downloading", Current: downloaded, Total: len(hashList)})
			return nil
		})
		if err != nil {
			return err
		}

		// Download standalone chunks
		err = Parallel(resp.Standalone, concurrency, func(entry DownloadURLEntry) error {
			data, err := S3Get(entry.URL)
			if err != nil {
				return err
			}
			if dek != nil {
				objKey, err := DeriveDataKey(dek, entry.Hash)
				if err != nil {
					return fmt.Errorf("derive data key %s: %w", entry.Hash, err)
				}
				data, err = DecryptObject(objKey, data)
				if err != nil {
					return fmt.Errorf("decrypt chunk %s: %w", entry.Hash, err)
				}
			}
			data, err = maybeDecompressStoredOrInferZstd(data, "")
			if err != nil {
				return fmt.Errorf("decompress chunk %s: %w", entry.Hash, err)
			}
			if verifyChecksums {
				actual := SHA256Hex(data)
				if actual != entry.Hash {
					return fmt.Errorf("checksum mismatch for chunk %s: got %s", entry.Hash, actual)
				}
			}
			chunkCache[entry.Hash] = data
			downloaded++
			emit(ProgressEvent{Phase: "downloading", Current: downloaded, Total: len(hashList)})
			return nil
		})
		if err != nil {
			return err
		}
	}

	// 5. Verify all chunks were downloaded
	var missingChunks []string
	for h := range allDataHashes {
		if _, ok := chunkCache[h]; !ok {
			missingChunks = append(missingChunks, h)
		}
	}
	if len(missingChunks) > 0 {
		return fmt.Errorf("restore incomplete: %d chunk(s) missing, first: %s",
			len(missingChunks), missingChunks[0])
	}

	// 6. Reassemble files
	written := 0
	totalFiles := len(col.fileMap)

	for relPath, hashes := range col.fileMap {
		filePath := filepath.Join(targetDir, relPath)
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
		emit(ProgressEvent{Phase: "writing", Current: written, Total: totalFiles})
	}

	// 7. Restore directory structure, symlinks, and metadata
	restoreMeta(col.trees, targetDir, snapshot.RootTreeHash, "")

	return nil
}
