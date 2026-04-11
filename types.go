package backup

// ChunkOptions configures FastCDC chunk sizes.
type ChunkOptions struct {
	MinSize int
	AvgSize int
	MaxSize int
}

// DefaultChunkOptions matches the TypeScript SDK defaults.
var DefaultChunkOptions = ChunkOptions{
	MinSize: 1 * 1024 * 1024,   //   8 MiB
	AvgSize: 4 * 1024 * 1024,  //  32 MiB
	MaxSize: 16 * 1024 * 1024, // 128 MiB
}

// ChunkData holds raw chunk bytes and their SHA-256 identity hash.
type ChunkData struct {
	Hash string
	Data []byte
	Size int
}

// ChunkMeta is the metadata sent when confirming uploaded chunks.
type ChunkMeta struct {
	Hash string `json:"hash"`
	Size int    `json:"size"`
	Type string `json:"type"`
}

// TreeNode represents a single entry in a tree blob.
type TreeNode struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Mode    *int     `json:"mode,omitempty"`
	Size    *int64   `json:"size,omitempty"`
	Mtime   string   `json:"mtime,omitempty"`
	Content []string `json:"content,omitempty"`
	Subtree string   `json:"subtree,omitempty"`
	Target  string   `json:"target,omitempty"`
}

// TreeBlob is the JSON structure stored as a tree chunk.
type TreeBlob struct {
	Nodes []TreeNode `json:"nodes"`
}

// ── API response types ──────────────────────────────────────────────────────

type NonceResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresIn int    `json:"expiresIn"`
	Domain    string `json:"domain"`
	URI       string `json:"uri"`
	ChainID   int    `json:"chainId"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  struct {
		WalletAddress string `json:"walletAddress"`
		DataLimit     int64  `json:"dataLimit"`
		DataUsed      int64  `json:"dataUsed"`
	} `json:"user"`
}

type DedupResponse struct {
	Existing []string `json:"existing"`
	Missing  []string `json:"missing"`
}

type UploadURLEntry struct {
	Hash string `json:"hash"`
	URL  string `json:"url"`
	Key  string `json:"key"`
}

type UploadURLsResponse struct {
	URLs          []UploadURLEntry `json:"urls"`
	Existing      []string         `json:"existing"`
	TotalNewBytes *int64           `json:"totalNewBytes,omitempty"`
	Message       string           `json:"message,omitempty"`
}

type ConfirmResponse struct {
	Confirmed []string           `json:"confirmed"`
	Failed    []ConfirmFailEntry `json:"failed"`
	DataUsed  int64              `json:"dataUsed"`
	DataLimit int64              `json:"dataLimit"`
}

type ConfirmFailEntry struct {
	Hash   string `json:"hash"`
	Reason string `json:"reason"`
}

type DownloadURLEntry struct {
	Hash string `json:"hash"`
	URL  string `json:"url"`
}

// ── Pack types ──────────────────────────────────────────────────────────────

type PackUploadURLResponse struct {
	PackID string `json:"packId"`
	URL    string `json:"url"`
	Key    string `json:"key"`
}

type PackChunkMeta struct {
	Hash             string `json:"hash"`
	Size             int    `json:"size"`
	Offset           int    `json:"offset"`
	Type             string `json:"type"`
	Compression      string `json:"compression,omitempty"`
	UncompressedSize int    `json:"uncompressedSize,omitempty"`
}

type PackConfirmResponse struct {
	Confirmed []string `json:"confirmed"`
	DataUsed  int64    `json:"dataUsed"`
	DataLimit int64    `json:"dataLimit"`
}

type PackDownloadChunk struct {
	Hash             string `json:"hash"`
	Offset           int    `json:"offset"`
	Size             int    `json:"size"`
	Compression      string `json:"compression,omitempty"`
	UncompressedSize int    `json:"uncompressedSize,omitempty"`
}

type PackDownloadEntry struct {
	PackID string              `json:"packId"`
	URL    string              `json:"url"`
	Chunks []PackDownloadChunk `json:"chunks"`
}

type PackDownloadResponse struct {
	Packs      []PackDownloadEntry `json:"packs"`
	Standalone []DownloadURLEntry  `json:"standalone"`
}

// ── Bloom filter ────────────────────────────────────────────────────────────

type BloomResponse struct {
	NumBits   int    `json:"numBits"`
	NumHashes int    `json:"numHashes"`
	Data      string `json:"data"`
	Count     int    `json:"count"`
}

// ── Snapshot ────────────────────────────────────────────────────────────────

// EncryptionMeta describes the encryption scheme used for a snapshot.
// Stored alongside the snapshot on the server for forward compatibility.
type EncryptionMeta struct {
	Scheme       string `json:"scheme"`
	DekWrappedWith string `json:"dekWrappedWith"`
}

type Snapshot struct {
	WalletAddress string            `json:"walletAddress"`
	SnapshotID    string            `json:"snapshotId"`
	RootTreeHash  string            `json:"rootTreeHash"`
	Hostname      string            `json:"hostname"`
	Paths         []string          `json:"paths"`
	Description   string            `json:"description"`
	Tags          map[string]string `json:"tags"`
	TotalSize     int64             `json:"totalSize"`
	TotalChunks   int               `json:"totalChunks"`
	CreatedAt     int64             `json:"createdAt"`
	WrappedDEK    string            `json:"wrappedDek,omitempty"`
	Encryption    *EncryptionMeta   `json:"encryption,omitempty"`
}

type SnapshotListResponse struct {
	Snapshots []Snapshot `json:"snapshots"`
	Cursor    *string    `json:"cursor"`
}

type SnapshotInput struct {
	RootTreeHash string            `json:"rootTreeHash"`
	Hostname     string            `json:"hostname,omitempty"`
	Paths        []string          `json:"paths,omitempty"`
	Description  string            `json:"description,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	TotalSize    int64             `json:"totalSize,omitempty"`
	TotalChunks  int               `json:"totalChunks,omitempty"`
	WrappedDEK   string            `json:"wrappedDek,omitempty"`
	Encryption   *EncryptionMeta   `json:"encryption,omitempty"`
}

type SnapshotTreeResponse struct {
	SnapshotID   string `json:"snapshotId"`
	RootTreeHash string `json:"rootTreeHash"`
	URL          string `json:"url"`
}

type DeleteSnapshotResponse struct {
	Deleted    bool   `json:"deleted"`
	SnapshotID string `json:"snapshotId"`
}

// ── Usage ───────────────────────────────────────────────────────────────────

type Usage struct {
	DataUsed   int64   `json:"dataUsed"`
	DataLimit  int64   `json:"dataLimit"`
	Available  int64   `json:"available"`
	Percentage float64 `json:"percentage"`
}

// ── Retention & pruning ─────────────────────────────────────────────────────

type RetentionPolicy struct {
	KeepLast       *int `json:"keepLast,omitempty"`
	KeepWithinDays *int `json:"keepWithinDays,omitempty"`
}

type PruneResponse struct {
	DeletedSnapshots []string `json:"deletedSnapshots"`
	DeletedChunks    int      `json:"deletedChunks"`
	DeletedPacks     []string `json:"deletedPacks"`
	FreedBytes       int64    `json:"freedBytes"`
}

// ── Encryption options ──────────────────────────────────────────────────────

// EncryptionOptions configures client-side encryption for backup or restore.
// The TMK is loaded from KeyfilePath using Passphrase (or PassphraseFunc for
// interactive applications). The key material is held in memory only.
type EncryptionOptions struct {
	KeyfilePath    string
	Passphrase     string
	PassphraseFunc func() (string, error)
}

// ── Backup / Restore options ────────────────────────────────────────────────

type BackupOptions struct {
	Description            string
	Hostname               string
	Tags                   map[string]string
	ParentSnapshotID       string
	OnProgress             func(ProgressEvent)
	DisablePackCompression bool
	Encryption             *EncryptionOptions
}

type RestoreOptions struct {
	OnProgress               func(ProgressEvent)
	SkipChecksumVerification bool
	Encryption               *EncryptionOptions
}

type ProgressEvent struct {
	Phase   string
	Current int
	Total   int
	Bytes   int64
	// StoredBytes is the post-compression payload size uploaded/downloaded.
	StoredBytes int64
	// RawBytes is the pre-compression payload size for the same unit of work.
	RawBytes int64
	// CompressionSavedBytes is RawBytes - StoredBytes (0 when no compression gain).
	CompressionSavedBytes int64
	// CompressionRatio is StoredBytes/RawBytes in [0,1], when RawBytes > 0.
	CompressionRatio float64
	Message string
}

// IntPtr returns a pointer to an int value (helper for optional fields).
func IntPtr(v int) *int { return &v }

// Int64Ptr returns a pointer to an int64 value (helper for optional fields).
func Int64Ptr(v int64) *int64 { return &v }
