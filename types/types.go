package types

import "encoding/json"

// ChunkOptions configures FastCDC chunk sizes.
type ChunkOptions struct {
	MinSize int
	AvgSize int
	MaxSize int
}

// DefaultChunkOptions matches the TypeScript SDK defaults.
var DefaultChunkOptions = ChunkOptions{
	MinSize: 1 * 1024 * 1024,  // 1 MiB
	AvgSize: 4 * 1024 * 1024,  // 4 MiB
	MaxSize: 16 * 1024 * 1024, // 16 MiB
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

// ChunkSizeEntry is used when requesting pre-signed upload URLs.
type ChunkSizeEntry struct {
	Hash string `json:"hash"`
	Size int    `json:"size"`
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

// NonceResponse is returned from POST /auth/nonce.
type NonceResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresIn int    `json:"expiresIn"`
	Domain    string `json:"domain"`
	URI       string `json:"uri"`
	ChainID   int    `json:"chainId"`
}

// AuthIdentity describes a single identity bound to a user account.
type AuthIdentity struct {
	Provider      string `json:"provider"`
	Identifier    string `json:"identifier"`
	WalletAddress string `json:"walletAddress,omitempty"`
	Email         string `json:"email,omitempty"`
	Verified      bool   `json:"verified,omitempty"`
}

// AuthUser is the user payload returned alongside auth tokens.
type AuthUser struct {
	UserID      string `json:"userId"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// AuthResponse is the unified response for SIWE verify and email login.
type AuthResponse struct {
	Token string   `json:"token"`
	User  AuthUser `json:"user"`
}

type EmailRegisterRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName,omitempty"`
}

type EmailRegisterResponse struct {
	UserID  string `json:"userId"`
	Message string `json:"message,omitempty"`
}

type EmailVerifyRequest struct {
	Token string `json:"token,omitempty"`
	Email string `json:"email,omitempty"`
	Code  string `json:"code,omitempty"`
}

type EmailVerifyResponse struct {
	Verified bool      `json:"verified"`
	Token    string    `json:"token,omitempty"`
	User     *AuthUser `json:"user,omitempty"`
}

type EmailLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LinkIdentityRequest struct {
	Provider        string `json:"provider"`
	ProviderSubject string `json:"providerSubject"`
	Password        string `json:"password,omitempty"`
}

type LinkIdentityResponse struct {
	Linked   bool         `json:"linked"`
	Identity AuthIdentity `json:"identity"`
}

type UserProfile struct {
	UserID      string `json:"userId"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"`
}

type IdentityListResponse struct {
	Identities []AuthIdentity `json:"identities"`
}

func (r *IdentityListResponse) UnmarshalJSON(data []byte) error {
	type identityListAlias IdentityListResponse
	var wrapped identityListAlias
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Identities != nil {
		*r = IdentityListResponse(wrapped)
		return nil
	}

	var bare []AuthIdentity
	if err := json.Unmarshal(data, &bare); err != nil {
		return err
	}
	r.Identities = bare
	return nil
}

type APIKey struct {
	APIKeyID    string   `json:"apiKeyId"`
	Name        string   `json:"name,omitempty"`
	KeyPrefix   string   `json:"keyPrefix,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Status      string   `json:"status,omitempty"`
	CreatedAt   string   `json:"createdAt,omitempty"`
	ExpiresAt   string   `json:"expiresAt,omitempty"`
	LastUsedAt  string   `json:"lastUsedAt,omitempty"`
	Revoked     bool     `json:"revoked,omitempty"`
	WorkspaceID string   `json:"workspaceId,omitempty"`
}

func (k *APIKey) UnmarshalJSON(data []byte) error {
	type apiKeyAlias APIKey
	type apiKeyCompat struct {
		apiKeyAlias
		KeyPrefix string `json:"keyPrefix,omitempty"`
		Prefix    string `json:"prefix,omitempty"`
	}

	var tmp apiKeyCompat
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	*k = APIKey(tmp.apiKeyAlias)
	if tmp.KeyPrefix != "" {
		k.KeyPrefix = tmp.KeyPrefix
	} else {
		k.KeyPrefix = tmp.Prefix
	}
	return nil
}

type APIKeyCreateRequest struct {
	Name        string   `json:"name,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	WorkspaceID string   `json:"workspaceId,omitempty"`
	ExpiresAt   string   `json:"expiresAt,omitempty"`
}

type APIKeyCreateResponse struct {
	APIKey    APIKey `json:"apiKey,omitempty"`
	PlainText string `json:"plaintext,omitempty"`
	Key       string `json:"key,omitempty"`
}

func (r *APIKeyCreateResponse) UnmarshalJSON(data []byte) error {
	type createAlias APIKeyCreateResponse
	var wrapped createAlias
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return err
	}
	*r = APIKeyCreateResponse(wrapped)
	if r.APIKey.APIKeyID != "" {
		return nil
	}

	var flat APIKey
	if err := json.Unmarshal(data, &flat); err == nil && flat.APIKeyID != "" {
		r.APIKey = flat
	}
	return nil
}

type APIKeyListResponse struct {
	APIKeys []APIKey `json:"apiKeys"`
}

func (r *APIKeyListResponse) UnmarshalJSON(data []byte) error {
	type apiKeyListAlias APIKeyListResponse
	var wrapped apiKeyListAlias
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.APIKeys != nil {
		*r = APIKeyListResponse(wrapped)
		return nil
	}

	var bare []APIKey
	if err := json.Unmarshal(data, &bare); err != nil {
		return err
	}
	r.APIKeys = bare
	return nil
}

func (r APIKeyCreateResponse) Plaintext() string {
	if r.PlainText != "" {
		return r.PlainText
	}
	return r.Key
}

type Workspace struct {
	WorkspaceID     string  `json:"workspaceId"`
	Name            string  `json:"name"`
	CreatedByUserID string  `json:"createdByUserId,omitempty"`
	CreatedAt       string  `json:"createdAt,omitempty"`
	UpdatedAt       string  `json:"updatedAt,omitempty"`
	DataUsed        int64   `json:"dataUsed,omitempty"`
	DataLimit       int64   `json:"dataLimit,omitempty"`
	SubscriptionID  *string `json:"subscriptionId,omitempty"`
	PlanID          *string `json:"planId,omitempty"`
	BillingStatus   *string `json:"billingStatus,omitempty"`
}

func (w *Workspace) UnmarshalJSON(data []byte) error {
	type workspaceAlias Workspace
	type workspaceCompat struct {
		workspaceAlias
		DataUsed  json.Number `json:"dataUsed,omitempty"`
		DataLimit json.Number `json:"dataLimit,omitempty"`
	}

	var tmp workspaceCompat
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	*w = Workspace(tmp.workspaceAlias)

	if tmp.DataUsed != "" {
		v, err := tmp.DataUsed.Int64()
		if err != nil {
			return err
		}
		w.DataUsed = v
	}
	if tmp.DataLimit != "" {
		v, err := tmp.DataLimit.Int64()
		if err != nil {
			return err
		}
		w.DataLimit = v
	}
	return nil
}

type WorkspaceCreateRequest struct {
	Name string `json:"name"`
}

type WorkspaceUpdateRequest struct {
	Name string `json:"name,omitempty"`
}

type WorkspaceListResponse struct {
	Workspaces []Workspace `json:"workspaces"`
	Cursor     *string     `json:"cursor,omitempty"`
}

func (r *WorkspaceListResponse) UnmarshalJSON(data []byte) error {
	type workspaceListAlias WorkspaceListResponse
	var wrapped workspaceListAlias
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Workspaces != nil {
		*r = WorkspaceListResponse(wrapped)
		return nil
	}

	var bare []Workspace
	if err := json.Unmarshal(data, &bare); err != nil {
		return err
	}
	r.Workspaces = bare
	return nil
}

type WorkspaceMember struct {
	WorkspaceID   string   `json:"workspaceId,omitempty"`
	UserID        string   `json:"userId"`
	Email         string   `json:"email,omitempty"`
	DisplayName   string   `json:"displayName,omitempty"`
	Role          string   `json:"role"`
	ExtraScopes   []string `json:"extraScopes,omitempty"`
	RevokedScopes []string `json:"revokedScopes,omitempty"`
	CreatedAt     string   `json:"createdAt,omitempty"`
}

type WorkspaceMemberListResponse struct {
	Members []WorkspaceMember `json:"members"`
}

func (r *WorkspaceMemberListResponse) UnmarshalJSON(data []byte) error {
	type memberListAlias WorkspaceMemberListResponse
	var wrapped memberListAlias
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Members != nil {
		*r = WorkspaceMemberListResponse(wrapped)
		return nil
	}

	var bare []WorkspaceMember
	if err := json.Unmarshal(data, &bare); err != nil {
		return err
	}
	r.Members = bare
	return nil
}

type WorkspaceMemberInvite struct {
	Email  string `json:"email,omitempty"`
	UserID string `json:"userId,omitempty"`
	Role   string `json:"role"`
}

type WorkspaceMemberUpdate struct {
	Role          string   `json:"role,omitempty"`
	ExtraScopes   []string `json:"extraScopes,omitempty"`
	RevokedScopes []string `json:"revokedScopes,omitempty"`
}

const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
	RoleViewer = "viewer"
)

const (
	ScopeBackupWrite     = "backup:write"
	ScopeBackupRead      = "backup:read"
	ScopeRestoreWrite    = "restore:write"
	ScopeRestoreRead     = "restore:read"
	ScopeSnapshotsRead   = "snapshots:read"
	ScopeUserRead        = "user:read"
	ScopeAPIKeysManage   = "api_keys:manage"
	ScopeWorkspaceManage = "workspace:manage"
)

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

// UnmarshalJSON supports usage fields encoded as either numbers or strings.
func (r *PackConfirmResponse) UnmarshalJSON(data []byte) error {
	type packConfirmAlias PackConfirmResponse
	type packConfirmCompat struct {
		packConfirmAlias
		DataUsed  json.Number `json:"dataUsed"`
		DataLimit json.Number `json:"dataLimit"`
	}

	var tmp packConfirmCompat
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	*r = PackConfirmResponse(tmp.packConfirmAlias)
	if tmp.DataUsed != "" {
		v, err := tmp.DataUsed.Int64()
		if err != nil {
			return err
		}
		r.DataUsed = v
	}
	if tmp.DataLimit != "" {
		v, err := tmp.DataLimit.Int64()
		if err != nil {
			return err
		}
		r.DataLimit = v
	}
	return nil
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

type BloomResponse struct {
	NumBits   int    `json:"numBits"`
	NumHashes int    `json:"numHashes"`
	Data      string `json:"data"`
	Count     int    `json:"count"`
}

type EncryptionMeta struct {
	Scheme         string `json:"scheme"`
	DekWrappedWith string `json:"dekWrappedWith"`
}

type Snapshot struct {
	SnapshotID   string            `json:"snapshotId"`
	WorkspaceID  string            `json:"workspaceId"`
	RootTreeHash string            `json:"rootTreeHash"`
	Hostname     string            `json:"hostname"`
	SourceID     string            `json:"sourceId"`
	Paths        []string          `json:"paths"`
	Description  string            `json:"description"`
	Tags         map[string]string `json:"tags"`
	TotalSize    int64             `json:"totalSize"`
	TotalChunks  int               `json:"totalChunks"`
	CreatedAt    int64             `json:"createdAt"`
	WrappedDEK   string            `json:"wrappedDek,omitempty"`
	Encryption   *EncryptionMeta   `json:"encryption,omitempty"`
}

type SnapshotListResponse struct {
	Snapshots []Snapshot `json:"snapshots"`
	Cursor    *string    `json:"cursor"`
}

type SnapshotInput struct {
	RootTreeHash string            `json:"rootTreeHash"`
	Hostname     string            `json:"hostname,omitempty"`
	SourceID     string            `json:"sourceId,omitempty"`
	Paths        []string          `json:"paths,omitempty"`
	Description  string            `json:"description,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	TotalSize    int64             `json:"totalSize,omitempty"`
	TotalChunks  int               `json:"totalChunks,omitempty"`
	WrappedDEK   string            `json:"wrappedDek,omitempty"`
	Encryption   *EncryptionMeta   `json:"encryption,omitempty"`
}

type SnapshotEncryptionUpdate struct {
	WrappedDEK string          `json:"wrappedDek"`
	Encryption *EncryptionMeta `json:"encryption,omitempty"`
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

type Usage struct {
	WorkspaceID string  `json:"workspaceId,omitempty"`
	DataUsed    int64   `json:"dataUsed"`
	DataLimit   int64   `json:"dataLimit"`
	Available   int64   `json:"available"`
	Percentage  float64 `json:"percentage"`
}

// UnmarshalJSON supports usage fields encoded as either numbers or strings.
func (u *Usage) UnmarshalJSON(data []byte) error {
	type usageAlias Usage
	type usageCompat struct {
		usageAlias
		DataUsed   json.Number `json:"dataUsed"`
		DataLimit  json.Number `json:"dataLimit"`
		Available  json.Number `json:"available"`
		Percentage json.Number `json:"percentage"`
	}

	var tmp usageCompat
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	*u = Usage(tmp.usageAlias)
	if tmp.DataUsed != "" {
		v, err := tmp.DataUsed.Int64()
		if err != nil {
			return err
		}
		u.DataUsed = v
	}
	if tmp.DataLimit != "" {
		v, err := tmp.DataLimit.Int64()
		if err != nil {
			return err
		}
		u.DataLimit = v
	}
	if tmp.Available != "" {
		v, err := tmp.Available.Int64()
		if err != nil {
			return err
		}
		u.Available = v
	}
	if tmp.Percentage != "" {
		v, err := tmp.Percentage.Float64()
		if err != nil {
			return err
		}
		u.Percentage = v
	}
	return nil
}

type PruneRequest struct {
	KeepLatest *int   `json:"keepLatest,omitempty"`
	Before     string `json:"before,omitempty"`
	DryRun     bool   `json:"dryRun,omitempty"`
}

type PruneResponse struct {
	DryRun      bool     `json:"dryRun"`
	KeepLatest  int      `json:"keepLatest"`
	Before      string   `json:"before,omitempty"`
	Candidates  int      `json:"candidates,omitempty"`
	Deleted     int      `json:"deleted,omitempty"`
	SnapshotIDs []string `json:"snapshotIds,omitempty"`
}

func (r PruneResponse) Count() int {
	if r.DryRun {
		return r.Candidates
	}
	return r.Deleted
}

type EncryptionOptions struct {
	KeyfilePath    string
	Passphrase     string
	PassphraseFunc func() (string, error)
}

type BackupOptions struct {
	WorkspaceID            string
	Description            string
	Hostname               string
	SourceID               string
	Tags                   map[string]string
	ParentSnapshotID       string
	OnProgress             func(ProgressEvent)
	DisablePackCompression bool
	Encryption             *EncryptionOptions
}

type RestoreOptions struct {
	WorkspaceID              string
	OnProgress               func(ProgressEvent)
	SkipChecksumVerification bool
	Encryption               *EncryptionOptions
}

type ProgressEvent struct {
	Phase                 string
	Current               int
	Total                 int
	Bytes                 int64
	StoredBytes           int64
	RawBytes              int64
	CompressionSavedBytes int64
	CompressionRatio      float64
	Message               string
}
