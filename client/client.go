package client

import (
	"errors"
	"fmt"

	"github.com/lighthouse-web3/baas-go-sdk/api"
	"github.com/lighthouse-web3/baas-go-sdk/pipeline"
	sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
)

// DefaultChunkOptions controls default chunking for high-level client usage.
var DefaultChunkOptions = sdktypes.DefaultChunkOptions

// BackupClientOptions configures the high-level BackupClient.
type BackupClientOptions struct {
	APIURL string

	APIKey string
	Token  string

	PrivateKey  string
	SignMessage func(message string) (string, error)
	Address     string

	Email    string
	Password string

	WorkspaceID string

	ChunkOptions *sdktypes.ChunkOptions
	Concurrency  int
}

// BackupClient is the high-level Lighthouse SDK client.
type BackupClient struct {
	HTTP          *api.HttpClient
	address       string
	wallet        *api.WalletAdapter
	email         string
	password      string
	chunkOpts     sdktypes.ChunkOptions
	concurrency   int
	authenticated bool
}

func NewBackupClient(opts BackupClientOptions) (*BackupClient, error) {
	if opts.APIURL == "" {
		return nil, errors.New("APIURL is required")
	}

	chunkOpts := DefaultChunkOptions
	if opts.ChunkOptions != nil {
		chunkOpts = *opts.ChunkOptions
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}

	c := &BackupClient{
		HTTP:        api.NewHttpClient(opts.APIURL),
		chunkOpts:   chunkOpts,
		concurrency: concurrency,
	}

	if opts.WorkspaceID != "" {
		c.HTTP.SetWorkspaceID(opts.WorkspaceID)
	}

	switch {
	case opts.APIKey != "":
		c.HTTP.SetToken(opts.APIKey)
		c.authenticated = true
	case opts.Token != "":
		c.HTTP.SetToken(opts.Token)
		c.authenticated = true
	case opts.PrivateKey != "" || (opts.SignMessage != nil && opts.Address != ""):
		wallet, err := buildWallet(opts)
		if err != nil {
			return nil, err
		}
		c.wallet = wallet
		c.address = wallet.Address
	case opts.Email != "" && opts.Password != "":
		c.email = opts.Email
		c.password = opts.Password
	}

	return c, nil
}

func (c *BackupClient) Address() string { return c.address }
func (c *BackupClient) SetWorkspaceID(id string) {
	c.HTTP.SetWorkspaceID(id)
}
func (c *BackupClient) WorkspaceID() string { return c.HTTP.WorkspaceID() }
func (c *BackupClient) SetToken(token string) {
	c.HTTP.SetToken(token)
	c.authenticated = true
}
func (c *BackupClient) SetAPIKey(apiKey string) { c.SetToken(apiKey) }

func (c *BackupClient) Authenticate() (string, error) {
	if c.wallet == nil {
		return "", errors.New("SIWE authentication requires PrivateKey or SignMessage+Address")
	}
	token, err := api.Authenticate(c.HTTP, c.wallet)
	if err != nil {
		return "", err
	}
	c.authenticated = true
	return token, nil
}

func (c *BackupClient) AuthenticateEmail() (sdktypes.AuthResponse, error) {
	if c.email == "" || c.password == "" {
		return sdktypes.AuthResponse{}, errors.New("email authentication requires Email and Password")
	}
	resp, err := api.LoginWithEmail(c.HTTP, c.email, c.password)
	if err != nil {
		return resp, err
	}
	c.authenticated = true
	return resp, nil
}

func (c *BackupClient) RegisterEmail(email, password, displayName string) (sdktypes.EmailRegisterResponse, error) {
	return api.RegisterWithEmail(c.HTTP, email, password, displayName)
}

func (c *BackupClient) VerifyEmail(req sdktypes.EmailVerifyRequest) (sdktypes.EmailVerifyResponse, error) {
	resp, err := api.VerifyEmail(c.HTTP, req)
	if err != nil {
		return resp, err
	}
	if resp.Token != "" {
		c.authenticated = true
	}
	return resp, nil
}

func (c *BackupClient) LinkIdentity(req sdktypes.LinkIdentityRequest) (sdktypes.LinkIdentityResponse, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.LinkIdentityResponse{}, err
	}
	return c.HTTP.LinkIdentity(req)
}

// Backup backs up one or more paths into the configured workspace.
func (c *BackupClient) Backup(paths []string, options *sdktypes.BackupOptions) (*sdktypes.Snapshot, error) {
	if err := c.ensureAuth(); err != nil {
		return nil, err
	}
	http, err := c.httpForBackupOp(options)
	if err != nil {
		return nil, err
	}
	return pipeline.PerformBackup(http, paths, c.chunkOpts, options, c.concurrency)
}

// Restore downloads and reassembles a snapshot.
func (c *BackupClient) Restore(snapshotID, targetDir string, options *sdktypes.RestoreOptions) error {
	if err := c.ensureAuth(); err != nil {
		return err
	}
	http, err := c.httpForRestoreOp(options)
	if err != nil {
		return err
	}
	return pipeline.PerformRestore(http, snapshotID, targetDir, options, c.concurrency)
}

// ListSnapshots returns a paginated list of snapshots in the current workspace.
func (c *BackupClient) ListSnapshots(cursor string, limit int) (sdktypes.SnapshotListResponse, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.SnapshotListResponse{}, err
	}
	if err := c.ensureWorkspace(); err != nil {
		return sdktypes.SnapshotListResponse{}, err
	}
	return c.HTTP.ListSnapshots(cursor, limit)
}

// GetSnapshot returns details for a single snapshot.
func (c *BackupClient) GetSnapshot(snapshotID string) (sdktypes.Snapshot, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.Snapshot{}, err
	}
	if err := c.ensureWorkspace(); err != nil {
		return sdktypes.Snapshot{}, err
	}
	return c.HTTP.GetSnapshot(snapshotID)
}

// DeleteSnapshot removes a single snapshot.
func (c *BackupClient) DeleteSnapshot(snapshotID string) error {
	if err := c.ensureAuth(); err != nil {
		return err
	}
	if err := c.ensureWorkspace(); err != nil {
		return err
	}
	_, err := c.HTTP.DeleteSnapshot(snapshotID)
	return err
}

// PruneSnapshots deletes snapshots older than req.Before while retaining latest req.KeepLatest.
func (c *BackupClient) PruneSnapshots(req sdktypes.PruneRequest) (sdktypes.PruneResponse, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.PruneResponse{}, err
	}
	if err := c.ensureWorkspace(); err != nil {
		return sdktypes.PruneResponse{}, err
	}
	return c.HTTP.PruneSnapshots(req)
}

// GetUsage returns the current workspace's storage usage.
func (c *BackupClient) GetUsage() (sdktypes.Usage, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.Usage{}, err
	}
	if err := c.ensureWorkspace(); err != nil {
		return sdktypes.Usage{}, err
	}
	return c.HTTP.GetUsage()
}

// UpdateSnapshotEncryption atomically replaces wrappedDek during TMK rotation.
func (c *BackupClient) UpdateSnapshotEncryption(snapshotID string, body sdktypes.SnapshotEncryptionUpdate) (sdktypes.Snapshot, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.Snapshot{}, err
	}
	if err := c.ensureWorkspace(); err != nil {
		return sdktypes.Snapshot{}, err
	}
	return c.HTTP.UpdateSnapshotEncryption(snapshotID, body)
}

// RotateTMK rewraps the DEK of a snapshot from oldTMK to newTMK.
func (c *BackupClient) RotateTMK(snapshotID string, oldTMK, newTMK []byte) (sdktypes.Snapshot, bool, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.Snapshot{}, false, err
	}
	if err := c.ensureWorkspace(); err != nil {
		return sdktypes.Snapshot{}, false, err
	}
	return pipeline.RotateSnapshotTMK(c.HTTP, snapshotID, oldTMK, newTMK)
}

// CreateWorkspace creates a new workspace.
func (c *BackupClient) CreateWorkspace(req sdktypes.WorkspaceCreateRequest) (sdktypes.Workspace, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.Workspace{}, err
	}
	return c.HTTP.CreateWorkspace(req)
}

// ListWorkspaces returns workspaces accessible to the authenticated caller.
func (c *BackupClient) ListWorkspaces() (sdktypes.WorkspaceListResponse, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.WorkspaceListResponse{}, err
	}
	return c.HTTP.ListWorkspaces()
}

// GetWorkspace fetches a single workspace.
func (c *BackupClient) GetWorkspace(workspaceID string) (sdktypes.Workspace, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.Workspace{}, err
	}
	return c.HTTP.GetWorkspace(workspaceID)
}

// UpdateWorkspace patches a workspace's name/metadata.
func (c *BackupClient) UpdateWorkspace(workspaceID string, req sdktypes.WorkspaceUpdateRequest) (sdktypes.Workspace, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.Workspace{}, err
	}
	return c.HTTP.UpdateWorkspace(workspaceID, req)
}

// ListWorkspaceMembers returns members of a workspace.
func (c *BackupClient) ListWorkspaceMembers(workspaceID string) ([]sdktypes.WorkspaceMember, error) {
	if err := c.ensureAuth(); err != nil {
		return nil, err
	}
	return c.HTTP.ListWorkspaceMembers(workspaceID)
}

// AddWorkspaceMember invites a user to the workspace.
func (c *BackupClient) AddWorkspaceMember(workspaceID string, req sdktypes.WorkspaceMemberInvite) (sdktypes.WorkspaceMember, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.WorkspaceMember{}, err
	}
	return c.HTTP.AddWorkspaceMember(workspaceID, req)
}

// UpdateWorkspaceMember modifies an existing member's role/scopes.
func (c *BackupClient) UpdateWorkspaceMember(workspaceID, userID string, req sdktypes.WorkspaceMemberUpdate) (sdktypes.WorkspaceMember, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.WorkspaceMember{}, err
	}
	return c.HTTP.UpdateWorkspaceMember(workspaceID, userID, req)
}

// RemoveWorkspaceMember revokes a user's workspace membership.
func (c *BackupClient) RemoveWorkspaceMember(workspaceID, userID string) error {
	if err := c.ensureAuth(); err != nil {
		return err
	}
	return c.HTTP.RemoveWorkspaceMember(workspaceID, userID)
}

// GetProfile returns authenticated user's profile.
func (c *BackupClient) GetProfile() (sdktypes.UserProfile, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.UserProfile{}, err
	}
	return c.HTTP.GetProfile()
}

// ListIdentities returns authenticated user's identities.
func (c *BackupClient) ListIdentities() ([]sdktypes.AuthIdentity, error) {
	if err := c.ensureAuth(); err != nil {
		return nil, err
	}
	return c.HTTP.ListIdentities()
}

// CreateAPIKey provisions a new API key.
func (c *BackupClient) CreateAPIKey(req sdktypes.APIKeyCreateRequest) (sdktypes.APIKeyCreateResponse, error) {
	if err := c.ensureAuth(); err != nil {
		return sdktypes.APIKeyCreateResponse{}, err
	}
	return c.HTTP.CreateAPIKey(req)
}

// ListAPIKeys returns API key metadata.
func (c *BackupClient) ListAPIKeys() ([]sdktypes.APIKey, error) {
	if err := c.ensureAuth(); err != nil {
		return nil, err
	}
	return c.HTTP.ListAPIKeys()
}

// DeleteAPIKey revokes an API key by ID.
func (c *BackupClient) DeleteAPIKey(apiKeyID string) error {
	if err := c.ensureAuth(); err != nil {
		return err
	}
	return c.HTTP.DeleteAPIKey(apiKeyID)
}

// ensureAuth and ensureWorkspace are exported for root package wrapper plumbing.
func (c *BackupClient) EnsureAuth() error      { return c.ensureAuth() }
func (c *BackupClient) EnsureWorkspace() error { return c.ensureWorkspace() }
func (c *BackupClient) ChunkOptions() sdktypes.ChunkOptions {
	return c.chunkOpts
}
func (c *BackupClient) Concurrency() int { return c.concurrency }

func buildWallet(opts BackupClientOptions) (*api.WalletAdapter, error) {
	if opts.PrivateKey != "" {
		return api.WalletFromPrivateKey(opts.PrivateKey)
	}
	if opts.SignMessage != nil && opts.Address != "" {
		return api.WalletFromSigner(opts.Address, opts.SignMessage), nil
	}
	return nil, fmt.Errorf("provide either PrivateKey or both Address and SignMessage")
}

func (c *BackupClient) ensureAuth() error {
	if !c.authenticated {
		return errors.New("not authenticated — call Authenticate(), AuthenticateEmail(), or SetAPIKey/SetToken first")
	}
	return nil
}

func (c *BackupClient) ensureWorkspace() error {
	if c.HTTP.WorkspaceID() == "" {
		return api.ErrWorkspaceRequired
	}
	return nil
}

func (c *BackupClient) httpForBackupOp(opts *sdktypes.BackupOptions) (*api.HttpClient, error) {
	if opts != nil && opts.WorkspaceID != "" {
		return c.HTTP.WithWorkspace(opts.WorkspaceID), nil
	}
	if err := c.ensureWorkspace(); err != nil {
		return nil, err
	}
	return c.HTTP, nil
}

func (c *BackupClient) httpForRestoreOp(opts *sdktypes.RestoreOptions) (*api.HttpClient, error) {
	if opts != nil && opts.WorkspaceID != "" {
		return c.HTTP.WithWorkspace(opts.WorkspaceID), nil
	}
	if err := c.ensureWorkspace(); err != nil {
		return nil, err
	}
	return c.HTTP, nil
}
