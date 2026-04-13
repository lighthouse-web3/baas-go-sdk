package backup

import (
	"errors"
	"fmt"
)

// BackupClientOptions configures the high-level BackupClient.
type BackupClientOptions struct {
	// Base URL of the backup service API (e.g. "http://localhost:3000").
	APIURL string
	// Ethereum private key (hex, with or without 0x prefix).
	PrivateKey string
	// Custom sign function — use when the private key lives in an external wallet.
	SignMessage func(message string) (string, error)
	// Required when using SignMessage instead of PrivateKey.
	Address string
	// Override default CDC chunk sizes.
	ChunkOptions *ChunkOptions
	// Max parallel S3 uploads/downloads (default 8).
	Concurrency int
}

// BackupClient is the high-level SDK client. It wraps the HTTP client,
// authentication, backup, and restore into a single cohesive API.
type BackupClient struct {
	HTTP          *HttpClient
	address       string
	wallet        *WalletAdapter
	chunkOpts     ChunkOptions
	concurrency   int
	authenticated bool
}

// NewBackupClient creates a BackupClient from the given options.
func NewBackupClient(opts BackupClientOptions) (*BackupClient, error) {
	if opts.APIURL == "" {
		return nil, errors.New("APIURL is required")
	}

	wallet, err := buildWallet(opts)
	if err != nil {
		return nil, err
	}

	chunkOpts := DefaultChunkOptions
	if opts.ChunkOptions != nil {
		chunkOpts = *opts.ChunkOptions
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}

	return &BackupClient{
		HTTP:        NewHttpClient(opts.APIURL),
		address:     wallet.Address,
		wallet:      wallet,
		chunkOpts:   chunkOpts,
		concurrency: concurrency,
	}, nil
}

// Address returns the Ethereum address associated with this client.
func (c *BackupClient) Address() string {
	return c.address
}

// Authenticate performs the full SIWE authentication flow.
// Must be called before other operations.
func (c *BackupClient) Authenticate() (string, error) {
	token, err := Authenticate(c.HTTP, c.wallet)
	if err != nil {
		return "", err
	}
	c.authenticated = true
	return token, nil
}

// SetToken uses an existing JWT instead of the full SIWE flow.
func (c *BackupClient) SetToken(token string) {
	c.HTTP.SetToken(token)
	c.authenticated = true
}

// Backup backs up one or more paths (files or directories).
// Full pipeline: scan → chunk → dedup → upload → tree → snapshot.
func (c *BackupClient) Backup(paths []string, options *BackupOptions) (*Snapshot, error) {
	if err := c.ensureAuth(); err != nil {
		return nil, err
	}
	return PerformBackup(c.HTTP, paths, c.chunkOpts, options, c.concurrency)
}

// Restore downloads and reassembles a snapshot to the given directory.
func (c *BackupClient) Restore(snapshotID, targetDir string, options *RestoreOptions) error {
	if err := c.ensureAuth(); err != nil {
		return err
	}
	return PerformRestore(c.HTTP, snapshotID, targetDir, options, c.concurrency)
}

// ListSnapshots returns a paginated list of snapshots.
func (c *BackupClient) ListSnapshots(cursor string, limit int) (SnapshotListResponse, error) {
	if err := c.ensureAuth(); err != nil {
		return SnapshotListResponse{}, err
	}
	return c.HTTP.ListSnapshots(cursor, limit)
}

// GetSnapshot returns details for a single snapshot.
func (c *BackupClient) GetSnapshot(snapshotID string) (Snapshot, error) {
	if err := c.ensureAuth(); err != nil {
		return Snapshot{}, err
	}
	return c.HTTP.GetSnapshot(snapshotID)
}

// DeleteSnapshot removes a single snapshot.
func (c *BackupClient) DeleteSnapshot(snapshotID string) error {
	if err := c.ensureAuth(); err != nil {
		return err
	}
	_, err := c.HTTP.DeleteSnapshot(snapshotID)
	return err
}

// PruneSnapshots applies a retention policy and garbage-collects orphaned data.
func (c *BackupClient) PruneSnapshots(policy RetentionPolicy) (PruneResponse, error) {
	if err := c.ensureAuth(); err != nil {
		return PruneResponse{}, err
	}
	return c.HTTP.PruneSnapshots(policy)
}

// GetUsage returns current storage quota information.
func (c *BackupClient) GetUsage() (Usage, error) {
	if err := c.ensureAuth(); err != nil {
		return Usage{}, err
	}
	return c.HTTP.GetUsage()
}

// UpdateSnapshotEncryption atomically replaces the wrappedDek during TMK rotation.
func (c *BackupClient) UpdateSnapshotEncryption(snapshotID string, body SnapshotEncryptionUpdate) (Snapshot, error) {
	if err := c.ensureAuth(); err != nil {
		return Snapshot{}, err
	}
	return c.HTTP.UpdateSnapshotEncryption(snapshotID, body)
}

// RotateTMK rewraps the DEK of a single snapshot from oldTMK to newTMK
func (c *BackupClient) RotateTMK(snapshotID string, oldTMK, newTMK []byte) (Snapshot, bool, error) {
	if err := c.ensureAuth(); err != nil {
		return Snapshot{}, false, err
	}
	return RotateSnapshotTMK(c.HTTP, snapshotID, oldTMK, newTMK)
}

// ── internal ────────────────────────────────────────────────────────────────

func buildWallet(opts BackupClientOptions) (*WalletAdapter, error) {
	if opts.PrivateKey != "" {
		return WalletFromPrivateKey(opts.PrivateKey)
	}
	if opts.SignMessage != nil && opts.Address != "" {
		return WalletFromSigner(opts.Address, opts.SignMessage), nil
	}
	return nil, fmt.Errorf("provide either PrivateKey or both Address and SignMessage")
}

func (c *BackupClient) ensureAuth() error {
	if !c.authenticated {
		return errors.New("not authenticated — call Authenticate() first")
	}
	return nil
}
