package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	sdkerrors "github.com/lighthouse-web3/baas-go-sdk/errors"
	sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
)

// ErrWorkspaceRequired is returned when a workspace-scoped request is made
// without a configured workspace ID.
var ErrWorkspaceRequired = errors.New("workspace ID is required for this operation — call SetWorkspaceID or use WithWorkspace")

// HttpClient provides typed methods for every Lighthouse backup API endpoint.
type HttpClient struct {
	baseURL     string
	token       string
	workspaceID string
	httpClient  *http.Client
}

// NewHttpClient creates an HttpClient pointing at the given API base URL.
func NewHttpClient(baseURL string) *HttpClient {
	return &HttpClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Minute,
		},
	}
}

func (c *HttpClient) SetToken(token string) { c.token = token }
func (c *HttpClient) GetToken() string      { return c.token }
func (c *HttpClient) SetWorkspaceID(id string) {
	c.workspaceID = id
}
func (c *HttpClient) WorkspaceID() string { return c.workspaceID }

func (c *HttpClient) WithWorkspace(id string) *HttpClient {
	clone := *c
	clone.workspaceID = id
	return &clone
}

func (c *HttpClient) RequestNonce(walletAddress string) (sdktypes.NonceResponse, error) {
	var resp sdktypes.NonceResponse
	err := c.request("POST", "/auth/nonce", map[string]string{"walletAddress": walletAddress}, &resp)
	return resp, err
}

func (c *HttpClient) VerifySIWE(message, signature string) (sdktypes.AuthResponse, error) {
	var resp sdktypes.AuthResponse
	err := c.request("POST", "/auth/verify", map[string]string{"message": message, "signature": signature}, &resp)
	return resp, err
}

func (c *HttpClient) EmailRegister(req sdktypes.EmailRegisterRequest) (sdktypes.EmailRegisterResponse, error) {
	var resp sdktypes.EmailRegisterResponse
	err := c.request("POST", "/auth/email/register", req, &resp)
	return resp, err
}

func (c *HttpClient) EmailVerify(req sdktypes.EmailVerifyRequest) (sdktypes.EmailVerifyResponse, error) {
	var resp sdktypes.EmailVerifyResponse
	err := c.request("POST", "/auth/email/verify", req, &resp)
	return resp, err
}

func (c *HttpClient) EmailLogin(req sdktypes.EmailLoginRequest) (sdktypes.AuthResponse, error) {
	var resp sdktypes.AuthResponse
	err := c.request("POST", "/auth/email/login", req, &resp)
	return resp, err
}

func (c *HttpClient) LinkIdentity(req sdktypes.LinkIdentityRequest) (sdktypes.LinkIdentityResponse, error) {
	var resp sdktypes.LinkIdentityResponse
	err := c.request("POST", "/auth/link-identity", req, &resp)
	return resp, err
}

func (c *HttpClient) GetProfile() (sdktypes.UserProfile, error) {
	var resp sdktypes.UserProfile
	err := c.request("GET", "/user/profile", nil, &resp)
	return resp, err
}

func (c *HttpClient) ListIdentities() ([]sdktypes.AuthIdentity, error) {
	var resp sdktypes.IdentityListResponse
	err := c.request("GET", "/user/identities", nil, &resp)
	return resp.Identities, err
}

func (c *HttpClient) CreateAPIKey(req sdktypes.APIKeyCreateRequest) (sdktypes.APIKeyCreateResponse, error) {
	var resp sdktypes.APIKeyCreateResponse
	err := c.request("POST", "/user/api-keys", req, &resp)
	return resp, err
}

func (c *HttpClient) ListAPIKeys() ([]sdktypes.APIKey, error) {
	var resp sdktypes.APIKeyListResponse
	err := c.request("GET", "/user/api-keys", nil, &resp)
	return resp.APIKeys, err
}

func (c *HttpClient) DeleteAPIKey(apiKeyID string) error {
	return c.request("DELETE", "/user/api-keys/"+url.PathEscape(apiKeyID), nil, nil)
}

func (c *HttpClient) CreateWorkspace(req sdktypes.WorkspaceCreateRequest) (sdktypes.Workspace, error) {
	var resp sdktypes.Workspace
	err := c.request("POST", "/workspaces", req, &resp)
	return resp, err
}

func (c *HttpClient) ListWorkspaces() (sdktypes.WorkspaceListResponse, error) {
	var resp sdktypes.WorkspaceListResponse
	err := c.request("GET", "/workspaces", nil, &resp)
	return resp, err
}

func (c *HttpClient) GetWorkspace(workspaceID string) (sdktypes.Workspace, error) {
	var resp sdktypes.Workspace
	err := c.request("GET", "/workspaces/"+url.PathEscape(workspaceID), nil, &resp)
	return resp, err
}

func (c *HttpClient) UpdateWorkspace(workspaceID string, req sdktypes.WorkspaceUpdateRequest) (sdktypes.Workspace, error) {
	var resp sdktypes.Workspace
	err := c.request("PATCH", "/workspaces/"+url.PathEscape(workspaceID), req, &resp)
	return resp, err
}

func (c *HttpClient) ListWorkspaceMembers(workspaceID string) ([]sdktypes.WorkspaceMember, error) {
	var resp sdktypes.WorkspaceMemberListResponse
	err := c.request("GET", "/workspaces/"+url.PathEscape(workspaceID)+"/members", nil, &resp)
	return resp.Members, err
}

func (c *HttpClient) AddWorkspaceMember(workspaceID string, req sdktypes.WorkspaceMemberInvite) (sdktypes.WorkspaceMember, error) {
	var resp sdktypes.WorkspaceMember
	err := c.request("POST", "/workspaces/"+url.PathEscape(workspaceID)+"/members", req, &resp)
	return resp, err
}

func (c *HttpClient) UpdateWorkspaceMember(workspaceID, userID string, req sdktypes.WorkspaceMemberUpdate) (sdktypes.WorkspaceMember, error) {
	var resp sdktypes.WorkspaceMember
	path := "/workspaces/" + url.PathEscape(workspaceID) + "/members/" + url.PathEscape(userID)
	err := c.request("PATCH", path, req, &resp)
	return resp, err
}

func (c *HttpClient) RemoveWorkspaceMember(workspaceID, userID string) error {
	path := "/workspaces/" + url.PathEscape(workspaceID) + "/members/" + url.PathEscape(userID)
	return c.request("DELETE", path, nil, nil)
}

func (c *HttpClient) CheckChunks(hashes []string) (sdktypes.DedupResponse, error) {
	var resp sdktypes.DedupResponse
	err := c.workspaceRequest("POST", "/backup/chunks/check", map[string]any{"hashes": hashes}, &resp)
	return resp, err
}

func (c *HttpClient) RequestUploadURLs(chunks []sdktypes.ChunkSizeEntry) (sdktypes.UploadURLsResponse, error) {
	var resp sdktypes.UploadURLsResponse
	err := c.workspaceRequest("POST", "/backup/chunks/upload-urls", map[string]any{"chunks": chunks}, &resp)
	return resp, err
}

func (c *HttpClient) ConfirmChunks(chunks []sdktypes.ChunkMeta) (sdktypes.ConfirmResponse, error) {
	var resp sdktypes.ConfirmResponse
	err := c.workspaceRequest("POST", "/backup/chunks/confirm", map[string]any{"chunks": chunks}, &resp)
	return resp, err
}

func (c *HttpClient) GetBloomFilter() (sdktypes.BloomResponse, error) {
	var resp sdktypes.BloomResponse
	err := c.workspaceRequest("GET", "/backup/chunks/bloom", nil, &resp)
	return resp, err
}

func (c *HttpClient) RequestPackUploadURL(size int64) (sdktypes.PackUploadURLResponse, error) {
	var resp sdktypes.PackUploadURLResponse
	err := c.workspaceRequest("POST", "/backup/packs/upload-url", map[string]any{"size": size}, &resp)
	return resp, err
}

func (c *HttpClient) ConfirmPack(packID string, chunks []sdktypes.PackChunkMeta) (sdktypes.PackConfirmResponse, error) {
	var resp sdktypes.PackConfirmResponse
	err := c.workspaceRequest("POST", "/backup/packs/confirm", map[string]any{
		"packId": packID,
		"chunks": chunks,
	}, &resp)
	return resp, err
}

func (c *HttpClient) CreateSnapshot(input sdktypes.SnapshotInput) (sdktypes.Snapshot, error) {
	var resp sdktypes.Snapshot
	err := c.workspaceRequest("POST", "/backup/snapshots", input, &resp)
	return resp, err
}

func (c *HttpClient) ListSnapshots(cursor string, limit int) (sdktypes.SnapshotListResponse, error) {
	params := url.Values{}
	if cursor != "" {
		params.Set("cursor", cursor)
	}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	path := "/backup/snapshots"
	if qs := params.Encode(); qs != "" {
		path += "?" + qs
	}
	var resp sdktypes.SnapshotListResponse
	err := c.workspaceRequest("GET", path, nil, &resp)
	return resp, err
}

func (c *HttpClient) GetSnapshot(snapshotID string) (sdktypes.Snapshot, error) {
	var resp sdktypes.Snapshot
	err := c.workspaceRequest("GET", "/backup/snapshots/"+url.PathEscape(snapshotID), nil, &resp)
	return resp, err
}

func (c *HttpClient) DeleteSnapshot(snapshotID string) (sdktypes.DeleteSnapshotResponse, error) {
	var resp sdktypes.DeleteSnapshotResponse
	err := c.workspaceRequest("DELETE", "/backup/snapshots/"+url.PathEscape(snapshotID), nil, &resp)
	return resp, err
}

func (c *HttpClient) UpdateSnapshotEncryption(snapshotID string, body sdktypes.SnapshotEncryptionUpdate) (sdktypes.Snapshot, error) {
	var resp sdktypes.Snapshot
	err := c.workspaceRequest("PATCH", "/backup/snapshots/"+url.PathEscape(snapshotID), body, &resp)
	return resp, err
}

func (c *HttpClient) PruneSnapshots(req sdktypes.PruneRequest) (sdktypes.PruneResponse, error) {
	var resp sdktypes.PruneResponse
	err := c.workspaceRequest("POST", "/backup/snapshots/prune", req, &resp)
	return resp, err
}

func (c *HttpClient) RequestDownloadURLs(hashes []string) (sdktypes.PackDownloadResponse, error) {
	var resp sdktypes.PackDownloadResponse
	err := c.workspaceRequest("POST", "/restore/download-urls", map[string]any{"hashes": hashes}, &resp)
	return resp, err
}

func (c *HttpClient) GetSnapshotTree(snapshotID string) (sdktypes.SnapshotTreeResponse, error) {
	var resp sdktypes.SnapshotTreeResponse
	err := c.workspaceRequest("GET", "/restore/snapshots/"+url.PathEscape(snapshotID)+"/tree", nil, &resp)
	return resp, err
}

func (c *HttpClient) GetUsage() (sdktypes.Usage, error) {
	var resp sdktypes.Usage
	err := c.workspaceRequest("GET", "/usage", nil, &resp)
	return resp, err
}

// S3Put uploads data to a pre-signed S3 URL.
func S3Put(url string, data []byte) error {
	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(data))

	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("S3 PUT failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("S3 PUT %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// S3Get downloads data from a pre-signed S3 URL.
func S3Get(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("S3 GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("S3 GET %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (c *HttpClient) workspaceRequest(method, subPath string, body any, out any) error {
	if c.workspaceID == "" {
		return ErrWorkspaceRequired
	}
	full := "/workspaces/" + url.PathEscape(c.workspaceID) + subPath
	return c.request(method, full, body, out)
}

func (c *HttpClient) request(method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var parsed map[string]any
		_ = json.Unmarshal(respBody, &parsed)

		msg := resp.Status
		if m, ok := parsed["message"].(string); ok {
			msg = m
		} else if m, ok := parsed["error"].(string); ok {
			msg = m
		}
		return sdkerrors.NewApiError(msg, resp.StatusCode, parsed)
	}

	if out != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, out)
	}
	return nil
}
