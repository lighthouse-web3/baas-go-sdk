package backup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// HttpClient provides typed methods for every backup-service API endpoint.
type HttpClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewHttpClient creates an HttpClient pointing at the given API base URL.
func NewHttpClient(baseURL string) *HttpClient {
	return &HttpClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Minute,
		},
	}
}

func (c *HttpClient) SetToken(token string)  { c.token = token }
func (c *HttpClient) GetToken() string        { return c.token }

// ── Auth ────────────────────────────────────────────────────────────────────

func (c *HttpClient) RequestNonce(walletAddress string) (NonceResponse, error) {
	var resp NonceResponse
	err := c.request("POST", "/auth/nonce", map[string]string{"walletAddress": walletAddress}, &resp)
	return resp, err
}

func (c *HttpClient) Verify(message, signature string) (AuthResponse, error) {
	var resp AuthResponse
	err := c.request("POST", "/auth/verify", map[string]string{"message": message, "signature": signature}, &resp)
	return resp, err
}

// ── Chunks ──────────────────────────────────────────────────────────────────

func (c *HttpClient) CheckChunks(hashes []string) (DedupResponse, error) {
	var resp DedupResponse
	err := c.request("POST", "/backup/chunks/check", map[string]interface{}{"hashes": hashes}, &resp)
	return resp, err
}

func (c *HttpClient) RequestUploadURLs(chunks []ChunkSizeEntry) (UploadURLsResponse, error) {
	var resp UploadURLsResponse
	err := c.request("POST", "/backup/chunks/upload-urls", map[string]interface{}{"chunks": chunks}, &resp)
	return resp, err
}

func (c *HttpClient) ConfirmChunks(chunks []ChunkMeta) (ConfirmResponse, error) {
	var resp ConfirmResponse
	err := c.request("POST", "/backup/chunks/confirm", map[string]interface{}{"chunks": chunks}, &resp)
	return resp, err
}

// ── Bloom ───────────────────────────────────────────────────────────────────

func (c *HttpClient) GetBloomFilter() (BloomResponse, error) {
	var resp BloomResponse
	err := c.request("GET", "/backup/chunks/bloom", nil, &resp)
	return resp, err
}

// ── Packs ───────────────────────────────────────────────────────────────────

func (c *HttpClient) RequestPackUploadURL(size int64) (PackUploadURLResponse, error) {
	var resp PackUploadURLResponse
	err := c.request("POST", "/backup/packs/upload-url", map[string]interface{}{"size": size}, &resp)
	return resp, err
}

func (c *HttpClient) ConfirmPack(packID string, chunks []PackChunkMeta) (PackConfirmResponse, error) {
	var resp PackConfirmResponse
	err := c.request("POST", "/backup/packs/confirm", map[string]interface{}{
		"packId": packID,
		"chunks": chunks,
	}, &resp)
	return resp, err
}

// ── Snapshots ───────────────────────────────────────────────────────────────

func (c *HttpClient) CreateSnapshot(input SnapshotInput) (Snapshot, error) {
	var resp Snapshot
	err := c.request("POST", "/backup/snapshots", input, &resp)
	return resp, err
}

func (c *HttpClient) ListSnapshots(cursor string, limit int) (SnapshotListResponse, error) {
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
	var resp SnapshotListResponse
	err := c.request("GET", path, nil, &resp)
	return resp, err
}

func (c *HttpClient) GetSnapshot(snapshotID string) (Snapshot, error) {
	var resp Snapshot
	err := c.request("GET", "/backup/snapshots/"+snapshotID, nil, &resp)
	return resp, err
}

func (c *HttpClient) DeleteSnapshot(snapshotID string) (DeleteSnapshotResponse, error) {
	var resp DeleteSnapshotResponse
	err := c.request("DELETE", "/backup/snapshots/"+snapshotID, nil, &resp)
	return resp, err
}

// ── Restore ─────────────────────────────────────────────────────────────────

func (c *HttpClient) RequestDownloadURLs(hashes []string) (PackDownloadResponse, error) {
	var resp PackDownloadResponse
	err := c.request("POST", "/restore/download-urls", map[string]interface{}{"hashes": hashes}, &resp)
	return resp, err
}

func (c *HttpClient) GetSnapshotTree(snapshotID string) (SnapshotTreeResponse, error) {
	var resp SnapshotTreeResponse
	err := c.request("GET", "/restore/snapshots/"+snapshotID+"/tree", nil, &resp)
	return resp, err
}

// ── Retention ───────────────────────────────────────────────────────────────

func (c *HttpClient) PruneSnapshots(policy RetentionPolicy) (PruneResponse, error) {
	var resp PruneResponse
	err := c.request("POST", "/backup/snapshots/prune", policy, &resp)
	return resp, err
}

// ── Usage ───────────────────────────────────────────────────────────────────

func (c *HttpClient) GetUsage() (Usage, error) {
	var resp Usage
	err := c.request("GET", "/user/usage", nil, &resp)
	return resp, err
}

// ── ChunkSizeEntry is used for requesting upload URLs ───────────────────────

type ChunkSizeEntry struct {
	Hash string `json:"hash"`
	Size int    `json:"size"`
}

// ── S3 helpers (exported for use by backup/restore pipelines) ───────────────

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

// ── internal request helper ─────────────────────────────────────────────────

func (c *HttpClient) request(method, path string, body interface{}, out interface{}) error {
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

	req.Header.Set("Content-Type", "application/json")
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
		var errBody map[string]interface{}
		_ = json.Unmarshal(respBody, &errBody)

		msg := resp.Status
		if m, ok := errBody["message"].(string); ok {
			msg = m
		} else if m, ok := errBody["error"].(string); ok {
			msg = m
		}
		return NewApiError(msg, resp.StatusCode, errBody)
	}

	if out != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, out)
	}
	return nil
}
