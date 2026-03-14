package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// BrokerClient communicates with the ephyr broker over a Unix socket.
type BrokerClient struct {
	httpClient *http.Client
	socketPath string
	configDir  string
	token      string
}

// RequestPayload is sent to POST /v1/request.
type RequestPayload struct {
	Target    string `json:"target"`
	Role      string `json:"role"`
	Duration  string `json:"duration,omitempty"`
	PublicKey string `json:"public_key"`
}

// RequestResponse is returned by POST /v1/request.
type RequestResponse struct {
	Status      string `json:"status"`       // "approved", "pending", "denied"
	Certificate string `json:"certificate"`  // base64 cert (only if approved)
	Serial      string `json:"serial"`
	ExpiresAt   string `json:"expires_at"`
	Principal   string `json:"principal"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Reason      string `json:"reason,omitempty"` // denial/pending reason
	RequestID   string `json:"request_id,omitempty"`
}

// CertInfo describes an active certificate.
type CertInfo struct {
	Serial    string `json:"serial"`
	Target    string `json:"target"`
	Role      string `json:"role"`
	Principal string `json:"principal"`
	ExpiresAt string `json:"expires_at"`
	IssuedAt  string `json:"issued_at"`
}

// TargetInfo describes an available target.
type TargetInfo struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	VLAN         int      `json:"vlan"`
	AllowedRoles []string `json:"allowed_roles"`
	AutoApprove  bool     `json:"auto_approve"`
	Description  string   `json:"description,omitempty"`
}

// SessionInfo describes the current agent session.
type SessionInfo struct {
	Token     string `json:"token"`
	AgentName string `json:"agent_name"`
	UID       uint32 `json:"uid"`
	CreatedAt string `json:"created_at"`
	LastSeen  string `json:"last_seen"`
}

// SessionCreateResponse is returned by POST /v1/session.
type SessionCreateResponse struct {
	Token     string `json:"token"`
	AgentName string `json:"agent_name"`
}

// ErrorResponse represents an API error.
type ErrorResponse struct {
	Error string `json:"error"`
}

// NewBrokerClient creates a new client that connects to the broker Unix socket.
func NewBrokerClient(socketPath, configDir string) *BrokerClient {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	client := &BrokerClient{
		httpClient: &http.Client{Transport: transport},
		socketPath: socketPath,
		configDir:  configDir,
	}

	// Try to load an existing session token.
	client.token = client.loadToken()

	return client
}

// EnsureSession ensures a session token exists, creating one if needed.
func (c *BrokerClient) EnsureSession() error {
	if c.token != "" {
		return nil
	}
	token, err := c.CreateSession()
	if err != nil {
		return err
	}
	c.token = token
	return nil
}

// CreateSession creates a new session with the broker and stores the token.
func (c *BrokerClient) CreateSession() (string, error) {
	resp, err := c.doRequest("POST", "/v1/session", nil)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", readError(resp)
	}

	var result SessionCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("create session: decode response: %w", err)
	}

	// Save token to disk.
	if err := c.saveToken(result.Token); err != nil {
		return "", fmt.Errorf("create session: save token: %w", err)
	}

	return result.Token, nil
}

// Request sends a certificate request to the broker.
func (c *BrokerClient) Request(target, role, duration string) (*RequestResponse, error) {
	if err := c.EnsureSession(); err != nil {
		return nil, err
	}

	pubKey, err := readPublicKey(c.configDir)
	if err != nil {
		return nil, err
	}

	payload := RequestPayload{
		Target:    target,
		Role:      role,
		Duration:  duration,
		PublicKey: strings.TrimSpace(pubKey),
	}

	body, err := jsonMarshal(payload)
	if err != nil {
		return nil, fmt.Errorf("request: marshal: %w", err)
	}

	resp, err := c.doRequest("POST", "/v1/request", strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated &&
		resp.StatusCode != http.StatusAccepted {
		return nil, readError(resp)
	}

	var result RequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("request: decode response: %w", err)
	}

	return &result, nil
}

// PollRequest polls for a pending request approval.
func (c *BrokerClient) PollRequest(requestID string) (*RequestResponse, error) {
	if err := c.EnsureSession(); err != nil {
		return nil, err
	}

	resp, err := c.doRequest("GET", "/v1/request/"+requestID, nil)
	if err != nil {
		return nil, fmt.Errorf("poll request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var result RequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("poll request: decode response: %w", err)
	}

	return &result, nil
}

// ListCerts returns the agent's active certificates.
func (c *BrokerClient) ListCerts() ([]CertInfo, error) {
	if err := c.EnsureSession(); err != nil {
		return nil, err
	}

	resp, err := c.doRequest("GET", "/v1/certs", nil)
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var result []CertInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("list certs: decode response: %w", err)
	}

	return result, nil
}

// ListTargets returns all targets and their allowed roles.
func (c *BrokerClient) ListTargets() ([]TargetInfo, error) {
	if err := c.EnsureSession(); err != nil {
		return nil, err
	}

	resp, err := c.doRequest("GET", "/v1/targets", nil)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var result []TargetInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("list targets: decode response: %w", err)
	}

	return result, nil
}

// Whoami returns the current session information.
func (c *BrokerClient) Whoami() (*SessionInfo, error) {
	if err := c.EnsureSession(); err != nil {
		return nil, err
	}

	resp, err := c.doRequest("GET", "/v1/session", nil)
	if err != nil {
		return nil, fmt.Errorf("whoami: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var result SessionInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("whoami: decode response: %w", err)
	}

	return &result, nil
}

// doRequest performs an HTTP request through the Unix socket.
// On a 401 response it automatically clears the stale session token,
// creates a fresh session, and retries the request once.
func (c *BrokerClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	// Buffer body so we can replay it on retry.
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}

	resp, err := c.doRequestOnce(method, path, bodyBytes)
	if err != nil {
		return nil, err
	}

	// Auto-retry on 401: the cached session token is stale (broker restarted, etc).
	// Skip retry for /v1/session itself to avoid infinite loops.
	if resp.StatusCode == http.StatusUnauthorized && c.token != "" && path != "/v1/session" {
		resp.Body.Close()
		c.token = ""
		c.deleteToken()

		token, err := c.CreateSession()
		if err != nil {
			return nil, fmt.Errorf("session expired, re-auth failed: %w", err)
		}
		c.token = token

		return c.doRequestOnce(method, path, bodyBytes)
	}

	return resp, nil
}

// doRequestOnce sends a single HTTP request (no retry).
func (c *BrokerClient) doRequestOnce(method, path string, bodyBytes []byte) (*http.Response, error) {
	url := "http://ephyr-broker" + path

	var body io.Reader
	if bodyBytes != nil {
		body = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.token != "" {
		req.Header.Set("X-Session-Token", c.token)
	}

	return c.httpClient.Do(req)
}

// deleteToken removes the cached session token from disk.
func (c *BrokerClient) deleteToken() {
	tokenPath := filepath.Join(c.configDir, "session_token")
	os.Remove(tokenPath)
}

// loadToken reads the session token from disk.
func (c *BrokerClient) loadToken() string {
	tokenPath := filepath.Join(c.configDir, "session_token")
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveToken writes the session token to disk.
func (c *BrokerClient) saveToken(token string) error {
	if err := os.MkdirAll(c.configDir, 0700); err != nil {
		return err
	}
	tokenPath := filepath.Join(c.configDir, "session_token")
	return os.WriteFile(tokenPath, []byte(token+"\n"), 0600)
}

// readError extracts an error message from an HTTP response.
func readError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	var errResp ErrorResponse
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		return fmt.Errorf("broker: %s (HTTP %d)", errResp.Error, resp.StatusCode)
	}

	text := strings.TrimSpace(string(body))
	if text == "" {
		text = resp.Status
	}
	return fmt.Errorf("broker: %s (HTTP %d)", text, resp.StatusCode)
}

// jsonMarshal encodes a value to a JSON string.
func jsonMarshal(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
