package signer

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// DefaultTimeout is the default IPC request timeout.
const DefaultTimeout = 10 * time.Second

// SignRequest is the JSON request sent over the Unix socket to the signer.
type SignRequest struct {
	Action       string   `json:"action"`                  // "sign" or "ping"
	PublicKey    string   `json:"public_key,omitempty"`     // authorized_key format
	Principals   []string `json:"principals,omitempty"`
	Duration     string   `json:"duration,omitempty"`       // Go duration string (e.g. "1h")
	KeyID        string   `json:"key_id,omitempty"`         // e.g. "agent-foo@target-host"
	ForceCommand string   `json:"force_command,omitempty"`
}

// SignResponse is the JSON response returned by the signer.
type SignResponse struct {
	Certificate string `json:"certificate,omitempty"` // base64-encoded certificate
	Serial      string `json:"serial,omitempty"`      // hex serial number
	ExpiresAt   string `json:"expires_at,omitempty"`  // RFC3339 timestamp
	Status      string `json:"status,omitempty"`      // "ok" for ping responses
	Error       string `json:"error,omitempty"`       // non-empty on failure
}

// Client is an IPC client that communicates with the signer subprocess
// over a Unix domain socket.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// NewClient creates a new IPC client for the given Unix socket path.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		timeout:    DefaultTimeout,
	}
}

// SetTimeout overrides the default request timeout.
func (c *Client) SetTimeout(d time.Duration) {
	c.timeout = d
}

// Ping sends a health check to the signer and returns nil if healthy.
func (c *Client) Ping() error {
	resp, err := c.do(SignRequest{Action: "ping"})
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("signer: ping: %s", resp.Error)
	}
	if resp.Status != "ok" {
		return fmt.Errorf("signer: ping: unexpected status %q", resp.Status)
	}
	return nil
}

// RequestSign sends a signing request and returns the response.
func (c *Client) RequestSign(req SignRequest) (*SignResponse, error) {
	req.Action = "sign"
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("signer: sign: %s", resp.Error)
	}
	return resp, nil
}

// do connects to the Unix socket, sends the request, and reads the response.
func (c *Client) do(req SignRequest) (*SignResponse, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("signer ipc: dial %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	// Set read/write deadline based on timeout.
	deadline := time.Now().Add(c.timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("signer ipc: set deadline: %w", err)
	}

	// Encode and send the request.
	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return nil, fmt.Errorf("signer ipc: encode request: %w", err)
	}

	// Read and decode the response.
	var resp SignResponse
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("signer ipc: decode response: %w", err)
	}

	return &resp, nil
}
