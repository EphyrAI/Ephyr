package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// DefaultTimeout is the default IPC request timeout.
const DefaultTimeout = 10 * time.Second

// SignRequest is the JSON request sent over the Unix socket to the signer.
type SignRequest struct {
	Action       string   `json:"action"`                    // "sign", "ping", "sign_delegation", or "root_public_key"
	PublicKey    string   `json:"public_key,omitempty"`       // authorized_key format (for "sign")
	Principals   []string `json:"principals,omitempty"`
	Duration     string   `json:"duration,omitempty"`         // Go duration string (e.g. "1h")
	KeyID        string   `json:"key_id,omitempty"`           // e.g. "agent-foo@target-host"
	ForceCommand string   `json:"force_command,omitempty"`

	// Delegation fields (used when Action is "sign_delegation").
	BrokerPublicKey string `json:"broker_public_key,omitempty"` // base64 Ed25519 public key (32 bytes)
	BrokerID        string `json:"broker_id,omitempty"`          // broker instance identifier
	DelegationTTL   string `json:"delegation_ttl,omitempty"`     // Go duration for cert validity
}

// SignResponse is the JSON response returned by the signer.
type SignResponse struct {
	Certificate string `json:"certificate,omitempty"` // base64-encoded certificate
	Serial      string `json:"serial,omitempty"`      // hex serial number
	ExpiresAt   string `json:"expires_at,omitempty"`  // RFC3339 timestamp
	Status      string `json:"status,omitempty"`      // "ok" for ping responses
	Error       string `json:"error,omitempty"`       // non-empty on failure

	// Delegation response fields.
	DelegationCertID string `json:"delegation_cert_id,omitempty"` // unique cert identifier
	DelegationSig    string `json:"delegation_sig,omitempty"`     // base64 Ed25519 signature over canonical payload
	RootPublicKey    string `json:"root_public_key,omitempty"`    // base64 signer's Ed25519 public key (for pinning)
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

// RequestDelegation sends a delegation signing request.
// The broker sends its public key; the signer signs a canonical payload
// containing the broker's public key, broker ID, issued_at, and expires_at.
// The returned signature and cert ID can be used by the broker to construct
// a DelegationCert.
func (c *Client) RequestDelegation(brokerPubKey ed25519.PublicKey, brokerID string, ttl time.Duration) (*SignResponse, error) {
	req := SignRequest{
		Action:          "sign_delegation",
		BrokerPublicKey: base64.StdEncoding.EncodeToString(brokerPubKey),
		BrokerID:        brokerID,
		DelegationTTL:   ttl.String(),
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("signer: sign_delegation: %s", resp.Error)
	}
	return resp, nil
}

// RootPublicKey requests the signer's root Ed25519 public key.
// Used at broker startup to pin the root key for token validation.
func (c *Client) RootPublicKey() (ed25519.PublicKey, error) {
	resp, err := c.do(SignRequest{Action: "root_public_key"})
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("signer: root_public_key: %s", resp.Error)
	}
	if resp.RootPublicKey == "" {
		return nil, fmt.Errorf("signer: root_public_key: empty response")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(resp.RootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("signer: root_public_key: decode base64: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer: root_public_key: invalid key size %d, want %d", len(keyBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(keyBytes), nil
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
