package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// MaxDelegationTTL is the maximum allowed delegation certificate lifetime.
const MaxDelegationTTL = 24 * time.Hour

// DelegationResult holds the output of a successful delegation signing.
type DelegationResult struct {
	CertID    string
	Signature []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// delegationPayload is the canonical JSON structure signed by the CA.
// Fields are ordered alphabetically by key for deterministic serialization.
type delegationPayload struct {
	CertID    string `json:"cert_id"`
	BrokerID  string `json:"broker_id"`
	PublicKey string `json:"public_key"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// BuildCanonicalPayload constructs the deterministic JSON payload for delegation signing.
// Exported for testing.
func BuildCanonicalPayload(certID, brokerID string, brokerPubKey ed25519.PublicKey, issuedAt, expiresAt time.Time) ([]byte, error) {
	payload := delegationPayload{
		CertID:    certID,
		BrokerID:  brokerID,
		PublicKey: base64.StdEncoding.EncodeToString(brokerPubKey),
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}

	// Use json.Marshal for deterministic output (keys sorted by struct field order).
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("delegation: marshal payload: %w", err)
	}
	return data, nil
}

// GenerateCertID creates a unique delegation certificate identifier
// from 16 cryptographically random bytes, hex-encoded.
func GenerateCertID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("delegation: generate cert id: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// SignDelegation signs a delegation payload with the CA key.
// The broker sends its public key; the signer signs a canonical payload
// containing the broker's public key, broker ID, issued_at, and expires_at.
// Extracted for testability -- called by handleConn in production.
func SignDelegation(ca *CA, brokerPubKey ed25519.PublicKey, brokerID string, ttl time.Duration) (*DelegationResult, error) {
	// Validate TTL.
	if ttl <= 0 {
		return nil, fmt.Errorf("delegation: ttl must be positive")
	}
	if ttl > MaxDelegationTTL {
		return nil, fmt.Errorf("delegation: ttl %v exceeds maximum of %v", ttl, MaxDelegationTTL)
	}

	// Validate broker public key length.
	if len(brokerPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("delegation: broker public key must be %d bytes, got %d", ed25519.PublicKeySize, len(brokerPubKey))
	}

	// Validate broker ID.
	if brokerID == "" {
		return nil, fmt.Errorf("delegation: broker_id is required")
	}

	// Generate unique cert ID.
	certID, err := GenerateCertID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	// Build the canonical payload.
	payload, err := BuildCanonicalPayload(certID, brokerID, brokerPubKey, now, expiresAt)
	if err != nil {
		return nil, err
	}

	// Sign with the CA's raw Ed25519 private key (not the SSH signer).
	signature := ed25519.Sign(ca.RawPrivateKey(), payload)

	return &DelegationResult{
		CertID:    certID,
		Signature: signature,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	}, nil
}

// VerifyDelegation verifies a delegation signature against the signer's public key.
// Used by the broker to validate delegation certificates.
func VerifyDelegation(rootPubKey ed25519.PublicKey, certID, brokerID string, brokerPubKey ed25519.PublicKey, issuedAt, expiresAt time.Time, signature []byte) bool {
	payload, err := BuildCanonicalPayload(certID, brokerID, brokerPubKey, issuedAt, expiresAt)
	if err != nil {
		return false
	}
	return ed25519.Verify(rootPubKey, payload, signature)
}
