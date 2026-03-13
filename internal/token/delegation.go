package token

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// DelegationPayload is what gets signed by the signer to create a DelegationCert.
type DelegationPayload struct {
	CertID    string `json:"cert_id"`
	BrokerID  string `json:"broker_id"`
	PublicKey []byte `json:"public_key"` // Ed25519 public key bytes
	IssuedAt  int64  `json:"issued_at"`  // Unix timestamp
	ExpiresAt int64  `json:"expires_at"` // Unix timestamp
}

// CreateDelegationPayload builds the canonical byte representation
// that the signer signs. Uses deterministic JSON marshaling with sorted keys.
func CreateDelegationPayload(p DelegationPayload) ([]byte, error) {
	// Marshal to map for deterministic key ordering.
	m := map[string]interface{}{
		"broker_id":  p.BrokerID,
		"cert_id":    p.CertID,
		"expires_at": p.ExpiresAt,
		"issued_at":  p.IssuedAt,
		"public_key": p.PublicKey,
	}

	// Sort keys for deterministic output.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build deterministic JSON manually to ensure consistent output.
	// json.Marshal already sorts map keys in Go 1.12+, but we do it
	// explicitly for clarity and safety.
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("token: failed to marshal delegation payload: %w", err)
	}

	return data, nil
}

// VerifyDelegationCert verifies a delegation cert's signature
// against the root CA public key.
func VerifyDelegationCert(cert *DelegationCert, payload *DelegationPayload, rootPubKey ed25519.PublicKey) error {
	if cert == nil {
		return errors.New("token: delegation cert is nil")
	}
	if payload == nil {
		return errors.New("token: delegation payload is nil")
	}
	if rootPubKey == nil {
		return errors.New("token: root public key is nil")
	}

	// Verify timestamps match.
	if cert.ID != payload.CertID {
		return errors.New("token: cert ID mismatch")
	}
	if cert.BrokerID != payload.BrokerID {
		return errors.New("token: broker ID mismatch")
	}

	// Rebuild canonical payload bytes.
	canonical, err := CreateDelegationPayload(*payload)
	if err != nil {
		return fmt.Errorf("token: failed to build canonical payload: %w", err)
	}

	// Verify signature.
	if !ed25519.Verify(rootPubKey, canonical, cert.Signature) {
		return errors.New("token: delegation cert signature invalid")
	}

	// Verify expiration.
	if time.Now().After(cert.ExpiresAt) {
		return errors.New("token: delegation cert expired")
	}

	return nil
}

// SignDelegationCert creates a delegation cert by signing the payload with the root private key.
// This is a helper primarily for testing; in production the signer process does this.
func SignDelegationCert(payload *DelegationPayload, rootPrivKey ed25519.PrivateKey) (*DelegationCert, error) {
	if payload == nil {
		return nil, errors.New("token: delegation payload is nil")
	}

	canonical, err := CreateDelegationPayload(*payload)
	if err != nil {
		return nil, fmt.Errorf("token: failed to build canonical payload: %w", err)
	}

	sig := ed25519.Sign(rootPrivKey, canonical)

	return &DelegationCert{
		ID:        payload.CertID,
		BrokerID:  payload.BrokerID,
		PublicKey: ed25519.PublicKey(payload.PublicKey),
		Signature: sig,
		IssuedAt:  time.Unix(payload.IssuedAt, 0),
		ExpiresAt: time.Unix(payload.ExpiresAt, 0),
	}, nil
}
