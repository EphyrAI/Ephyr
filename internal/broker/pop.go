package broker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ProofPayload is the canonical structure signed by the holder's private key.
// The JSON field order is fixed to ensure deterministic serialization.
type ProofPayload struct {
	TaskID    string `json:"task_id"`
	ReqType   string `json:"req_type"`   // ssh_exec, http_proxy, mcp_federation, delegate, bind
	Resource  string `json:"resource"`   // target name, service name, remote name
	Method    string `json:"method"`     // role, HTTP method, tool name
	BodyHash  string `json:"body_hash"`  // SHA-256 hex of canonical request body
	MacDigest string `json:"mac_digest"` // SHA-256 hex of serialized macaroon
	Nonce     string `json:"nonce"`      // 16 bytes hex, unique per request
	Ts        string `json:"ts"`         // RFC 3339 timestamp
}

// PopProof is the proof-of-possession included in MCP requests.
type PopProof struct {
	Sig     string       `json:"sig"`     // base64url Ed25519 signature
	Payload ProofPayload `json:"payload"`
}

// NonceCache prevents replay of proof-of-possession nonces.
// It stores "taskID:nonce" entries with expiry times and removes
// them periodically via the Cleanup method.
type NonceCache struct {
	mu      sync.RWMutex
	entries map[string]time.Time // "taskID:nonce" -> first-seen
	ttl     time.Duration
}

// NewNonceCache creates a NonceCache with the given TTL for nonce entries.
func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// CheckAndStore returns an error if the nonce was already seen for the given
// task ID. Otherwise it stores the nonce with the current timestamp.
func (nc *NonceCache) CheckAndStore(taskID, nonce string) error {
	key := taskID + ":" + nonce

	nc.mu.Lock()
	defer nc.mu.Unlock()

	if _, exists := nc.entries[key]; exists {
		return fmt.Errorf("nonce already used")
	}
	nc.entries[key] = time.Now()
	return nil
}

// Cleanup removes nonce entries that are older than the TTL.
// Call periodically to prevent unbounded growth.
func (nc *NonceCache) Cleanup() {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	cutoff := time.Now().Add(-nc.ttl)
	for key, ts := range nc.entries {
		if ts.Before(cutoff) {
			delete(nc.entries, key)
		}
	}
}

// Count returns the number of cached nonce entries.
func (nc *NonceCache) Count() int {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return len(nc.entries)
}

// canonicalizePayload serializes a ProofPayload to canonical JSON bytes.
// Go's json.Marshal produces sorted keys for structs (in field declaration
// order), which gives us deterministic output.
func canonicalizePayload(p *ProofPayload) ([]byte, error) {
	return json.Marshal(p)
}

// VerifyPoP verifies a proof-of-possession against a holder's public key.
// It checks:
//  1. Signature validity (Ed25519 over canonical JSON payload)
//  2. mac_digest matches SHA-256(macBinary)
//  3. body_hash matches SHA-256(requestBody)
//  4. Nonce uniqueness via NonceCache
//  5. Timestamp within +/- clockSkew of time.Now()
//
// Returns nil on success, a descriptive error on failure.
func VerifyPoP(proof *PopProof, holderPubKey []byte, macBinary []byte, requestBody []byte, clockSkew time.Duration, nonceCache *NonceCache) error {
	if proof == nil {
		return fmt.Errorf("pop: proof is nil")
	}
	if len(holderPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("pop: invalid holder public key: expected %d bytes, got %d", ed25519.PublicKeySize, len(holderPubKey))
	}

	// 1. Canonicalize the proof payload and verify signature.
	canonical, err := canonicalizePayload(&proof.Payload)
	if err != nil {
		return fmt.Errorf("pop: failed to canonicalize payload: %w", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(proof.Sig)
	if err != nil {
		return fmt.Errorf("pop: invalid signature encoding: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("pop: invalid signature length: expected %d bytes, got %d", ed25519.SignatureSize, len(sigBytes))
	}

	if !ed25519.Verify(ed25519.PublicKey(holderPubKey), canonical, sigBytes) {
		return fmt.Errorf("pop: signature verification failed")
	}

	// 2. Verify mac_digest matches SHA-256 of the serialized macaroon.
	macHash := sha256.Sum256(macBinary)
	expectedMacDigest := hex.EncodeToString(macHash[:])
	if proof.Payload.MacDigest != expectedMacDigest {
		return fmt.Errorf("pop: mac_digest mismatch: proof does not match presented macaroon")
	}

	// 3. Verify body_hash matches SHA-256 of the request body.
	bodyHash := sha256.Sum256(requestBody)
	expectedBodyHash := hex.EncodeToString(bodyHash[:])
	if proof.Payload.BodyHash != expectedBodyHash {
		return fmt.Errorf("pop: body_hash mismatch: request body has been tampered with")
	}

	// 4. Check nonce uniqueness.
	if nonceCache != nil {
		if err := nonceCache.CheckAndStore(proof.Payload.TaskID, proof.Payload.Nonce); err != nil {
			return fmt.Errorf("pop: replay detected: %w", err)
		}
	}

	// 5. Parse timestamp and check within clock skew window.
	ts, err := time.Parse(time.RFC3339, proof.Payload.Ts)
	if err != nil {
		return fmt.Errorf("pop: invalid timestamp: %w", err)
	}
	now := time.Now()
	if ts.Before(now.Add(-clockSkew)) {
		return fmt.Errorf("pop: timestamp too old (skew %s)", clockSkew)
	}
	if ts.After(now.Add(clockSkew)) {
		return fmt.Errorf("pop: timestamp too far in future (skew %s)", clockSkew)
	}

	return nil
}
