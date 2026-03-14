package macaroon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// VerifyResult is the output of successful macaroon verification.
type VerifyResult struct {
	Envelope  EffectiveEnvelope
	Metadata  TokenMetadata
	SigDigest string // SHA-256 hex of macaroon signature, for task lookup
}

// Verifier validates macaroon tokens against root keys and reduces caveats.
type Verifier struct {
	keyStore *RootKeyStore
}

// NewVerifier creates a new Verifier backed by the given RootKeyStore.
func NewVerifier(keyStore *RootKeyStore) *Verifier {
	return &Verifier{
		keyStore: keyStore,
	}
}

// Verify validates a macaroon: HMAC chain + caveat reduction + expiry check.
// Returns the effective envelope and signature digest for task lookup.
func (v *Verifier) Verify(mac *Macaroon) (*VerifyResult, error) {
	// 1. Extract root task ID from mac.Id().
	rootTaskID := string(mac.Id())

	// 2. Look up root key in keyStore.
	key, ok := v.keyStore.Get(rootTaskID)
	if !ok {
		return nil, fmt.Errorf("verifier: unknown root task %q: %w", rootTaskID, ErrInvalidSignature)
	}

	// 3. Validate HMAC chain, get caveats as strings.
	caveats, err := mac.Verify(key[:])
	if err != nil {
		return nil, fmt.Errorf("verifier: %w", err)
	}

	// 4. Reduce caveats to effective envelope + metadata.
	reduced, err := Reduce(caveats)
	if err != nil {
		return nil, fmt.Errorf("verifier: caveat reduction failed: %w", err)
	}

	// 5. Check expiry.
	if !reduced.Envelope.ExpiresAt.IsZero() && time.Now().After(reduced.Envelope.ExpiresAt) {
		return nil, ErrExpired
	}

	// 6. Compute signature digest: SHA-256 of the macaroon signature bytes.
	sig := mac.Signature()
	hash := sha256.Sum256(sig[:])
	sigDigest := hex.EncodeToString(hash[:])

	// 7. Return result.
	return &VerifyResult{
		Envelope:  reduced.Envelope,
		Metadata:  reduced.Metadata,
		SigDigest: sigDigest,
	}, nil
}
