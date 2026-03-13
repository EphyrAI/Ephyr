package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Validator verifies CTT tokens against the trust chain.
type Validator struct {
	rootPublicKey ed25519.PublicKey // pinned signer root public key
	delegations   sync.Map         // kid -> *DelegationCert (cached)
}

// NewValidator creates a new token validator pinned to the given root public key.
func NewValidator(rootPubKey ed25519.PublicKey) *Validator {
	return &Validator{
		rootPublicKey: rootPubKey,
	}
}

// AddDelegation registers a delegation cert for validation.
func (v *Validator) AddDelegation(cert *DelegationCert) {
	if cert == nil {
		return
	}
	v.delegations.Store(cert.ID, cert)
}

// ValidateCTTE parses and validates a CTT-E token string.
// Returns the parsed claims if valid, or an error describing the failure.
//
// Validation steps:
//  1. Parse JWT (split on dots, base64url decode)
//  2. Extract kid from header, look up delegation cert
//  3. Verify delegation cert signature against root public key
//  4. Verify delegation cert hasn't expired
//  5. Verify CTT-E signature against delegated public key
//  6. Verify CTT-E hasn't expired
//  7. Verify audience is "clauth-broker"
//  8. Return parsed TaskClaims
func (v *Validator) ValidateCTTE(tokenStr string) (*TaskClaims, error) {
	return v.validateAt(tokenStr, time.Now(), TokenTypeCTTE)
}

// Validate parses and validates a CTT-E or CTT-D token string.
// Accepts both token types; otherwise identical to ValidateCTTE.
func (v *Validator) Validate(tokenStr string) (*TaskClaims, error) {
	return v.validateAt(tokenStr, time.Now(), TokenTypeCTTE, TokenTypeCTTD)
}

// validateAt is the internal validation with an injectable clock for testing.
// allowedTypes specifies which token types are accepted.
func (v *Validator) validateAt(tokenStr string, now time.Time, allowedTypes ...TokenType) (*TaskClaims, error) {
	// Step 1: Parse JWT structure.
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("token: invalid JWT format: expected 3 parts")
	}

	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("token: invalid header encoding: %w", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("token: invalid header JSON: %w", err)
	}

	// Verify header fields.
	if header.Algorithm != "EdDSA" {
		return nil, fmt.Errorf("token: unsupported algorithm: %s", header.Algorithm)
	}
	typeAllowed := false
	for _, at := range allowedTypes {
		if header.Type == string(at) {
			typeAllowed = true
			break
		}
	}
	if !typeAllowed {
		return nil, fmt.Errorf("token: unexpected token type: %s", header.Type)
	}

	// Step 2: Look up delegation cert by kid.
	if header.KeyID == "" {
		return nil, errors.New("token: missing kid in header")
	}

	certVal, ok := v.delegations.Load(header.KeyID)
	if !ok {
		return nil, fmt.Errorf("token: unknown delegation key ID: %s", header.KeyID)
	}
	cert := certVal.(*DelegationCert)

	// Step 3: Verify delegation cert against root public key.
	delegPayload := &DelegationPayload{
		CertID:    cert.ID,
		BrokerID:  cert.BrokerID,
		PublicKey: []byte(cert.PublicKey),
		IssuedAt:  cert.IssuedAt.Unix(),
		ExpiresAt: cert.ExpiresAt.Unix(),
	}
	if err := VerifyDelegationCert(cert, delegPayload, v.rootPublicKey); err != nil {
		return nil, fmt.Errorf("token: delegation cert verification failed: %w", err)
	}

	// Step 4: Verify delegation cert hasn't expired (already done in VerifyDelegationCert,
	// but we re-check with our specific time for testability).
	if now.After(cert.ExpiresAt) {
		return nil, errors.New("token: delegation cert expired")
	}

	// Step 5: Verify CTT-E signature against delegated public key.
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("token: invalid signature encoding: %w", err)
	}

	signingInput := headerB64 + "." + payloadB64
	if !ed25519.Verify(cert.PublicKey, []byte(signingInput), sig) {
		return nil, errors.New("token: invalid token signature")
	}

	// Decode and parse payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("token: invalid payload encoding: %w", err)
	}

	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("token: invalid payload JSON: %w", err)
	}

	claims := &TaskClaims{
		Issuer:    payload.Issuer,
		Subject:   payload.Subject,
		Audience:  payload.Audience,
		IssuedAt:  time.Unix(payload.IssuedAt, 0),
		ExpiresAt: time.Unix(payload.ExpiresAt, 0),
		TokenID:   payload.TokenID,
		Task:      payload.Task,
		Envelope:  payload.Envelope,
	}

	// Step 6: Verify CTT-E hasn't expired.
	if now.After(claims.ExpiresAt) {
		return nil, errors.New("token: token expired")
	}

	// Step 7: Verify audience.
	if claims.Audience != "clauth-broker" {
		return nil, fmt.Errorf("token: unexpected audience: %s", claims.Audience)
	}

	// Step 8: Return parsed claims.
	return claims, nil
}

// ParseUnverified parses a JWT without verifying signatures.
// Used for logging/debugging only. Never use for authorization decisions.
func ParseUnverified(tokenStr string) (*TaskClaims, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("token: invalid JWT format: expected 3 parts")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token: invalid payload encoding: %w", err)
	}

	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("token: invalid payload JSON: %w", err)
	}

	return &TaskClaims{
		Issuer:    payload.Issuer,
		Subject:   payload.Subject,
		Audience:  payload.Audience,
		IssuedAt:  time.Unix(payload.IssuedAt, 0),
		ExpiresAt: time.Unix(payload.ExpiresAt, 0),
		TokenID:   payload.TokenID,
		Task:      payload.Task,
		Envelope:  payload.Envelope,
	}, nil
}
