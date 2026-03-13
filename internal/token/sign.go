package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// jwtHeader is the JWT header for CTT tokens.
type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// jwtPayload is the JWT payload with Unix timestamp fields for serialization.
type jwtPayload struct {
	Issuer    string       `json:"iss"`
	Subject   string       `json:"sub"`
	Audience  string       `json:"aud"`
	IssuedAt  int64        `json:"iat"`
	ExpiresAt int64        `json:"exp"`
	TokenID   string       `json:"jti"`
	Task      TaskIdentity `json:"task"`
	Envelope  Envelope     `json:"envelope"`
}

// Issuer signs CTT tokens using the broker's delegated Ed25519 key.
type Issuer struct {
	brokerID   string
	privateKey ed25519.PrivateKey
	delegation *DelegationCert
	mu         sync.RWMutex
}

// NewIssuer creates a new token issuer for the given broker instance.
func NewIssuer(brokerID string) *Issuer {
	return &Issuer{
		brokerID: brokerID,
	}
}

// SetDelegation updates the delegated signing key and cert.
// Called on each delegation rotation.
func (i *Issuer) SetDelegation(privKey ed25519.PrivateKey, cert *DelegationCert) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.privateKey = privKey
	i.delegation = cert
}

// DelegationKeyID returns the current delegation cert key ID.
func (i *Issuer) DelegationKeyID() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.delegation == nil {
		return ""
	}
	return i.delegation.ID
}

// SignCTTE creates and signs a CTT-E execution token.
// Returns a compact JWT string: header.payload.signature
func (i *Issuer) SignCTTE(claims *TaskClaims) (string, error) {
	i.mu.RLock()
	privKey := i.privateKey
	deleg := i.delegation
	i.mu.RUnlock()

	if privKey == nil || deleg == nil {
		return "", errors.New("token: issuer has no delegation key set")
	}

	if claims == nil {
		return "", errors.New("token: claims are nil")
	}

	// Populate standard fields if not set.
	if claims.Issuer == "" {
		claims.Issuer = "clauth:" + i.brokerID
	}
	if claims.Audience == "" {
		claims.Audience = "clauth-broker"
	}
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now()
	}
	if claims.TokenID == "" {
		claims.TokenID = "cte_" + NewULID()
	}

	return signJWT(claims, deleg.ID, string(TokenTypeCTTE), privKey)
}

// signJWT builds and signs a JWT from the given claims.
func signJWT(claims *TaskClaims, kid string, typ string, privKey ed25519.PrivateKey) (string, error) {
	// Build header.
	header := jwtHeader{
		Algorithm: "EdDSA",
		Type:      typ,
		KeyID:     kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("token: failed to marshal header: %w", err)
	}

	// Build payload with Unix timestamps.
	payload := jwtPayload{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		IssuedAt:  claims.IssuedAt.Unix(),
		ExpiresAt: claims.ExpiresAt.Unix(),
		TokenID:   claims.TokenID,
		Task:      claims.Task,
		Envelope:  claims.Envelope,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("token: failed to marshal payload: %w", err)
	}

	// Base64url encode header and payload.
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign: Ed25519 over "header.payload".
	signingInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(privKey, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return headerB64 + "." + payloadB64 + "." + sigB64, nil
}
