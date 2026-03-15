package broker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	macaroonpkg "github.com/EphyrAI/Ephyr/internal/macaroon"
	"github.com/EphyrAI/Ephyr/internal/token"
)

// authenticateWithCTTE attempts to validate a Bearer token as a CTT-E or CTT-D task token.
// Returns nil, nil if the token is not a JWT (caller should fall through to API key auth).
// Returns agent, nil on successful task token validation.
// Returns nil, err on validation failure.
func (s *MCPServer) authenticateWithCTTE(bearerToken string) (*MCPAgent, error) {
	// Not a JWT — signal caller to try API key auth.
	if strings.Count(bearerToken, ".") != 2 {
		return nil, nil
	}

	// JWT path requires the JWT validator to be initialized.
	if s.broker.tokenValidator == nil || s.broker.delegation == nil || !s.broker.delegation.IsReady() {
		return nil, fmt.Errorf("task identity (JWT) not enabled, cannot validate task token")
	}

	// Validate the token: signature chain, delegation cert, expiry, audience.
	// Accepts both CTT-E (execution) and CTT-D (delegation) token types.
	claims, err := s.broker.tokenValidator.Validate(bearerToken)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Check revocation via epoch watermarks — walks the lineage array
	// and checks if any ancestor was revoked after this token was issued.
	if err := s.broker.revocation.CheckLineage(claims.Task.Lineage, claims.IssuedAt); err != nil {
		return nil, fmt.Errorf("task token revoked: %w", err)
	}

	// Verify the task still exists in the manager (not expired or cleaned up).
	task := s.broker.taskMgr.GetTask(claims.Task.ID)
	if task == nil {
		return nil, fmt.Errorf("task not found or expired")
	}

	// Build MCPAgent from the task's stored envelope.
	agent := &MCPAgent{
		Name:        claims.Subject,
		Roles:       task.Envelope.Roles,
		AutoApprove: true, // task tokens are pre-approved
		TaskClaims:  claims,
	}

	return agent, nil
}

// authenticateWithMacaroon validates a base64url-encoded macaroon token.
// Called when the bearer token has a "mac_" prefix (prefix already stripped).
func (s *MCPServer) authenticateWithMacaroon(tokenStr string) (*MCPAgent, error) {
	if s.broker.macaroonVerifier == nil {
		return nil, fmt.Errorf("macaroon verification not available")
	}

	// Track verification latency.
	defer s.broker.metrics.ObserveTiming(&s.broker.metrics.MacaroonVerifyLatency)()

	// 1. Decode from base64url (standard encoding, no padding).
	data, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("macaroon: invalid base64url encoding: %w", err)
	}

	// 2. Unmarshal binary.
	var mac macaroonpkg.Macaroon
	if err := mac.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("macaroon: %w", err)
	}

	// 3. Verify HMAC chain + reduce caveats + check expiry.
	result, err := s.broker.macaroonVerifier.Verify(&mac)
	if err != nil {
		return nil, fmt.Errorf("macaroon verification failed: %w", err)
	}

	// 4. Look up task from signature digest.
	task := s.broker.taskMgr.LookupBySignature(result.SigDigest)
	if task == nil {
		// Try root task ID (for root macaroons where sig might not be indexed yet).
		task = s.broker.taskMgr.GetTask(string(mac.Id()))
	}
	if task == nil {
		return nil, fmt.Errorf("task not found or expired for macaroon")
	}

	// 5. Check revocation via lineage.
	if s.broker.revocation != nil {
		for _, id := range task.Lineage {
			if s.broker.revocation.IsRevoked(id) {
				return nil, fmt.Errorf("task %s has been revoked", id)
			}
		}
	}

	// 6. Build MCPAgent with macaroon-derived permissions.
	// Map the macaroon's EffectiveEnvelope to token.TaskClaims so that
	// envelope_check.go and the rest of the broker work unchanged.
	agent := &MCPAgent{
		Name:        result.Metadata.Agent,
		Roles:       result.Envelope.Roles,
		AutoApprove: true, // macaroon tokens are pre-approved
		TaskClaims: &token.TaskClaims{
			Subject:   result.Metadata.Agent,
			IssuedAt:  task.CreatedAt,
			ExpiresAt: result.Envelope.ExpiresAt,
			Task: token.TaskIdentity{
				ID:          task.ID,
				RootID:      task.RootID,
				ParentID:    task.ParentID,
				Depth:       task.Depth,
				Lineage:     task.Lineage,
				InitiatedBy: task.InitiatedBy,
				Description: task.Description,
			},
			Envelope: token.Envelope{
				Targets:  result.Envelope.Targets,
				Roles:    result.Envelope.Roles,
				Services: result.Envelope.Services,
				Remotes:  result.Envelope.Remotes,
				Methods:  result.Envelope.Methods,
			},
		},
		RawMacaroon: &mac, // preserved for delegation
	}

	return agent, nil
}

// sha256Hex computes SHA-256 of a 32-byte array and returns the hex string.
func sha256Hex(sig [32]byte) string {
	h := sha256.Sum256(sig[:])
	return hex.EncodeToString(h[:])
}

// Ensure token package is referenced to prevent "imported and not used" errors.
var _ *token.TaskClaims
