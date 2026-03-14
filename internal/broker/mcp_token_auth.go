package broker

import (
	"fmt"
	"strings"

	"github.com/ben-spanswick/ephyr/internal/token"
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

	// Task identity must be enabled (delegation active, validator ready).
	if !s.broker.TaskIdentityEnabled() {
		return nil, fmt.Errorf("task identity not enabled, cannot validate task token")
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
	// TaskClaims field is being added to MCPAgent by another agent concurrently.
	agent := &MCPAgent{
		Name:        claims.Subject,
		Roles:       task.Envelope.Roles,
		AutoApprove: true, // task tokens are pre-approved
		TaskClaims:  claims,
	}

	return agent, nil
}

// Ensure token package is referenced to prevent "imported and not used" errors.
var _ *token.TaskClaims
