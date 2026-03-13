package token

import (
	"crypto/ed25519"
	"time"
)

// TokenType distinguishes execution from delegation tokens.
type TokenType string

const (
	// TokenTypeCTTE is a CTT-E execution token.
	TokenTypeCTTE TokenType = "CTT-E"
	// TokenTypeCTTD is a CTT-D delegation token (Phase 2b).
	TokenTypeCTTD TokenType = "CTT-D"
)

// DelegationCert is a certificate issued by the signer that authorizes
// the broker to sign task tokens. The broker generates an Ed25519 keypair
// locally; the signer signs the public key and returns this cert.
type DelegationCert struct {
	ID        string            `json:"id"`        // unique cert ID (kid in JWT header)
	BrokerID  string            `json:"broker_id"` // broker instance identifier
	PublicKey ed25519.PublicKey  `json:"-"`         // broker's public key (not serialized in JSON)
	Signature []byte            `json:"signature"` // signer's signature over the cert payload
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// TaskClaims are the JWT claims for a CTT-E execution token.
type TaskClaims struct {
	// Standard JWT claims
	Issuer    string    `json:"iss"` // "clauth:<broker-instance-id>"
	Subject   string    `json:"sub"` // agent name
	Audience  string    `json:"aud"` // "clauth-broker"
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	TokenID   string    `json:"jti"` // "cte_<ULID>" or "ctd_<ULID>"

	// Task identity
	Task TaskIdentity `json:"task"`

	// Capability envelope (upper bound)
	Envelope Envelope `json:"envelope"`
}

// TaskIdentity captures the hierarchical identity of a task.
type TaskIdentity struct {
	ID          string   `json:"id"`           // ULID
	RootID      string   `json:"root_id"`      // ULID of root task
	ParentID    string   `json:"parent_id"`    // ULID of parent (empty for root)
	Depth       int      `json:"depth"`        // 0 = root
	Lineage     []string `json:"lineage"`      // [root, ..., self]
	InitiatedBy string   `json:"initiated_by"` // "clauth:local:uid:1000" or "clauth:apikey:ak_xxx"
	Description string   `json:"description"`  // human-readable
}

// Envelope defines the capability bounds for a task token.
type Envelope struct {
	Targets  []string `json:"targets"`
	Roles    []string `json:"roles"`
	Services []string `json:"services"`
	Remotes  []string `json:"remotes"`
	Methods  []string `json:"methods"`
}

// ContainsTarget checks if the envelope permits a given target.
// A wildcard "*" in Targets matches any target.
func (e *Envelope) ContainsTarget(t string) bool {
	return containsString(e.Targets, t)
}

// ContainsRole checks if the envelope permits a given role.
// A wildcard "*" in Roles matches any role.
func (e *Envelope) ContainsRole(r string) bool {
	return containsString(e.Roles, r)
}

// ContainsService checks if the envelope permits a given service.
// A wildcard "*" in Services matches any service.
func (e *Envelope) ContainsService(s string) bool {
	return containsString(e.Services, s)
}

// ContainsMethod checks if the envelope permits a given HTTP method.
// A wildcard "*" in Methods matches any method.
func (e *Envelope) ContainsMethod(m string) bool {
	return containsString(e.Methods, m)
}

// ContainsRemote checks if the envelope permits a given remote.
// A wildcard "*" in Remotes matches any remote.
func (e *Envelope) ContainsRemote(r string) bool {
	return containsString(e.Remotes, r)
}

// IsSubsetOf checks if this envelope is a subset of (or equal to) the parent envelope.
// Used for delegation: a delegated token cannot exceed the parent's capabilities.
// Wildcard "*" in the parent matches everything in the child.
func (e *Envelope) IsSubsetOf(parent *Envelope) bool {
	return isSubset(e.Targets, parent.Targets) &&
		isSubset(e.Roles, parent.Roles) &&
		isSubset(e.Services, parent.Services) &&
		isSubset(e.Remotes, parent.Remotes) &&
		isSubset(e.Methods, parent.Methods)
}

// containsString checks if the slice contains the given string or a wildcard.
func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == "*" || s == val {
			return true
		}
	}
	return false
}

// isSubset checks if every element in child is present in parent.
// A wildcard "*" in parent matches everything.
func isSubset(child, parent []string) bool {
	// If parent contains wildcard, everything is a subset.
	for _, p := range parent {
		if p == "*" {
			return true
		}
	}
	// Check each child element is in parent.
	for _, c := range child {
		if c == "*" {
			// Child wildcard can only be subset if parent also has wildcard.
			// We already checked parent for wildcard above.
			return false
		}
		found := false
		for _, p := range parent {
			if p == c {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
