package policy

import "time"

// Config is the top-level policy configuration loaded from YAML.
type Config struct {
	Global  GlobalPolicy              `yaml:"global"`
	Agents  map[string]AgentPolicy    `yaml:"agents"`
	Targets map[string]TargetPolicy   `yaml:"targets"`
	Roles   map[string]RoleDefinition `yaml:"roles"`
}

// GlobalPolicy defines cluster-wide limits and defaults.
type GlobalPolicy struct {
	MaxActiveCerts int             `yaml:"max_active_certs"` // default 10
	DefaultTTL     string          `yaml:"default_ttl"`      // e.g. "5m"
	MaxTTL         string          `yaml:"max_ttl"`          // e.g. "30m"
	RateLimit      RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig controls request throttling per agent.
type RateLimitConfig struct {
	RequestsPerWindow int `yaml:"requests_per_window"` // default 10
	WindowSeconds     int `yaml:"window_seconds"`      // default 60
}

// AgentPolicy defines per-agent constraints.
type AgentPolicy struct {
	UID                int    `yaml:"uid"`
	MaxConcurrentCerts int    `yaml:"max_concurrent_certs"` // default 3
	Description        string `yaml:"description"`
	APIKeyHash         string `yaml:"api_key_hash"`
}

// TargetPolicy defines a target host and what roles may access it.
type TargetPolicy struct {
	Host         string   `yaml:"host"`
	Port         int      `yaml:"port"`                    // default 22
	VLAN         int      `yaml:"vlan"`
	AllowedRoles []string `yaml:"allowed_roles"`
	MaxTTL       string   `yaml:"max_ttl"`
	AutoApprove  bool     `yaml:"auto_approve"`
	ForceCommand string   `yaml:"force_command,omitempty"`
	Description  string   `yaml:"description,omitempty"`
}

// RoleDefinition maps a logical role name to an SSH principal.
type RoleDefinition struct {
	Principal   string `yaml:"principal"`   // SSH principal name, e.g. "agent-read"
	Description string `yaml:"description"`
	APIKeyHash         string `yaml:"api_key_hash"`
}

// ResolvedConfig holds the parsed Config alongside pre-resolved durations
// so callers never need to re-parse duration strings.
type ResolvedConfig struct {
	Raw              *Config
	GlobalDefaultTTL time.Duration
	GlobalMaxTTL     time.Duration
	TargetMaxTTLs    map[string]time.Duration // target name -> parsed max_ttl
}

// Decision is the outcome of a policy evaluation.
type Decision int

const (
	// Approve means the request is auto-approved and a cert can be issued.
	Approve Decision = iota
	// Deny means the request violates policy and must be rejected.
	Deny
	// Pending means the request is valid but requires manual approval.
	Pending
)

// String returns a human-readable decision label.
func (d Decision) String() string {
	switch d {
	case Approve:
		return "APPROVE"
	case Deny:
		return "DENY"
	case Pending:
		return "PENDING"
	default:
		return "UNKNOWN"
	}
}

// EvalRequest is the input to the policy engine's Evaluate method.
type EvalRequest struct {
	AgentUID   int
	TargetName string
	RoleName   string
	Duration   time.Duration
}

// EvalResult is the output of a policy evaluation.
type EvalResult struct {
	Decision        Decision
	Reason          string
	ClampedDuration time.Duration
	Principal       string // the SSH principal from the matched role
}

// TrackedCert represents an active certificate being tracked by the engine.
type TrackedCert struct {
	Serial    uint64
	AgentUID  int
	Target    string
	Role      string
	ExpiresAt time.Time
}
