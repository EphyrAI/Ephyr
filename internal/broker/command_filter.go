package broker

import (
	"fmt"
	"strings"
)

// CommandFilterResult describes the outcome of a command filter check.
type CommandFilterResult struct {
	Allowed bool
	Reason  string // human-readable explanation for the agent
	Pattern string // the pattern that matched (for audit)
	Mode    string // "deny", "allow", or "" (not filtered)
}

// CheckCommand evaluates a command string against deny/allow patterns.
// Returns immediately with Allowed=true if filtering is not enabled,
// ensuring zero overhead for targets without command_filter: true.
func CheckCommand(command string, denyPatterns, allowPatterns []string, filterEnabled bool) CommandFilterResult {
	if !filterEnabled {
		return CommandFilterResult{Allowed: true}
	}

	cmd := strings.ToLower(strings.TrimSpace(command))

	// Allow-list mode takes precedence when present (more restrictive).
	if len(allowPatterns) > 0 {
		for _, pattern := range allowPatterns {
			if matchPattern(cmd, strings.ToLower(pattern)) {
				return CommandFilterResult{Allowed: true, Mode: "allow", Pattern: pattern}
			}
		}
		return CommandFilterResult{
			Allowed: false,
			Reason:  "Command not in allow list. Only commands matching the configured allow patterns are permitted on this target. Your command did not match any allowed pattern.",
			Mode:    "allow",
		}
	}

	// Deny-list mode.
	if len(denyPatterns) > 0 {
		for _, pattern := range denyPatterns {
			if matchPattern(cmd, strings.ToLower(pattern)) {
				reason := buildDenyReason(command, pattern)
				return CommandFilterResult{
					Allowed: false,
					Reason:  reason,
					Pattern: pattern,
					Mode:    "deny",
				}
			}
		}
	}

	return CommandFilterResult{Allowed: true}
}

// matchPattern does simple substring/glob matching.
// Supports:
//   - "rm " -- substring match (matches anywhere in command)
//   - "rm -rf*" -- prefix + wildcard (command starts with prefix)
//   - "*passwd*" -- contains match (equivalent to substring but explicit)
//   - "*passwd" -- suffix match (command ends with suffix)
func matchPattern(cmd, pattern string) bool {
	if pattern == "" {
		return false
	}

	startsWithStar := strings.HasPrefix(pattern, "*")
	endsWithStar := strings.HasSuffix(pattern, "*")

	switch {
	case startsWithStar && endsWithStar:
		// *contains* pattern (also handles single "*" which matches everything)
		if len(pattern) <= 2 {
			return true // "*" or "**" matches everything
		}
		inner := pattern[1 : len(pattern)-1]
		return strings.Contains(cmd, inner)
	case endsWithStar:
		// prefix* pattern
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(cmd, prefix)
	case startsWithStar:
		// *suffix pattern
		suffix := pattern[1:]
		return strings.HasSuffix(cmd, suffix)
	default:
		// Plain substring match
		return strings.Contains(cmd, pattern)
	}
}

// buildDenyReason creates an informative message for the agent explaining
// why the command was blocked.
func buildDenyReason(command, pattern string) string {
	destructive := []string{"rm ", "rm -", "rmdir", "dd if=", "mkfs", "fdisk", "shred"}
	privilege := []string{"chmod", "chown", "passwd", "usermod", "userdel", "visudo"}
	dangerous := []string{":()", "fork", "> /dev/", "| /dev/"}

	lowerPattern := strings.ToLower(pattern)

	for _, d := range destructive {
		if strings.Contains(lowerPattern, d) {
			return fmt.Sprintf("Command blocked: destructive operation detected. The pattern %q is prohibited on this target. File deletion and disk operations are not permitted.", pattern)
		}
	}
	for _, p := range privilege {
		if strings.Contains(lowerPattern, p) {
			return fmt.Sprintf("Command blocked: privilege modification detected. The pattern %q is prohibited on this target. Permission and user modifications are not permitted.", pattern)
		}
	}
	for _, g := range dangerous {
		if strings.Contains(lowerPattern, g) {
			return fmt.Sprintf("Command blocked: dangerous operation detected. The pattern %q is prohibited on this target.", pattern)
		}
	}

	return fmt.Sprintf("Command blocked: matches prohibited pattern %q on this target.", pattern)
}
