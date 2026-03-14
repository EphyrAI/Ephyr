package macaroon

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// knownCaveatKeys enumerates every valid caveat key.
// Any caveat with a key not in this set causes Reduce to fail closed.
var knownCaveatKeys = map[string]bool{
	"target":           true,
	"role":             true,
	"service":          true,
	"remote":           true,
	"method":           true,
	"can_delegate":     true,
	"delegation_depth": true,
	"expires_before":   true,
	"agent":            true,
	"initiated_by":     true,
}

// Reduce takes the caveats from a verified macaroon and produces the
// effective authorization envelope and metadata.
//
// This function is SAFETY CRITICAL. It enforces the following invariants:
//
//  1. Set dimensions (target, role, service, remote, method) use intersection:
//     each subsequent caveat can only narrow the set, never widen it.
//  2. Numeric dimensions (delegation_depth) use minimum.
//  3. Boolean dimensions (can_delegate) use AND.
//  4. Time dimensions (expires_before) use minimum (earliest).
//  5. Metadata dimensions (agent, initiated_by) use first-value-wins.
//  6. Unknown caveats cause immediate failure (fail closed).
func Reduce(caveats []string) (*ReducerOutput, error) {
	if len(caveats) == 0 {
		// No caveats: return an unconstrained envelope.
		return &ReducerOutput{
			Envelope: EffectiveEnvelope{
				CanDelegate:     true,
				DelegationDepth: -1, // unconstrained
			},
		}, nil
	}

	out := &ReducerOutput{
		Envelope: EffectiveEnvelope{
			CanDelegate:     true,
			DelegationDepth: -1, // -1 means unconstrained
		},
	}

	// Track which set dimensions have been constrained.
	type setDim struct {
		values      []string
		constrained bool
	}
	sets := map[string]*setDim{
		"target":  {},
		"role":    {},
		"service": {},
		"remote":  {},
		"method":  {},
	}

	depthConstrained := false
	expiresConstrained := false
	var expiresAt time.Time

	for _, raw := range caveats {
		key, op, value, err := parseCaveat(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedCaveat, err)
		}

		if !knownCaveatKeys[key] {
			return nil, fmt.Errorf("%w: %q", ErrUnknownCaveat, key)
		}

		switch key {
		case "target", "role", "service", "remote", "method":
			if op != "IN" {
				return nil, fmt.Errorf("%w: %s requires IN operator, got %q", ErrMalformedCaveat, key, op)
			}
			newSet := parseCSV(value)
			dim := sets[key]
			if !dim.constrained {
				dim.values = newSet
				dim.constrained = true
			} else {
				dim.values = intersectSets(dim.values, newSet)
			}

		case "expires_before":
			if op != "=" {
				return nil, fmt.Errorf("%w: expires_before requires = operator, got %q", ErrMalformedCaveat, op)
			}
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid time %q: %w", ErrMalformedCaveat, value, err)
			}
			if !expiresConstrained || t.Before(expiresAt) {
				expiresAt = t
				expiresConstrained = true
			}

		case "can_delegate":
			if op != "=" {
				return nil, fmt.Errorf("%w: can_delegate requires = operator, got %q", ErrMalformedCaveat, op)
			}
			b, err := strconv.ParseBool(value)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid bool %q: %w", ErrMalformedCaveat, value, err)
			}
			// AND: any false makes it false.
			if !b {
				out.Envelope.CanDelegate = false
			}

		case "delegation_depth":
			if op != "<=" {
				return nil, fmt.Errorf("%w: delegation_depth requires <= operator, got %q", ErrMalformedCaveat, op)
			}
			d, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid int %q: %w", ErrMalformedCaveat, value, err)
			}
			if !depthConstrained || d < out.Envelope.DelegationDepth {
				out.Envelope.DelegationDepth = d
				depthConstrained = true
			}

		case "agent":
			if op != "=" {
				return nil, fmt.Errorf("%w: agent requires = operator, got %q", ErrMalformedCaveat, op)
			}
			if out.Metadata.Agent == "" {
				out.Metadata.Agent = value
			}
			// first value wins; subsequent are ignored

		case "initiated_by":
			if op != "=" {
				return nil, fmt.Errorf("%w: initiated_by requires = operator, got %q", ErrMalformedCaveat, op)
			}
			if out.Metadata.InitiatedBy == "" {
				out.Metadata.InitiatedBy = value
			}
			// first value wins; subsequent are ignored
		}
	}

	// Apply set dimensions.
	if sets["target"].constrained {
		out.Envelope.Targets = sets["target"].values
	}
	if sets["role"].constrained {
		out.Envelope.Roles = sets["role"].values
	}
	if sets["service"].constrained {
		out.Envelope.Services = sets["service"].values
	}
	if sets["remote"].constrained {
		out.Envelope.Remotes = sets["remote"].values
	}
	if sets["method"].constrained {
		out.Envelope.Methods = sets["method"].values
	}

	if expiresConstrained {
		out.Envelope.ExpiresAt = expiresAt
	}

	return out, nil
}

// parseCaveat parses a caveat string into key, operator, and value.
// Supported formats:
//
//	"key = value"
//	"key IN [a,b,c]"
//	"key <= value"
func parseCaveat(raw string) (key, op, value string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", fmt.Errorf("empty caveat")
	}

	// Try " IN " first (contains space, so it's unambiguous).
	if idx := strings.Index(raw, " IN "); idx > 0 {
		key = strings.TrimSpace(raw[:idx])
		value = strings.TrimSpace(raw[idx+4:])
		if key == "" || value == "" {
			return "", "", "", fmt.Errorf("empty key or value in %q", raw)
		}
		return key, "IN", value, nil
	}

	// Try " <= ".
	if idx := strings.Index(raw, " <= "); idx > 0 {
		key = strings.TrimSpace(raw[:idx])
		value = strings.TrimSpace(raw[idx+4:])
		if key == "" || value == "" {
			return "", "", "", fmt.Errorf("empty key or value in %q", raw)
		}
		return key, "<=", value, nil
	}

	// Try " = " (must come after <= to avoid ambiguity).
	if idx := strings.Index(raw, " = "); idx > 0 {
		key = strings.TrimSpace(raw[:idx])
		value = strings.TrimSpace(raw[idx+3:])
		if key == "" || value == "" {
			return "", "", "", fmt.Errorf("empty key or value in %q", raw)
		}
		return key, "=", value, nil
	}

	return "", "", "", fmt.Errorf("no operator found in %q", raw)
}

// parseCSV parses a "[a,b,c]" formatted string into a slice of strings.
// Leading/trailing brackets and whitespace are stripped from each element.
func parseCSV(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// intersectSets returns the intersection of two string slices.
// The result is sorted for deterministic output.
func intersectSets(a, b []string) []string {
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	var result []string
	for _, v := range b {
		if set[v] {
			result = append(result, v)
			delete(set, v) // prevent duplicates
		}
	}
	sort.Strings(result)
	return result
}
