package macaroon

import (
	"sort"
	"testing"
)

func FuzzReduce(f *testing.F) {
	// Seed corpus with valid caveats covering all types.
	f.Add("target IN [a,b,c]")
	f.Add("role IN [read]")
	f.Add("service IN [github,gitea]")
	f.Add("remote IN [demo-tools]")
	f.Add("method IN [GET,POST]")
	f.Add("expires_before = 2026-12-31T23:59:59Z")
	f.Add("can_delegate = false")
	f.Add("can_delegate = true")
	f.Add("delegation_depth <= 5")
	f.Add("delegation_depth <= 0")
	f.Add("agent = claude")
	f.Add("initiated_by = urn:ephyr:agent:claude")
	// Malformed seeds.
	f.Add("")
	f.Add("unknown_key = value")
	f.Add("no-operator-here")
	f.Add("target = wrong-op")
	f.Add("delegation_depth <= not-a-number")
	f.Add("expires_before = not-a-time")
	f.Add("can_delegate = maybe")

	f.Fuzz(func(t *testing.T, caveat string) {
		// Must not panic regardless of input.
		_, _ = Reduce([]string{caveat})
	})
}

func FuzzReduceNarrowing(f *testing.F) {
	// Property: adding caveats can never widen the envelope.
	// Seed with pairs of valid caveats.
	f.Add("target IN [a,b,c]", "target IN [b,c]")
	f.Add("role IN [read,operator]", "role IN [read]")
	f.Add("delegation_depth <= 5", "delegation_depth <= 3")
	f.Add("can_delegate = true", "can_delegate = false")
	f.Add("expires_before = 2026-12-31T23:59:59Z", "expires_before = 2026-06-15T12:00:00Z")
	f.Add("service IN [a,b,c]", "service IN [b,c,d]")
	f.Add("method IN [GET,POST,PUT]", "method IN [GET]")
	f.Add("agent = first", "agent = second")
	f.Add("initiated_by = urn:a", "initiated_by = urn:b")

	f.Fuzz(func(t *testing.T, c1, c2 string) {
		r1, err1 := Reduce([]string{c1})
		r2, err2 := Reduce([]string{c1, c2})

		if err1 != nil || err2 != nil {
			// Invalid caveats, skip property check.
			return
		}

		// r2 must be subset of or equal to r1 in every dimension.

		// Check set dimensions: r2.Targets subset of r1.Targets.
		checkSubset(t, "targets", r1.Envelope.Targets, r2.Envelope.Targets)
		checkSubset(t, "roles", r1.Envelope.Roles, r2.Envelope.Roles)
		checkSubset(t, "services", r1.Envelope.Services, r2.Envelope.Services)
		checkSubset(t, "remotes", r1.Envelope.Remotes, r2.Envelope.Remotes)
		checkSubset(t, "methods", r1.Envelope.Methods, r2.Envelope.Methods)

		// can_delegate: r2 can never be true if r1 is false.
		if !r1.Envelope.CanDelegate && r2.Envelope.CanDelegate {
			t.Errorf("can_delegate widened: r1=%v, r2=%v", r1.Envelope.CanDelegate, r2.Envelope.CanDelegate)
		}

		// delegation_depth: r2 <= r1 (when both constrained).
		if r1.Envelope.DelegationDepth >= 0 && r2.Envelope.DelegationDepth >= 0 {
			if r2.Envelope.DelegationDepth > r1.Envelope.DelegationDepth {
				t.Errorf("delegation_depth widened: r1=%d, r2=%d",
					r1.Envelope.DelegationDepth, r2.Envelope.DelegationDepth)
			}
		}

		// expires_before: r2 <= r1 (when both constrained).
		if !r1.Envelope.ExpiresAt.IsZero() && !r2.Envelope.ExpiresAt.IsZero() {
			if r2.Envelope.ExpiresAt.After(r1.Envelope.ExpiresAt) {
				t.Errorf("expires_at widened: r1=%v, r2=%v",
					r1.Envelope.ExpiresAt, r2.Envelope.ExpiresAt)
			}
		}
	})
}

// checkSubset verifies that narrowed is a subset of wider.
// If wider is nil/empty (unconstrained), any narrowed is valid.
// If wider is constrained, every element in narrowed must be in wider.
func checkSubset(t *testing.T, name string, wider, narrowed []string) {
	t.Helper()
	if len(wider) == 0 {
		// Unconstrained, anything is allowed.
		return
	}
	wideSet := make(map[string]bool, len(wider))
	for _, v := range wider {
		wideSet[v] = true
	}
	sort.Strings(narrowed)
	for _, v := range narrowed {
		if !wideSet[v] {
			t.Errorf("%s widened: %q not in wider set %v", name, v, wider)
		}
	}
}
