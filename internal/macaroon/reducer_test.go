package macaroon

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestReduce_SingleTarget(t *testing.T) {
	out, err := Reduce([]string{"target IN [a,b]"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(out.Envelope.Targets)
	want := []string{"a", "b"}
	if !reflect.DeepEqual(out.Envelope.Targets, want) {
		t.Fatalf("targets = %v, want %v", out.Envelope.Targets, want)
	}
}

func TestReduce_IntersectionNarrows(t *testing.T) {
	out, err := Reduce([]string{
		"target IN [a,b,c]",
		"target IN [b,c,d]",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(out.Envelope.Targets)
	want := []string{"b", "c"}
	if !reflect.DeepEqual(out.Envelope.Targets, want) {
		t.Fatalf("targets = %v, want %v", out.Envelope.Targets, want)
	}
}

func TestReduce_IntersectionToEmpty(t *testing.T) {
	out, err := Reduce([]string{
		"target IN [a]",
		"target IN [b]",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty intersection is valid (no access for that dimension).
	if len(out.Envelope.Targets) != 0 {
		t.Fatalf("targets = %v, want empty", out.Envelope.Targets)
	}
}

func TestReduce_MultipleExpires(t *testing.T) {
	out, err := Reduce([]string{
		"expires_before = 2026-12-31T23:59:59Z",
		"expires_before = 2026-06-15T12:00:00Z",
		"expires_before = 2026-09-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, _ := time.Parse(time.RFC3339, "2026-06-15T12:00:00Z")
	if !out.Envelope.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", out.Envelope.ExpiresAt, want)
	}
}

func TestReduce_CanDelegate_AND(t *testing.T) {
	// true AND true AND false = false
	out, err := Reduce([]string{
		"can_delegate = true",
		"can_delegate = true",
		"can_delegate = false",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Envelope.CanDelegate {
		t.Fatal("can_delegate should be false (AND)")
	}

	// All true.
	out2, err := Reduce([]string{
		"can_delegate = true",
		"can_delegate = true",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out2.Envelope.CanDelegate {
		t.Fatal("can_delegate should be true when all true")
	}
}

func TestReduce_DelegationDepth_Min(t *testing.T) {
	out, err := Reduce([]string{
		"delegation_depth <= 5",
		"delegation_depth <= 3",
		"delegation_depth <= 1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Envelope.DelegationDepth != 1 {
		t.Fatalf("delegation_depth = %d, want 1", out.Envelope.DelegationDepth)
	}
}

func TestReduce_AgentFirstWins(t *testing.T) {
	out, err := Reduce([]string{
		"agent = claude-1",
		"agent = claude-2",
		"agent = claude-3",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Metadata.Agent != "claude-1" {
		t.Fatalf("agent = %q, want %q", out.Metadata.Agent, "claude-1")
	}
}

func TestReduce_InitiatedByFirstWins(t *testing.T) {
	out, err := Reduce([]string{
		"initiated_by = urn:ephyr:agent:claude-1",
		"initiated_by = urn:ephyr:agent:claude-2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Metadata.InitiatedBy != "urn:ephyr:agent:claude-1" {
		t.Fatalf("initiated_by = %q, want %q", out.Metadata.InitiatedBy, "urn:ephyr:agent:claude-1")
	}
}

func TestReduce_UnknownCaveat_FailsClosed(t *testing.T) {
	_, err := Reduce([]string{
		"target IN [a]",
		"secret_power = unlimited",
	})
	if err == nil {
		t.Fatal("expected error for unknown caveat, got nil")
	}
	// Should wrap ErrUnknownCaveat.
	if !containsError(err, ErrUnknownCaveat) {
		t.Fatalf("expected ErrUnknownCaveat, got: %v", err)
	}
}

func TestReduce_MalformedCaveat_FailsClosed(t *testing.T) {
	cases := []string{
		"",                            // empty
		"nodicehere",                  // no operator
		"target = ",                   // empty value
		" = value",                    // empty key
		"delegation_depth <= abc",     // non-numeric depth
		"expires_before = not-a-time", // invalid time
		"can_delegate = maybe",        // invalid bool
	}
	for _, c := range cases {
		_, err := Reduce([]string{c})
		if err == nil {
			t.Fatalf("expected error for malformed caveat %q, got nil", c)
		}
	}
}

func TestReduce_AllDimensions(t *testing.T) {
	out, err := Reduce([]string{
		"agent = claude-main",
		"initiated_by = urn:ephyr:agent:claude-main",
		"target IN [dockerhost,hugoblog,mandrake-rack]",
		"role IN [read,operator]",
		"service IN [github,gitea,portainer]",
		"remote IN [demo-tools]",
		"method IN [GET,POST]",
		"can_delegate = true",
		"delegation_depth <= 3",
		"expires_before = 2026-12-31T23:59:59Z",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	env := out.Envelope
	sort.Strings(env.Targets)
	sort.Strings(env.Roles)
	sort.Strings(env.Services)

	wantTargets := []string{"dockerhost", "hugoblog", "mandrake-rack"}
	if !reflect.DeepEqual(env.Targets, wantTargets) {
		t.Fatalf("targets = %v, want %v", env.Targets, wantTargets)
	}
	wantRoles := []string{"operator", "read"}
	if !reflect.DeepEqual(env.Roles, wantRoles) {
		t.Fatalf("roles = %v, want %v", env.Roles, wantRoles)
	}
	wantServices := []string{"gitea", "github", "portainer"}
	if !reflect.DeepEqual(env.Services, wantServices) {
		t.Fatalf("services = %v, want %v", env.Services, wantServices)
	}
	if !reflect.DeepEqual(env.Remotes, []string{"demo-tools"}) {
		t.Fatalf("remotes = %v", env.Remotes)
	}
	wantMethods := []string{"GET", "POST"}
	sort.Strings(env.Methods)
	if !reflect.DeepEqual(env.Methods, wantMethods) {
		t.Fatalf("methods = %v, want %v", env.Methods, wantMethods)
	}
	if !env.CanDelegate {
		t.Fatal("can_delegate should be true")
	}
	if env.DelegationDepth != 3 {
		t.Fatalf("delegation_depth = %d, want 3", env.DelegationDepth)
	}
	wantExpiry, _ := time.Parse(time.RFC3339, "2026-12-31T23:59:59Z")
	if !env.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expires_at = %v, want %v", env.ExpiresAt, wantExpiry)
	}

	if out.Metadata.Agent != "claude-main" {
		t.Fatalf("agent = %q", out.Metadata.Agent)
	}
	if out.Metadata.InitiatedBy != "urn:ephyr:agent:claude-main" {
		t.Fatalf("initiated_by = %q", out.Metadata.InitiatedBy)
	}
}

func TestReduce_DelegationChain3Levels(t *testing.T) {
	// Simulate caveats accumulated across 3 levels of delegation.
	// Level 0 (root): broad access.
	// Level 1: narrows targets and roles.
	// Level 2: narrows further, reduces delegation depth and expiry.
	caveats := []string{
		// Root task caveats.
		"agent = claude-orchestrator",
		"initiated_by = urn:ephyr:agent:claude-orchestrator",
		"target IN [dockerhost,hugoblog,mandrake-rack]",
		"role IN [read,operator,admin]",
		"service IN [github,gitea,portainer,grafana]",
		"can_delegate = true",
		"delegation_depth <= 5",
		"expires_before = 2026-12-31T23:59:59Z",

		// Level 1 delegation caveats.
		"agent = claude-worker-1",
		"target IN [dockerhost,hugoblog]",
		"role IN [read,operator]",
		"service IN [github,gitea]",
		"delegation_depth <= 3",
		"expires_before = 2026-06-30T23:59:59Z",

		// Level 2 delegation caveats.
		"agent = claude-worker-2",
		"target IN [dockerhost]",
		"role IN [read]",
		"can_delegate = false",
		"delegation_depth <= 0",
		"expires_before = 2026-03-31T23:59:59Z",
	}

	out, err := Reduce(caveats)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	env := out.Envelope

	// Targets: {dh,hb,mr} ∩ {dh,hb} ∩ {dh} = {dh}
	if !reflect.DeepEqual(env.Targets, []string{"dockerhost"}) {
		t.Fatalf("targets = %v, want [dockerhost]", env.Targets)
	}

	// Roles: {r,o,a} ∩ {r,o} ∩ {r} = {r}
	if !reflect.DeepEqual(env.Roles, []string{"read"}) {
		t.Fatalf("roles = %v, want [read]", env.Roles)
	}

	// Services: {gh,gt,po,gr} ∩ {gh,gt} = {gh,gt} (level 2 doesn't constrain)
	sort.Strings(env.Services)
	if !reflect.DeepEqual(env.Services, []string{"gitea", "github"}) {
		t.Fatalf("services = %v, want [gitea,github]", env.Services)
	}

	// can_delegate: true AND true AND false = false
	if env.CanDelegate {
		t.Fatal("can_delegate should be false")
	}

	// delegation_depth: min(5, 3, 0) = 0
	if env.DelegationDepth != 0 {
		t.Fatalf("delegation_depth = %d, want 0", env.DelegationDepth)
	}

	// expires: earliest of the three = 2026-03-31
	wantExpiry, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	if !env.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expires_at = %v, want %v", env.ExpiresAt, wantExpiry)
	}

	// Agent: first wins = orchestrator
	if out.Metadata.Agent != "claude-orchestrator" {
		t.Fatalf("agent = %q, want claude-orchestrator", out.Metadata.Agent)
	}
}

func TestReduce_EmptyInput(t *testing.T) {
	out, err := Reduce([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty caveats = unconstrained envelope.
	if !out.Envelope.CanDelegate {
		t.Fatal("empty caveats should leave can_delegate true")
	}
	if out.Envelope.DelegationDepth != -1 {
		t.Fatalf("empty caveats delegation_depth = %d, want -1 (unconstrained)", out.Envelope.DelegationDepth)
	}
	if len(out.Envelope.Targets) != 0 {
		t.Fatalf("empty caveats should have nil targets, got %v", out.Envelope.Targets)
	}
}

func TestReduce_NilInput(t *testing.T) {
	out, err := Reduce(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatal("nil input should return non-nil output")
	}
}

func TestReduce_WrongOperator(t *testing.T) {
	// target requires IN, not =
	_, err := Reduce([]string{"target = dockerhost"})
	if err == nil {
		t.Fatal("expected error for wrong operator on target")
	}
}

func TestReduce_DelegationDepthWrongOperator(t *testing.T) {
	_, err := Reduce([]string{"delegation_depth = 5"})
	if err == nil {
		t.Fatal("expected error for = operator on delegation_depth")
	}
}

func TestReduce_CanDelegateWrongOperator(t *testing.T) {
	_, err := Reduce([]string{"can_delegate IN [true]"})
	if err == nil {
		t.Fatal("expected error for IN operator on can_delegate")
	}
}

func TestReduce_ExpiresWrongOperator(t *testing.T) {
	_, err := Reduce([]string{"expires_before IN [2026-01-01T00:00:00Z]"})
	if err == nil {
		t.Fatal("expected error for IN operator on expires_before")
	}
}

func TestReduce_MultipleRoleIntersections(t *testing.T) {
	out, err := Reduce([]string{
		"role IN [read,operator,admin]",
		"role IN [read,operator]",
		"role IN [operator,admin]",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// {r,o,a} ∩ {r,o} = {r,o} ∩ {o,a} = {o}
	if !reflect.DeepEqual(out.Envelope.Roles, []string{"operator"}) {
		t.Fatalf("roles = %v, want [operator]", out.Envelope.Roles)
	}
}

// containsError checks if err wraps or contains the target error.
func containsError(err, target error) bool {
	if err == nil {
		return false
	}
	return err.Error() == target.Error() || len(err.Error()) > len(target.Error()) && err.Error()[:len(target.Error())] == target.Error()[:len(target.Error())]
}

func TestParseCaveat(t *testing.T) {
	cases := []struct {
		raw  string
		key  string
		op   string
		val  string
		fail bool
	}{
		{"target IN [a,b,c]", "target", "IN", "[a,b,c]", false},
		{"role IN [read]", "role", "IN", "[read]", false},
		{"expires_before = 2026-12-31T23:59:59Z", "expires_before", "=", "2026-12-31T23:59:59Z", false},
		{"delegation_depth <= 5", "delegation_depth", "<=", "5", false},
		{"can_delegate = false", "can_delegate", "=", "false", false},
		{"agent = claude", "agent", "=", "claude", false},
		{"", "", "", "", true},
		{"nope", "", "", "", true},
	}
	for _, tc := range cases {
		key, op, val, err := parseCaveat(tc.raw)
		if tc.fail {
			if err == nil {
				t.Fatalf("expected error for %q", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", tc.raw, err)
		}
		if key != tc.key || op != tc.op || val != tc.val {
			t.Fatalf("parseCaveat(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tc.raw, key, op, val, tc.key, tc.op, tc.val)
		}
	}
}

func TestParseCSV(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"[a,b,c]", []string{"a", "b", "c"}},
		{"[a]", []string{"a"}},
		{"[]", nil},
		{"[a, b , c]", []string{"a", "b", "c"}},
		{"a,b,c", []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		got := parseCSV(tc.input)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parseCSV(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestIntersectSets(t *testing.T) {
	cases := []struct {
		a, b []string
		want []string
	}{
		{[]string{"a", "b", "c"}, []string{"b", "c", "d"}, []string{"b", "c"}},
		{[]string{"a"}, []string{"b"}, nil},
		{[]string{"x"}, []string{"x"}, []string{"x"}},
		{nil, []string{"a"}, nil},
		{[]string{"a"}, nil, nil},
		{nil, nil, nil},
	}
	for _, tc := range cases {
		got := intersectSets(tc.a, tc.b)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("intersect(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
