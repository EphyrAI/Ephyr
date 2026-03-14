package macaroon

import (
	"strings"
	"testing"
	"time"
)

func testEnvelope() EffectiveEnvelope {
	return EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"github", "gitea"},
		Remotes:         []string{"demo-tools"},
		Methods:         []string{"GET", "POST"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
}

func caveatsContain(caveats [][]byte, prefix string) bool {
	for _, c := range caveats {
		if strings.HasPrefix(string(c), prefix) {
			return true
		}
	}
	return false
}

func caveatValue(caveats [][]byte, prefix string) string {
	for _, c := range caveats {
		s := string(c)
		if strings.HasPrefix(s, prefix) {
			return s
		}
	}
	return ""
}

func TestMintRoot_Basic(t *testing.T) {
	ks := NewRootKeyStore()
	m := NewMinter(ks)

	env := testEnvelope()
	mac, err := m.MintRoot("01JQROOT000000000000000000", "claude-main", "urn:ephyr:agent:claude-main", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	if mac == nil {
		t.Fatal("MintRoot returned nil")
	}

	// Check location.
	if mac.Location() != "ephyr-broker" {
		t.Fatalf("location = %q, want %q", mac.Location(), "ephyr-broker")
	}

	// Check ID is the root task ID.
	if string(mac.Id()) != "01JQROOT000000000000000000" {
		t.Fatalf("id = %q, want %q", string(mac.Id()), "01JQROOT000000000000000000")
	}

	// Check expected caveats are present.
	caveats := mac.Caveats()
	if !caveatsContain(caveats, "agent = claude-main") {
		t.Fatal("missing agent caveat")
	}
	if !caveatsContain(caveats, "initiated_by = urn:ephyr:agent:claude-main") {
		t.Fatal("missing initiated_by caveat")
	}
	if !caveatsContain(caveats, "expires_before = ") {
		t.Fatal("missing expires_before caveat")
	}
	if !caveatsContain(caveats, "target IN [") {
		t.Fatal("missing target caveat")
	}
	if !caveatsContain(caveats, "role IN [") {
		t.Fatal("missing role caveat")
	}
	if !caveatsContain(caveats, "service IN [") {
		t.Fatal("missing service caveat")
	}
	if !caveatsContain(caveats, "remote IN [") {
		t.Fatal("missing remote caveat")
	}
	if !caveatsContain(caveats, "method IN [") {
		t.Fatal("missing method caveat")
	}
	if !caveatsContain(caveats, "can_delegate = true") {
		t.Fatal("missing can_delegate caveat")
	}
	if !caveatsContain(caveats, "delegation_depth <= 3") {
		t.Fatal("missing delegation_depth caveat")
	}
}

func TestMintRoot_VerifiesWithKey(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := testEnvelope()
	mac, err := minter.MintRoot("01JQROUNDTRIP0000000000000", "claude-test", "urn:ephyr:agent:claude-test", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Verify should succeed.
	result, err := verifier.Verify(mac)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Metadata.Agent != "claude-test" {
		t.Fatalf("agent = %q, want %q", result.Metadata.Agent, "claude-test")
	}
}

func TestMintRoot_AllEnvelopeDimensions(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog", "mandrake-rack"},
		Roles:           []string{"read", "operator", "admin"},
		Services:        []string{"github", "gitea", "portainer"},
		Remotes:         []string{"demo-tools", "prod-tools"},
		Methods:         []string{"GET", "POST", "PUT", "DELETE"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	mac, err := minter.MintRoot("01JQDIMS0000000000000000000", "claude-full", "urn:ephyr:agent:claude-full", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	result, err := verifier.Verify(mac)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// All 5 set dimensions should be populated.
	if len(result.Envelope.Targets) != 3 {
		t.Fatalf("targets count = %d, want 3", len(result.Envelope.Targets))
	}
	if len(result.Envelope.Roles) != 3 {
		t.Fatalf("roles count = %d, want 3", len(result.Envelope.Roles))
	}
	if len(result.Envelope.Services) != 3 {
		t.Fatalf("services count = %d, want 3", len(result.Envelope.Services))
	}
	if len(result.Envelope.Remotes) != 2 {
		t.Fatalf("remotes count = %d, want 2", len(result.Envelope.Remotes))
	}
	if len(result.Envelope.Methods) != 4 {
		t.Fatalf("methods count = %d, want 4", len(result.Envelope.Methods))
	}
	if result.Envelope.DelegationDepth != 5 {
		t.Fatalf("delegation_depth = %d, want 5", result.Envelope.DelegationDepth)
	}
	if !result.Envelope.CanDelegate {
		t.Fatal("can_delegate should be true")
	}
}

func TestMintRoot_NoDelegation(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)

	env := EffectiveEnvelope{
		Targets:     []string{"dockerhost"},
		Roles:       []string{"read"},
		CanDelegate: false,
		ExpiresAt:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	mac, err := minter.MintRoot("01JQNODEL00000000000000000", "claude-leaf", "urn:ephyr:agent:claude-leaf", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	caveats := mac.Caveats()

	// can_delegate = false should be present.
	if !caveatsContain(caveats, "can_delegate = false") {
		t.Fatal("missing can_delegate = false caveat")
	}

	// delegation_depth should NOT be present when CanDelegate is false.
	if caveatsContain(caveats, "delegation_depth") {
		t.Fatal("delegation_depth caveat should not be present when CanDelegate is false")
	}
}

func TestMintDelegated_NarrowsEnvelope(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)

	parentEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog", "mandrake-rack"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"github", "gitea"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	parent, err := minter.MintRoot("01JQPARENT0000000000000000", "claude-parent", "urn:ephyr:agent:claude-parent", parentEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	childEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		Services:        []string{"github"},
		CanDelegate:     true,
		DelegationDepth: 2,
		ExpiresAt:       time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}

	child, err := minter.MintDelegated(parent, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	// Child should have more caveats than parent (parent's + child's narrowing).
	if len(child.Caveats()) <= len(parent.Caveats()) {
		t.Fatalf("child caveats (%d) should be more than parent (%d)",
			len(child.Caveats()), len(parent.Caveats()))
	}

	// Child should share the same ID as parent (same root task).
	if string(child.Id()) != string(parent.Id()) {
		t.Fatal("child should have same ID as parent")
	}
}

func TestMintDelegated_ChainVerifies(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	parentEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog"},
		Roles:           []string{"read", "operator"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	parent, err := minter.MintRoot("01JQCHAIN0000000000000000", "claude-root", "urn:ephyr:agent:claude-root", parentEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	childEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		CanDelegate:     false,
		DelegationDepth: 0,
		ExpiresAt:       time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}

	child, err := minter.MintDelegated(parent, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	// Both should verify.
	parentResult, err := verifier.Verify(parent)
	if err != nil {
		t.Fatalf("Verify parent: %v", err)
	}
	if parentResult.Metadata.Agent != "claude-root" {
		t.Fatalf("parent agent = %q", parentResult.Metadata.Agent)
	}

	childResult, err := verifier.Verify(child)
	if err != nil {
		t.Fatalf("Verify child: %v", err)
	}
	if childResult.Metadata.Agent != "claude-root" {
		t.Fatalf("child agent = %q, want %q (first-value-wins)", childResult.Metadata.Agent, "claude-root")
	}

	// Child envelope should be narrower.
	if len(childResult.Envelope.Targets) != 1 || childResult.Envelope.Targets[0] != "dockerhost" {
		t.Fatalf("child targets = %v, want [dockerhost]", childResult.Envelope.Targets)
	}
	if childResult.Envelope.CanDelegate {
		t.Fatal("child can_delegate should be false")
	}
}

func TestMintDelegated_SizeLimit(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)

	env := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		CanDelegate:     true,
		DelegationDepth: 100,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	parent, err := minter.MintRoot("01JQSIZE00000000000000000", "claude-size", "urn:ephyr:agent:claude-size", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Keep delegating with large target lists until we exceed the size limit.
	current := parent
	var lastErr error
	for i := 0; i < 100; i++ {
		// Each delegation adds targets with long names to grow the token.
		bigTargets := make([]string, 20)
		for j := range bigTargets {
			bigTargets[j] = strings.Repeat("x", 50)
		}
		childEnv := EffectiveEnvelope{
			Targets:         bigTargets,
			Roles:           []string{"read"},
			CanDelegate:     true,
			DelegationDepth: 100 - i,
			ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		}
		next, err := minter.MintDelegated(current, childEnv)
		if err != nil {
			lastErr = err
			break
		}
		current = next
	}

	if lastErr == nil {
		t.Fatal("expected size limit error after many delegations")
	}
	if !strings.Contains(lastErr.Error(), "token exceeds maximum size") {
		t.Fatalf("expected token size error, got: %v", lastErr)
	}
}

func TestMintRoot_EmptyDimensionsOmitted(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)

	env := EffectiveEnvelope{
		Targets:     []string{"dockerhost"},
		Roles:       []string{"read"},
		CanDelegate: false,
		ExpiresAt:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		// Services, Remotes, Methods are empty.
	}

	mac, err := minter.MintRoot("01JQEMPTY0000000000000000", "claude-empty", "urn:ephyr:agent:claude-empty", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	caveats := mac.Caveats()

	// Should have target and role.
	if !caveatsContain(caveats, "target IN [") {
		t.Fatal("missing target caveat")
	}
	if !caveatsContain(caveats, "role IN [") {
		t.Fatal("missing role caveat")
	}

	// Should NOT have service, remote, or method caveats.
	if caveatsContain(caveats, "service IN [") {
		t.Fatal("service caveat should not be present when empty")
	}
	if caveatsContain(caveats, "remote IN [") {
		t.Fatal("remote caveat should not be present when empty")
	}
	if caveatsContain(caveats, "method IN [") {
		t.Fatal("method caveat should not be present when empty")
	}
}
