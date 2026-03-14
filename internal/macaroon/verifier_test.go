package macaroon

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestVerify_ValidRoot(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"github"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	mac, err := minter.MintRoot("01JQVALID0000000000000000", "claude-v", "urn:ephyr:agent:claude-v", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	result, err := verifier.Verify(mac)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Metadata.Agent != "claude-v" {
		t.Fatalf("agent = %q, want %q", result.Metadata.Agent, "claude-v")
	}
	if result.Metadata.InitiatedBy != "urn:ephyr:agent:claude-v" {
		t.Fatalf("initiated_by = %q", result.Metadata.InitiatedBy)
	}
	if !result.Envelope.CanDelegate {
		t.Fatal("can_delegate should be true")
	}
	if result.Envelope.DelegationDepth != 3 {
		t.Fatalf("delegation_depth = %d, want 3", result.Envelope.DelegationDepth)
	}
	if result.SigDigest == "" {
		t.Fatal("sig_digest should not be empty")
	}
}

func TestVerify_ValidDelegated(t *testing.T) {
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

	parent, err := minter.MintRoot("01JQDEL0000000000000000000", "claude-p", "urn:ephyr:agent:claude-p", parentEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	childEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		CanDelegate:     false,
		ExpiresAt:       time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}

	child, err := minter.MintDelegated(parent, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	result, err := verifier.Verify(child)
	if err != nil {
		t.Fatalf("Verify child: %v", err)
	}

	// Envelope should be narrowed.
	if len(result.Envelope.Targets) != 1 || result.Envelope.Targets[0] != "dockerhost" {
		t.Fatalf("targets = %v, want [dockerhost]", result.Envelope.Targets)
	}
	if len(result.Envelope.Roles) != 1 || result.Envelope.Roles[0] != "read" {
		t.Fatalf("roles = %v, want [read]", result.Envelope.Roles)
	}
	if result.Envelope.CanDelegate {
		t.Fatal("child can_delegate should be false")
	}

	// Expiry should be the earlier one.
	wantExpiry, _ := time.Parse(time.RFC3339, "2026-06-30T23:59:59Z")
	if !result.Envelope.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expires_at = %v, want %v", result.Envelope.ExpiresAt, wantExpiry)
	}
}

func TestVerify_WrongKeyVerifier(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)

	env := EffectiveEnvelope{
		Targets:     []string{"dockerhost"},
		Roles:       []string{"read"},
		CanDelegate: false,
		ExpiresAt:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	mac, err := minter.MintRoot("01JQWRONG0000000000000000", "claude-w", "urn:ephyr:agent:claude-w", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Create a separate key store (different keys).
	ks2 := NewRootKeyStore()
	_, _ = ks2.Generate("01JQWRONG0000000000000000", time.Now().Add(time.Hour))

	verifier2 := NewVerifier(ks2)
	_, err = verifier2.Verify(mac)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected invalid signature error, got: %v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:     []string{"dockerhost"},
		Roles:       []string{"read"},
		CanDelegate: false,
		ExpiresAt:   time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), // in the past
	}

	mac, err := minter.MintRoot("01JQEXPIRED000000000000000", "claude-e", "urn:ephyr:agent:claude-e", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	_, err = verifier.Verify(mac)
	if err != ErrExpired {
		t.Fatalf("expected ErrExpired, got: %v", err)
	}
}

func TestVerify_DeletedKey(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:     []string{"dockerhost"},
		Roles:       []string{"read"},
		CanDelegate: false,
		ExpiresAt:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	mac, err := minter.MintRoot("01JQDELETED00000000000000", "claude-d", "urn:ephyr:agent:claude-d", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Delete the key.
	ks.Delete("01JQDELETED00000000000000")

	_, err = verifier.Verify(mac)
	if err == nil {
		t.Fatal("expected error after key deletion")
	}
	if !strings.Contains(err.Error(), "unknown root task") {
		t.Fatalf("expected unknown root task error, got: %v", err)
	}
}

func TestVerify_SigDigest(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:     []string{"dockerhost"},
		Roles:       []string{"read"},
		CanDelegate: false,
		ExpiresAt:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	mac, err := minter.MintRoot("01JQDIGEST0000000000000000", "claude-s", "urn:ephyr:agent:claude-s", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	result, err := verifier.Verify(mac)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Compute expected digest manually.
	sig := mac.Signature()
	hash := sha256.Sum256(sig[:])
	expected := hex.EncodeToString(hash[:])

	if result.SigDigest != expected {
		t.Fatalf("sig_digest = %q, want %q", result.SigDigest, expected)
	}

	// Digest should be 64 hex chars (SHA-256).
	if len(result.SigDigest) != 64 {
		t.Fatalf("sig_digest length = %d, want 64", len(result.SigDigest))
	}
}

func TestVerify_DelegationChain3Deep(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	// Root: broad access.
	rootEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog", "mandrake-rack"},
		Roles:           []string{"read", "operator", "admin"},
		Services:        []string{"github", "gitea", "portainer"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	root, err := minter.MintRoot("01JQCHAIN3000000000000000", "claude-orchestrator", "urn:ephyr:agent:claude-orchestrator", rootEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Child: narrower.
	childEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"github"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}

	child, err := minter.MintDelegated(root, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated (child): %v", err)
	}

	// Grandchild: narrowest.
	grandchildEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		CanDelegate:     false,
		DelegationDepth: 0,
		ExpiresAt:       time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC),
	}

	grandchild, err := minter.MintDelegated(child, grandchildEnv)
	if err != nil {
		t.Fatalf("MintDelegated (grandchild): %v", err)
	}

	// Verify all three.
	rootResult, err := verifier.Verify(root)
	if err != nil {
		t.Fatalf("Verify root: %v", err)
	}
	sort.Strings(rootResult.Envelope.Targets)
	if len(rootResult.Envelope.Targets) != 3 {
		t.Fatalf("root targets = %v, want 3 targets", rootResult.Envelope.Targets)
	}

	childResult, err := verifier.Verify(child)
	if err != nil {
		t.Fatalf("Verify child: %v", err)
	}
	sort.Strings(childResult.Envelope.Targets)
	if len(childResult.Envelope.Targets) != 2 {
		t.Fatalf("child targets = %v, want 2 targets", childResult.Envelope.Targets)
	}

	grandchildResult, err := verifier.Verify(grandchild)
	if err != nil {
		t.Fatalf("Verify grandchild: %v", err)
	}
	if len(grandchildResult.Envelope.Targets) != 1 || grandchildResult.Envelope.Targets[0] != "dockerhost" {
		t.Fatalf("grandchild targets = %v, want [dockerhost]", grandchildResult.Envelope.Targets)
	}
	if grandchildResult.Envelope.CanDelegate {
		t.Fatal("grandchild can_delegate should be false")
	}

	// All should share the same agent (first-value-wins).
	if grandchildResult.Metadata.Agent != "claude-orchestrator" {
		t.Fatalf("grandchild agent = %q, want claude-orchestrator", grandchildResult.Metadata.Agent)
	}

	// Each should have a unique sig digest.
	if rootResult.SigDigest == childResult.SigDigest {
		t.Fatal("root and child should have different sig digests")
	}
	if childResult.SigDigest == grandchildResult.SigDigest {
		t.Fatal("child and grandchild should have different sig digests")
	}
}

func TestVerify_AttenuationNarrows(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	parentEnv := EffectiveEnvelope{
		Targets:         []string{"A", "B", "C"},
		Roles:           []string{"read", "operator"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	parent, err := minter.MintRoot("01JQATTEN0000000000000000", "claude-att", "urn:ephyr:agent:claude-att", parentEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Child requests only target "A".
	childEnv := EffectiveEnvelope{
		Targets:         []string{"A"},
		Roles:           []string{"read"},
		CanDelegate:     false,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	child, err := minter.MintDelegated(parent, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	result, err := verifier.Verify(child)
	if err != nil {
		t.Fatalf("Verify child: %v", err)
	}

	// Intersection of {A,B,C} and {A} = {A}.
	if len(result.Envelope.Targets) != 1 || result.Envelope.Targets[0] != "A" {
		t.Fatalf("child targets = %v, want [A]", result.Envelope.Targets)
	}

	// Intersection of {read,operator} and {read} = {read}.
	if len(result.Envelope.Roles) != 1 || result.Envelope.Roles[0] != "read" {
		t.Fatalf("child roles = %v, want [read]", result.Envelope.Roles)
	}

	// can_delegate: true AND false = false.
	if result.Envelope.CanDelegate {
		t.Fatal("child can_delegate should be false")
	}
}

func BenchmarkVerify(b *testing.B) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog", "mandrake-rack"},
		Roles:           []string{"read", "operator", "admin"},
		Services:        []string{"github", "gitea", "portainer"},
		Remotes:         []string{"demo-tools"},
		Methods:         []string{"GET", "POST", "PUT", "DELETE"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	mac, err := minter.MintRoot("01JQBENCH0000000000000000", "claude-bench", "urn:ephyr:agent:claude-bench", env)
	if err != nil {
		b.Fatalf("MintRoot: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := verifier.Verify(mac)
		if err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}
