package macaroon

import (
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestE2E_FullDelegationFlow exercises the complete mint-verify-delegate-revoke flow:
//  1. Create root key store + minter + verifier
//  2. Mint root macaroon with full envelope
//  3. Verify root -- check effective envelope matches
//  4. Mint delegated child with narrowed envelope
//  5. Verify child -- check envelope is narrowed
//  6. Mint grandchild with further narrowing
//  7. Verify grandchild -- check cumulative narrowing
//  8. Delete root key -- verify all fail
func TestE2E_FullDelegationFlow(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	// 1 + 2: Mint root with full envelope.
	rootEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog", "mandrake-rack"},
		Roles:           []string{"read", "operator", "admin"},
		Services:        []string{"github", "gitea", "portainer", "grafana"},
		Remotes:         []string{"demo-tools", "prod-tools"},
		Methods:         []string{"GET", "POST", "PUT", "DELETE"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	rootMac, err := minter.MintRoot("01E2EROOT0000000000000000", "claude-orchestrator", "ephyr:local:uid:1000", rootEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// 3: Verify root -- all dimensions should match.
	rootResult, err := verifier.Verify(rootMac)
	if err != nil {
		t.Fatalf("Verify root: %v", err)
	}
	sort.Strings(rootResult.Envelope.Targets)
	if len(rootResult.Envelope.Targets) != 3 {
		t.Fatalf("root targets count = %d, want 3", len(rootResult.Envelope.Targets))
	}
	if rootResult.Envelope.Targets[0] != "dockerhost" {
		t.Fatalf("root targets[0] = %q, want dockerhost", rootResult.Envelope.Targets[0])
	}
	sort.Strings(rootResult.Envelope.Roles)
	if len(rootResult.Envelope.Roles) != 3 {
		t.Fatalf("root roles count = %d, want 3", len(rootResult.Envelope.Roles))
	}
	sort.Strings(rootResult.Envelope.Services)
	if len(rootResult.Envelope.Services) != 4 {
		t.Fatalf("root services count = %d, want 4", len(rootResult.Envelope.Services))
	}
	sort.Strings(rootResult.Envelope.Remotes)
	if len(rootResult.Envelope.Remotes) != 2 {
		t.Fatalf("root remotes count = %d, want 2", len(rootResult.Envelope.Remotes))
	}
	if !rootResult.Envelope.CanDelegate {
		t.Fatal("root can_delegate should be true")
	}
	if rootResult.Envelope.DelegationDepth != 5 {
		t.Fatalf("root delegation_depth = %d, want 5", rootResult.Envelope.DelegationDepth)
	}
	if rootResult.Metadata.Agent != "claude-orchestrator" {
		t.Fatalf("root agent = %q, want claude-orchestrator", rootResult.Metadata.Agent)
	}
	if rootResult.Metadata.InitiatedBy != "ephyr:local:uid:1000" {
		t.Fatalf("root initiated_by = %q, want ephyr:local:uid:1000", rootResult.Metadata.InitiatedBy)
	}
	if rootResult.SigDigest == "" {
		t.Fatal("root sig_digest should not be empty")
	}

	// 4: Mint delegated child with narrowed envelope.
	childEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"github", "gitea"},
		Remotes:         []string{"demo-tools"},
		Methods:         []string{"GET", "POST"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}

	childMac, err := minter.MintDelegated(rootMac, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated (child): %v", err)
	}

	// 5: Verify child -- envelope should be narrowed.
	childResult, err := verifier.Verify(childMac)
	if err != nil {
		t.Fatalf("Verify child: %v", err)
	}
	sort.Strings(childResult.Envelope.Targets)
	if len(childResult.Envelope.Targets) != 2 {
		t.Fatalf("child targets = %v, want 2 targets", childResult.Envelope.Targets)
	}
	sort.Strings(childResult.Envelope.Roles)
	if len(childResult.Envelope.Roles) != 2 {
		t.Fatalf("child roles = %v, want 2 roles", childResult.Envelope.Roles)
	}
	sort.Strings(childResult.Envelope.Services)
	if len(childResult.Envelope.Services) != 2 {
		t.Fatalf("child services = %v, want 2 services", childResult.Envelope.Services)
	}
	if childResult.Envelope.DelegationDepth != 3 {
		t.Fatalf("child delegation_depth = %d, want 3", childResult.Envelope.DelegationDepth)
	}
	wantChildExpiry, _ := time.Parse(time.RFC3339, "2026-06-30T23:59:59Z")
	if !childResult.Envelope.ExpiresAt.Equal(wantChildExpiry) {
		t.Fatalf("child expires_at = %v, want %v", childResult.Envelope.ExpiresAt, wantChildExpiry)
	}
	// Agent should be inherited (first-value-wins).
	if childResult.Metadata.Agent != "claude-orchestrator" {
		t.Fatalf("child agent = %q, want claude-orchestrator", childResult.Metadata.Agent)
	}
	// Child must have different sig digest than root.
	if childResult.SigDigest == rootResult.SigDigest {
		t.Fatal("child and root should have different sig digests")
	}

	// 6: Mint grandchild with further narrowing.
	grandchildEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		Services:        []string{"github"},
		Methods:         []string{"GET"},
		CanDelegate:     false,
		ExpiresAt:       time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC),
	}

	grandchildMac, err := minter.MintDelegated(childMac, grandchildEnv)
	if err != nil {
		t.Fatalf("MintDelegated (grandchild): %v", err)
	}

	// 7: Verify grandchild -- cumulative narrowing.
	gcResult, err := verifier.Verify(grandchildMac)
	if err != nil {
		t.Fatalf("Verify grandchild: %v", err)
	}
	if len(gcResult.Envelope.Targets) != 1 || gcResult.Envelope.Targets[0] != "dockerhost" {
		t.Fatalf("grandchild targets = %v, want [dockerhost]", gcResult.Envelope.Targets)
	}
	if len(gcResult.Envelope.Roles) != 1 || gcResult.Envelope.Roles[0] != "read" {
		t.Fatalf("grandchild roles = %v, want [read]", gcResult.Envelope.Roles)
	}
	if len(gcResult.Envelope.Services) != 1 || gcResult.Envelope.Services[0] != "github" {
		t.Fatalf("grandchild services = %v, want [github]", gcResult.Envelope.Services)
	}
	if gcResult.Envelope.CanDelegate {
		t.Fatal("grandchild can_delegate should be false")
	}
	wantGCExpiry, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	if !gcResult.Envelope.ExpiresAt.Equal(wantGCExpiry) {
		t.Fatalf("grandchild expires_at = %v, want %v", gcResult.Envelope.ExpiresAt, wantGCExpiry)
	}
	if gcResult.Metadata.Agent != "claude-orchestrator" {
		t.Fatalf("grandchild agent = %q, want claude-orchestrator (first-value-wins)", gcResult.Metadata.Agent)
	}
	// All three should have unique sig digests.
	if gcResult.SigDigest == childResult.SigDigest {
		t.Fatal("grandchild and child should have different sig digests")
	}
	if gcResult.SigDigest == rootResult.SigDigest {
		t.Fatal("grandchild and root should have different sig digests")
	}

	// 8: Delete root key -- all three should fail verification.
	ks.Delete("01E2EROOT0000000000000000")

	_, err = verifier.Verify(rootMac)
	if err == nil {
		t.Fatal("root should fail verification after key deletion")
	}
	if !strings.Contains(err.Error(), "unknown root task") {
		t.Fatalf("expected unknown root task error for root, got: %v", err)
	}

	_, err = verifier.Verify(childMac)
	if err == nil {
		t.Fatal("child should fail verification after key deletion")
	}

	_, err = verifier.Verify(grandchildMac)
	if err == nil {
		t.Fatal("grandchild should fail verification after key deletion")
	}
}

// TestE2E_AttenuationNeverWidens verifies that delegation can never widen
// the effective envelope beyond the parent's capabilities.
func TestE2E_AttenuationNeverWidens(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	// Parent has only {host1}.
	parentEnv := EffectiveEnvelope{
		Targets:         []string{"host1"},
		Roles:           []string{"read"},
		Services:        []string{"grafana"},
		Methods:         []string{"GET"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	parent, err := minter.MintRoot("01E2EWIDEN0000000000000000", "claude-parent", "ephyr:local:uid:1000", parentEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Try to delegate with wider set: {host1, host2}.
	// The macaroon's HMAC chain will accept the caveats (they are appended),
	// but the reducer must produce the INTERSECTION which is {host1}.
	childEnv := EffectiveEnvelope{
		Targets:         []string{"host1", "host2"}, // wider than parent!
		Roles:           []string{"read", "operator"},
		Services:        []string{"grafana", "portainer"},
		Methods:         []string{"GET", "POST"},
		CanDelegate:     true,
		DelegationDepth: 2,
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

	// Intersection of {host1} and {host1, host2} = {host1}.
	if len(result.Envelope.Targets) != 1 || result.Envelope.Targets[0] != "host1" {
		t.Fatalf("child targets = %v, want [host1] (intersection, never wider)", result.Envelope.Targets)
	}

	// Intersection of {read} and {read, operator} = {read}.
	if len(result.Envelope.Roles) != 1 || result.Envelope.Roles[0] != "read" {
		t.Fatalf("child roles = %v, want [read]", result.Envelope.Roles)
	}

	// Intersection of {grafana} and {grafana, portainer} = {grafana}.
	if len(result.Envelope.Services) != 1 || result.Envelope.Services[0] != "grafana" {
		t.Fatalf("child services = %v, want [grafana]", result.Envelope.Services)
	}

	// Intersection of {GET} and {GET, POST} = {GET}.
	if len(result.Envelope.Methods) != 1 || result.Envelope.Methods[0] != "GET" {
		t.Fatalf("child methods = %v, want [GET]", result.Envelope.Methods)
	}
}

// TestE2E_AttenuationNeverWidens_DelegationDepth verifies that delegation
// depth can only decrease (minimum rule), never increase.
func TestE2E_AttenuationNeverWidens_DelegationDepth(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	parentEnv := EffectiveEnvelope{
		Targets:         []string{"host1"},
		Roles:           []string{"read"},
		CanDelegate:     true,
		DelegationDepth: 2,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	parent, err := minter.MintRoot("01E2EDEPTH0000000000000000", "agent", "ephyr:local:uid:1000", parentEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Try to delegate with deeper depth (5 > 2).
	childEnv := EffectiveEnvelope{
		Targets:         []string{"host1"},
		Roles:           []string{"read"},
		CanDelegate:     true,
		DelegationDepth: 5, // higher than parent's 2
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	child, err := minter.MintDelegated(parent, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	result, err := verifier.Verify(child)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// min(2, 5) = 2
	if result.Envelope.DelegationDepth != 2 {
		t.Fatalf("delegation_depth = %d, want 2 (minimum rule)", result.Envelope.DelegationDepth)
	}
}

// TestE2E_AttenuationNeverWidens_Expiry verifies that expiry can only
// move earlier (minimum rule), never later.
func TestE2E_AttenuationNeverWidens_Expiry(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	parentExpiry := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)
	parentEnv := EffectiveEnvelope{
		Targets:     []string{"host1"},
		Roles:       []string{"read"},
		CanDelegate: true,
		DelegationDepth: 3,
		ExpiresAt:   parentExpiry,
	}
	parent, err := minter.MintRoot("01E2EEXPIRY000000000000000", "agent", "ephyr:local:uid:1000", parentEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Try to delegate with LATER expiry.
	childEnv := EffectiveEnvelope{
		Targets:         []string{"host1"},
		Roles:           []string{"read"},
		CanDelegate:     false,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC), // later than parent
	}
	child, err := minter.MintDelegated(parent, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	result, err := verifier.Verify(child)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Effective expiry should be the earlier one (parent's).
	if !result.Envelope.ExpiresAt.Equal(parentExpiry) {
		t.Fatalf("expires_at = %v, want %v (earliest wins)", result.Envelope.ExpiresAt, parentExpiry)
	}
}

// TestE2E_AttenuationNeverWidens_CanDelegate verifies that delegation
// uses AND logic: once false, always false.
func TestE2E_AttenuationNeverWidens_CanDelegate(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	parentEnv := EffectiveEnvelope{
		Targets:         []string{"host1"},
		Roles:           []string{"read"},
		CanDelegate:     false, // parent says NO
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	parent, err := minter.MintRoot("01E2ECANDELFALSE0000000000", "agent", "ephyr:local:uid:1000", parentEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Try to re-enable delegation in child.
	childEnv := EffectiveEnvelope{
		Targets:         []string{"host1"},
		Roles:           []string{"read"},
		CanDelegate:     true, // trying to widen!
		DelegationDepth: 5,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	child, err := minter.MintDelegated(parent, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	result, err := verifier.Verify(child)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// AND: false AND true = false
	if result.Envelope.CanDelegate {
		t.Fatal("can_delegate should be false (false AND true = false)")
	}
}

// TestE2E_CascadingRevocationViaKeyDeletion verifies that deleting the root
// key invalidates the entire task tree (root, child, grandchild).
func TestE2E_CascadingRevocationViaKeyDeletion(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	rootEnv := EffectiveEnvelope{
		Targets:         []string{"A", "B", "C"},
		Roles:           []string{"read", "operator"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	root, err := minter.MintRoot("01E2EREVOKE000000000000000", "claude-root", "ephyr:local:uid:1000", rootEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	childEnv := EffectiveEnvelope{
		Targets:         []string{"A", "B"},
		Roles:           []string{"read"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}
	child, err := minter.MintDelegated(root, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated (child): %v", err)
	}

	grandchildEnv := EffectiveEnvelope{
		Targets:         []string{"A"},
		Roles:           []string{"read"},
		CanDelegate:     false,
		ExpiresAt:       time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC),
	}
	grandchild, err := minter.MintDelegated(child, grandchildEnv)
	if err != nil {
		t.Fatalf("MintDelegated (grandchild): %v", err)
	}

	// All three should verify before key deletion.
	if _, err := verifier.Verify(root); err != nil {
		t.Fatalf("root should verify before deletion: %v", err)
	}
	if _, err := verifier.Verify(child); err != nil {
		t.Fatalf("child should verify before deletion: %v", err)
	}
	if _, err := verifier.Verify(grandchild); err != nil {
		t.Fatalf("grandchild should verify before deletion: %v", err)
	}

	// Delete root key.
	ks.Delete("01E2EREVOKE000000000000000")

	// All three should now fail.
	_, err = verifier.Verify(root)
	if err == nil {
		t.Fatal("root should fail after key deletion")
	}
	if !strings.Contains(err.Error(), "unknown root task") {
		t.Fatalf("expected unknown root task error, got: %v", err)
	}

	_, err = verifier.Verify(child)
	if err == nil {
		t.Fatal("child should fail after key deletion")
	}

	_, err = verifier.Verify(grandchild)
	if err == nil {
		t.Fatal("grandchild should fail after key deletion")
	}
}

// TestE2E_SerializationRoundtrip verifies that macaroons survive
// marshal -> unmarshal -> verify for both root and delegated tokens.
func TestE2E_SerializationRoundtrip(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog"},
		Roles:           []string{"read", "operator"},
		Services:        []string{"github", "gitea"},
		Remotes:         []string{"demo-tools"},
		Methods:         []string{"GET", "POST"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	// Root roundtrip.
	rootMac, err := minter.MintRoot("01E2ESERIAL000000000000000", "claude-serial", "ephyr:local:uid:1000", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	rootData, err := rootMac.MarshalBinary()
	if err != nil {
		t.Fatalf("Marshal root: %v", err)
	}

	var rootDeserialized Macaroon
	if err := rootDeserialized.UnmarshalBinary(rootData); err != nil {
		t.Fatalf("Unmarshal root: %v", err)
	}

	rootResult, err := verifier.Verify(&rootDeserialized)
	if err != nil {
		t.Fatalf("Verify deserialized root: %v", err)
	}
	if rootResult.Metadata.Agent != "claude-serial" {
		t.Fatalf("deserialized root agent = %q, want claude-serial", rootResult.Metadata.Agent)
	}

	// Child roundtrip.
	childEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		CanDelegate:     false,
		ExpiresAt:       time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}
	childMac, err := minter.MintDelegated(rootMac, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	childData, err := childMac.MarshalBinary()
	if err != nil {
		t.Fatalf("Marshal child: %v", err)
	}

	var childDeserialized Macaroon
	if err := childDeserialized.UnmarshalBinary(childData); err != nil {
		t.Fatalf("Unmarshal child: %v", err)
	}

	childResult, err := verifier.Verify(&childDeserialized)
	if err != nil {
		t.Fatalf("Verify deserialized child: %v", err)
	}
	if len(childResult.Envelope.Targets) != 1 || childResult.Envelope.Targets[0] != "dockerhost" {
		t.Fatalf("deserialized child targets = %v, want [dockerhost]", childResult.Envelope.Targets)
	}
	if childResult.Envelope.CanDelegate {
		t.Fatal("deserialized child can_delegate should be false")
	}
	if childResult.Metadata.Agent != "claude-serial" {
		t.Fatalf("deserialized child agent = %q, want claude-serial (first-value-wins)", childResult.Metadata.Agent)
	}

	// Verify binary equality: marshal(original) == marshal(deserialized).
	rootData2, _ := rootDeserialized.MarshalBinary()
	if !bytes.Equal(rootData, rootData2) {
		t.Fatal("root binary should be identical after roundtrip")
	}
	childData2, _ := childDeserialized.MarshalBinary()
	if !bytes.Equal(childData, childData2) {
		t.Fatal("child binary should be identical after roundtrip")
	}
}

// TestE2E_TokenSizeGrowthAcrossDelegation tracks token size at each
// delegation level and verifies it grows monotonically while staying
// under MaxTokenSize for reasonable depth (5).
func TestE2E_TokenSizeGrowthAcrossDelegation(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	rootEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost", "hugoblog", "mandrake-rack"},
		Roles:           []string{"read", "operator", "admin"},
		Services:        []string{"github", "gitea", "portainer", "grafana"},
		Remotes:         []string{"demo-tools"},
		Methods:         []string{"GET", "POST", "PUT", "DELETE"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	rootMac, err := minter.MintRoot("01E2ESIZE00000000000000000", "claude-size", "ephyr:local:uid:1000", rootEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	rootData, err := rootMac.MarshalBinary()
	if err != nil {
		t.Fatalf("Marshal root: %v", err)
	}

	sizes := []int{len(rootData)}
	t.Logf("Depth 0 (root): %d bytes", len(rootData))

	current := rootMac
	for depth := 1; depth <= 5; depth++ {
		childEnv := EffectiveEnvelope{
			Targets:         rootEnv.Targets[:max(1, len(rootEnv.Targets)-depth)],
			Roles:           []string{"read"},
			Services:        rootEnv.Services[:max(1, len(rootEnv.Services)-depth)],
			Methods:         []string{"GET"},
			CanDelegate:     depth < 5,
			DelegationDepth: max(0, 5-depth),
			ExpiresAt:       time.Date(2026, time.Month(12-depth), 15, 23, 59, 59, 0, time.UTC),
		}

		child, err := minter.MintDelegated(current, childEnv)
		if err != nil {
			t.Fatalf("MintDelegated depth %d: %v", depth, err)
		}

		childData, err := child.MarshalBinary()
		if err != nil {
			t.Fatalf("Marshal depth %d: %v", depth, err)
		}

		sizes = append(sizes, len(childData))
		t.Logf("Depth %d: %d bytes (%d caveats)", depth, len(childData), len(child.Caveats()))

		// Verify the child is valid.
		_, err = verifier.Verify(child)
		if err != nil {
			t.Fatalf("Verify depth %d: %v", depth, err)
		}

		current = child
	}

	// Verify monotonic growth.
	for i := 1; i < len(sizes); i++ {
		if sizes[i] <= sizes[i-1] {
			t.Fatalf("token size did not grow at depth %d: %d <= %d", i, sizes[i], sizes[i-1])
		}
	}

	// Verify all sizes are under MaxTokenSize.
	for i, size := range sizes {
		if size > MaxTokenSize {
			t.Fatalf("token at depth %d exceeds MaxTokenSize: %d > %d", i, size, MaxTokenSize)
		}
	}

	t.Logf("Total growth: %d bytes (root) -> %d bytes (depth 5), ratio: %.2fx",
		sizes[0], sizes[len(sizes)-1], float64(sizes[len(sizes)-1])/float64(sizes[0]))
}

// TestE2E_DisjointSetsProduceEmptyIntersection verifies that delegating
// with completely disjoint sets results in empty effective sets.
func TestE2E_DisjointSetsProduceEmptyIntersection(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	parentEnv := EffectiveEnvelope{
		Targets:         []string{"A"},
		Roles:           []string{"read"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	parent, err := minter.MintRoot("01E2EDISJOINT00000000000000", "agent", "ephyr:local:uid:1000", parentEnv)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Delegate with completely disjoint target set.
	childEnv := EffectiveEnvelope{
		Targets:         []string{"B"}, // no overlap with {A}
		Roles:           []string{"admin"}, // no overlap with {read}
		CanDelegate:     false,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	child, err := minter.MintDelegated(parent, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	result, err := verifier.Verify(child)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Intersection should be empty.
	if len(result.Envelope.Targets) != 0 {
		t.Fatalf("targets = %v, want empty (disjoint intersection)", result.Envelope.Targets)
	}
	if len(result.Envelope.Roles) != 0 {
		t.Fatalf("roles = %v, want empty (disjoint intersection)", result.Envelope.Roles)
	}
}

// TestE2E_MultiLevelSigDigestUniqueness verifies that every macaroon
// in a delegation chain has a unique signature digest.
func TestE2E_MultiLevelSigDigestUniqueness(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:         []string{"h1", "h2", "h3", "h4", "h5"},
		Roles:           []string{"read", "operator"},
		CanDelegate:     true,
		DelegationDepth: 5,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	current, err := minter.MintRoot("01E2ESIGUNIQ00000000000000", "agent", "ephyr:local:uid:1000", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	digests := make(map[string]int) // digest -> depth

	result, err := verifier.Verify(current)
	if err != nil {
		t.Fatalf("Verify root: %v", err)
	}
	digests[result.SigDigest] = 0

	for depth := 1; depth <= 5; depth++ {
		childEnv := EffectiveEnvelope{
			Targets:         env.Targets[:max(1, len(env.Targets)-depth)],
			Roles:           []string{"read"},
			CanDelegate:     depth < 5,
			DelegationDepth: max(0, 5-depth),
			ExpiresAt:       time.Date(2026, time.Month(12-depth), 15, 23, 59, 59, 0, time.UTC),
		}
		child, err := minter.MintDelegated(current, childEnv)
		if err != nil {
			t.Fatalf("MintDelegated depth %d: %v", depth, err)
		}

		childResult, err := verifier.Verify(child)
		if err != nil {
			t.Fatalf("Verify depth %d: %v", depth, err)
		}

		if prevDepth, exists := digests[childResult.SigDigest]; exists {
			t.Fatalf("duplicate sig digest at depth %d (matches depth %d)", depth, prevDepth)
		}
		digests[childResult.SigDigest] = depth

		current = child
	}

	if len(digests) != 6 {
		t.Fatalf("expected 6 unique digests, got %d", len(digests))
	}
}

// TestE2E_TamperedCaveatFailsVerification ensures that modifying a caveat
// in a delegated macaroon breaks HMAC chain verification.
func TestE2E_TamperedCaveatFailsVerification(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		CanDelegate:     true,
		DelegationDepth: 3,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	root, err := minter.MintRoot("01E2ETAMPER000000000000000", "agent", "ephyr:local:uid:1000", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	childEnv := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		CanDelegate:     false,
		ExpiresAt:       time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}
	child, err := minter.MintDelegated(root, childEnv)
	if err != nil {
		t.Fatalf("MintDelegated: %v", err)
	}

	// Valid verification should succeed.
	_, err = verifier.Verify(child)
	if err != nil {
		t.Fatalf("Verify should succeed before tampering: %v", err)
	}

	// Tamper with a caveat: try to widen targets.
	child.caveats[len(child.caveats)-3] = []byte("target IN [dockerhost,hugoblog,mandrake-rack]")

	_, err = verifier.Verify(child)
	if err == nil {
		t.Fatal("verification should fail after tampering with caveat")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected invalid signature error, got: %v", err)
	}
}

// TestE2E_CaveatRemovalFailsVerification ensures that removing a caveat
// from a delegated macaroon breaks HMAC chain verification.
func TestE2E_CaveatRemovalFailsVerification(t *testing.T) {
	ks := NewRootKeyStore()
	minter := NewMinter(ks)
	verifier := NewVerifier(ks)

	env := EffectiveEnvelope{
		Targets:         []string{"dockerhost"},
		Roles:           []string{"read"},
		CanDelegate:     false,
		ExpiresAt:       time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	mac, err := minter.MintRoot("01E2EREMOVE000000000000000", "agent", "ephyr:local:uid:1000", env)
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	// Verify it works first.
	_, err = verifier.Verify(mac)
	if err != nil {
		t.Fatalf("Verify should succeed before removal: %v", err)
	}

	// Remove the can_delegate = false caveat (last one).
	mac.caveats = mac.caveats[:len(mac.caveats)-1]

	_, err = verifier.Verify(mac)
	if err == nil {
		t.Fatal("verification should fail after removing caveat")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected invalid signature error, got: %v", err)
	}
}

// max returns the larger of a or b (Go 1.21 has built-in max,
// but we include it for compatibility).
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
