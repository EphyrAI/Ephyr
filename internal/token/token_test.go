package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// --- Test helpers ---

// testSetup creates a root CA keypair, broker keypair, and a valid delegation cert.
func testSetup(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey, *DelegationCert) {
	t.Helper()

	// Root CA keypair (signer).
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}

	// Broker keypair.
	brokerPub, brokerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate broker key: %v", err)
	}

	// Create delegation cert.
	now := time.Now()
	payload := &DelegationPayload{
		CertID:    "deleg-test-001",
		BrokerID:  "broker-test",
		PublicKey:  []byte(brokerPub),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
	}

	cert, err := SignDelegationCert(payload, rootPriv)
	if err != nil {
		t.Fatalf("sign delegation cert: %v", err)
	}

	return rootPub, rootPriv, brokerPub, brokerPriv, cert
}

func testClaims() *TaskClaims {
	taskID := NewULID()
	return &TaskClaims{
		Subject:   "test-agent",
		Audience:  "clauth-broker",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		TokenID:   "cte_" + NewULID(),
		Task: TaskIdentity{
			ID:          taskID,
			RootID:      taskID,
			ParentID:    "",
			Depth:       0,
			Lineage:     []string{taskID},
			InitiatedBy: "clauth:local:uid:1000",
			Description: "test task",
		},
		Envelope: Envelope{
			Targets:  []string{"dockerhost", "hugoblog"},
			Roles:    []string{"operator"},
			Services: []string{"github", "gitea"},
			Remotes:  []string{"demo-tools"},
			Methods:  []string{"GET", "POST"},
		},
	}
}

// --- ULID Tests ---

func TestNewULID_Length(t *testing.T) {
	id := NewULID()
	if len(id) != 26 {
		t.Errorf("ULID length = %d, want 26", len(id))
	}
}

func TestNewULID_ValidChars(t *testing.T) {
	id := NewULID()
	if !ValidateULID(id) {
		t.Errorf("ULID %q failed validation", id)
	}
}

func TestNewULID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := NewULID()
		if seen[id] {
			t.Fatalf("duplicate ULID after %d iterations: %s", i, id)
		}
		seen[id] = true
	}
}

func TestNewULID_Monotonic(t *testing.T) {
	// ULIDs generated in sequence should be lexicographically ordered
	// (same millisecond may differ in random part, but timestamp prefix should be non-decreasing).
	prev := NewULID()
	for i := 0; i < 100; i++ {
		curr := NewULID()
		// Compare timestamp portion only (first 10 chars).
		if curr[:10] < prev[:10] {
			t.Errorf("ULID timestamp went backwards: %s < %s", curr[:10], prev[:10])
		}
		prev = curr
	}
}

func TestULIDTime_RoundTrip(t *testing.T) {
	before := time.Now().Truncate(time.Millisecond)
	id := NewULID()
	after := time.Now().Truncate(time.Millisecond).Add(time.Millisecond)

	extracted := ULIDTime(id)
	if extracted.Before(before) || extracted.After(after) {
		t.Errorf("extracted time %v not in range [%v, %v]", extracted, before, after)
	}
}

func TestULIDTime_InvalidLength(t *testing.T) {
	result := ULIDTime("short")
	if !result.IsZero() {
		t.Errorf("expected zero time for short ULID, got %v", result)
	}
}

func TestULIDTime_InvalidChars(t *testing.T) {
	result := ULIDTime("OOOOOOOOOO0000000000000000") // O is not in Crockford base32; invalid in timestamp portion
	if !result.IsZero() {
		t.Errorf("expected zero time for invalid chars, got %v", result)
	}
}

func TestValidateULID_Valid(t *testing.T) {
	if !ValidateULID(NewULID()) {
		t.Error("expected valid ULID to pass validation")
	}
}

func TestValidateULID_InvalidLength(t *testing.T) {
	if ValidateULID("ABC") {
		t.Error("expected short string to fail validation")
	}
}

func TestValidateULID_InvalidChars(t *testing.T) {
	// 'O' is not in Crockford Base32.
	if ValidateULID("OOOOOOOOOOOOOOOOOOOOOOOOOO") {
		t.Error("expected string with 'O' to fail validation")
	}
}

func TestValidateULID_Overflow(t *testing.T) {
	// First char > '7' would overflow 48-bit timestamp.
	if ValidateULID("80000000000000000000000000") {
		t.Error("expected overflow ULID to fail validation")
	}
}

// --- Envelope Tests ---

func TestEnvelope_ContainsTarget(t *testing.T) {
	e := Envelope{Targets: []string{"host-a", "host-b"}}
	if !e.ContainsTarget("host-a") {
		t.Error("expected host-a to be contained")
	}
	if e.ContainsTarget("host-c") {
		t.Error("expected host-c to NOT be contained")
	}
}

func TestEnvelope_ContainsTarget_Wildcard(t *testing.T) {
	e := Envelope{Targets: []string{"*"}}
	if !e.ContainsTarget("anything") {
		t.Error("expected wildcard to match anything")
	}
}

func TestEnvelope_ContainsRole(t *testing.T) {
	e := Envelope{Roles: []string{"admin", "read"}}
	if !e.ContainsRole("admin") {
		t.Error("expected admin to be contained")
	}
	if e.ContainsRole("operator") {
		t.Error("expected operator to NOT be contained")
	}
}

func TestEnvelope_ContainsService(t *testing.T) {
	e := Envelope{Services: []string{"github"}}
	if !e.ContainsService("github") {
		t.Error("expected github to be contained")
	}
	if e.ContainsService("gitea") {
		t.Error("expected gitea to NOT be contained")
	}
}

func TestEnvelope_ContainsMethod(t *testing.T) {
	e := Envelope{Methods: []string{"GET", "POST"}}
	if !e.ContainsMethod("GET") {
		t.Error("expected GET to be contained")
	}
	if e.ContainsMethod("DELETE") {
		t.Error("expected DELETE to NOT be contained")
	}
}

func TestEnvelope_ContainsRemote(t *testing.T) {
	e := Envelope{Remotes: []string{"demo-tools"}}
	if !e.ContainsRemote("demo-tools") {
		t.Error("expected demo-tools to be contained")
	}
	if e.ContainsRemote("other") {
		t.Error("expected other to NOT be contained")
	}
}

func TestEnvelope_IsSubsetOf_Equal(t *testing.T) {
	e := Envelope{
		Targets:  []string{"a", "b"},
		Roles:    []string{"read"},
		Services: []string{"s1"},
		Remotes:  []string{"r1"},
		Methods:  []string{"GET"},
	}
	if !e.IsSubsetOf(&e) {
		t.Error("envelope should be subset of itself")
	}
}

func TestEnvelope_IsSubsetOf_ProperSubset(t *testing.T) {
	parent := Envelope{
		Targets:  []string{"a", "b", "c"},
		Roles:    []string{"read", "operator"},
		Services: []string{"s1", "s2"},
		Remotes:  []string{"r1", "r2"},
		Methods:  []string{"GET", "POST", "DELETE"},
	}
	child := Envelope{
		Targets:  []string{"a"},
		Roles:    []string{"read"},
		Services: []string{"s1"},
		Remotes:  []string{"r1"},
		Methods:  []string{"GET"},
	}
	if !child.IsSubsetOf(&parent) {
		t.Error("child should be subset of parent")
	}
}

func TestEnvelope_IsSubsetOf_Disjoint(t *testing.T) {
	parent := Envelope{
		Targets:  []string{"a"},
		Roles:    []string{"read"},
		Services: []string{"s1"},
		Remotes:  []string{"r1"},
		Methods:  []string{"GET"},
	}
	child := Envelope{
		Targets:  []string{"x"},
		Roles:    []string{"admin"},
		Services: []string{"s2"},
		Remotes:  []string{"r2"},
		Methods:  []string{"DELETE"},
	}
	if child.IsSubsetOf(&parent) {
		t.Error("disjoint child should not be subset of parent")
	}
}

func TestEnvelope_IsSubsetOf_PartialOverlap(t *testing.T) {
	parent := Envelope{
		Targets:  []string{"a", "b"},
		Roles:    []string{"read"},
		Services: []string{"s1"},
		Remotes:  []string{"r1"},
		Methods:  []string{"GET"},
	}
	child := Envelope{
		Targets:  []string{"a", "c"}, // "c" is not in parent
		Roles:    []string{"read"},
		Services: []string{"s1"},
		Remotes:  []string{"r1"},
		Methods:  []string{"GET"},
	}
	if child.IsSubsetOf(&parent) {
		t.Error("partially overlapping child should not be subset of parent")
	}
}

func TestEnvelope_IsSubsetOf_ParentWildcard(t *testing.T) {
	parent := Envelope{
		Targets:  []string{"*"},
		Roles:    []string{"*"},
		Services: []string{"*"},
		Remotes:  []string{"*"},
		Methods:  []string{"*"},
	}
	child := Envelope{
		Targets:  []string{"a", "b", "c"},
		Roles:    []string{"admin", "operator"},
		Services: []string{"s1", "s2", "s3"},
		Remotes:  []string{"r1"},
		Methods:  []string{"GET", "POST", "DELETE"},
	}
	if !child.IsSubsetOf(&parent) {
		t.Error("any child should be subset of wildcard parent")
	}
}

func TestEnvelope_IsSubsetOf_ChildWildcard(t *testing.T) {
	parent := Envelope{
		Targets:  []string{"a", "b"},
		Roles:    []string{"read"},
		Services: []string{"s1"},
		Remotes:  []string{"r1"},
		Methods:  []string{"GET"},
	}
	child := Envelope{
		Targets:  []string{"*"}, // wildcard in child but not parent
		Roles:    []string{"read"},
		Services: []string{"s1"},
		Remotes:  []string{"r1"},
		Methods:  []string{"GET"},
	}
	if child.IsSubsetOf(&parent) {
		t.Error("child wildcard should not be subset of non-wildcard parent")
	}
}

func TestEnvelope_IsSubsetOf_Empty(t *testing.T) {
	parent := Envelope{
		Targets:  []string{"a"},
		Roles:    []string{"read"},
		Services: []string{"s1"},
		Remotes:  []string{"r1"},
		Methods:  []string{"GET"},
	}
	child := Envelope{} // all empty slices
	if !child.IsSubsetOf(&parent) {
		t.Error("empty child should be subset of any parent")
	}
}

// --- Delegation Tests ---

func TestDelegationCert_SignAndVerify(t *testing.T) {
	rootPub, rootPriv, _, _, _ := testSetup(t)

	brokerPub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	payload := &DelegationPayload{
		CertID:    "deleg-002",
		BrokerID:  "broker-2",
		PublicKey:  []byte(brokerPub2),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
	}

	cert, err := SignDelegationCert(payload, rootPriv)
	if err != nil {
		t.Fatalf("sign delegation cert: %v", err)
	}

	err = VerifyDelegationCert(cert, payload, rootPub)
	if err != nil {
		t.Fatalf("verify delegation cert: %v", err)
	}
}

func TestDelegationCert_WrongRootKey(t *testing.T) {
	_, rootPriv, _, _, _ := testSetup(t)

	// Different root key.
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	brokerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	payload := &DelegationPayload{
		CertID:    "deleg-003",
		BrokerID:  "broker-3",
		PublicKey:  []byte(brokerPub),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
	}

	cert, err := SignDelegationCert(payload, rootPriv)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyDelegationCert(cert, payload, wrongPub)
	if err == nil {
		t.Fatal("expected error verifying with wrong root key")
	}
	if !strings.Contains(err.Error(), "signature invalid") {
		t.Errorf("expected signature invalid error, got: %v", err)
	}
}

func TestDelegationCert_Expired(t *testing.T) {
	rootPub, rootPriv, _, _, _ := testSetup(t)

	brokerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create an already-expired cert.
	past := time.Now().Add(-2 * time.Hour)
	payload := &DelegationPayload{
		CertID:    "deleg-expired",
		BrokerID:  "broker-exp",
		PublicKey:  []byte(brokerPub),
		IssuedAt:  past.Unix(),
		ExpiresAt: past.Add(1 * time.Hour).Unix(), // expired 1 hour ago
	}

	cert, err := SignDelegationCert(payload, rootPriv)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyDelegationCert(cert, payload, rootPub)
	if err == nil {
		t.Fatal("expected error for expired cert")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expiration error, got: %v", err)
	}
}

func TestDelegationPayload_Deterministic(t *testing.T) {
	payload := DelegationPayload{
		CertID:    "test-id",
		BrokerID:  "test-broker",
		PublicKey:  []byte("fake-key-bytes-32-chars-long!!!!"),
		IssuedAt:  1000000,
		ExpiresAt: 2000000,
	}

	b1, err := CreateDelegationPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := CreateDelegationPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	if string(b1) != string(b2) {
		t.Error("delegation payload serialization is not deterministic")
	}
}

// --- Signing Tests ---

func TestIssuer_SignCTTE_RoundTrip(t *testing.T) {
	rootPub, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Token should have 3 dot-separated parts.
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Validate with the validator.
	validator := NewValidator(rootPub)
	validator.AddDelegation(cert)

	parsed, err := validator.ValidateCTTE(tokenStr)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	if parsed.Subject != "test-agent" {
		t.Errorf("subject = %q, want %q", parsed.Subject, "test-agent")
	}
	if parsed.Task.Description != "test task" {
		t.Errorf("task description = %q, want %q", parsed.Task.Description, "test task")
	}
	if len(parsed.Envelope.Targets) != 2 {
		t.Errorf("targets = %v, want 2 items", parsed.Envelope.Targets)
	}
}

func TestIssuer_NoDelegation(t *testing.T) {
	issuer := NewIssuer("broker-test")
	claims := testClaims()

	_, err := issuer.SignCTTE(claims)
	if err == nil {
		t.Fatal("expected error when no delegation set")
	}
}

func TestIssuer_NilClaims(t *testing.T) {
	_, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	_, err := issuer.SignCTTE(nil)
	if err == nil {
		t.Fatal("expected error for nil claims")
	}
}

func TestIssuer_DelegationKeyID(t *testing.T) {
	_, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	if issuer.DelegationKeyID() != "" {
		t.Error("expected empty key ID before delegation")
	}

	issuer.SetDelegation(brokerPriv, cert)
	if issuer.DelegationKeyID() != "deleg-test-001" {
		t.Errorf("key ID = %q, want %q", issuer.DelegationKeyID(), "deleg-test-001")
	}
}

func TestIssuer_AutoPopulatesFields(t *testing.T) {
	rootPub, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := &TaskClaims{
		Subject:   "agent-x",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Task: TaskIdentity{
			ID:     NewULID(),
			RootID: NewULID(),
		},
		Envelope: Envelope{
			Targets: []string{"*"},
			Roles:   []string{"*"},
		},
	}

	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	validator := NewValidator(rootPub)
	validator.AddDelegation(cert)

	parsed, err := validator.ValidateCTTE(tokenStr)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Check auto-populated fields.
	if parsed.Issuer != "clauth:broker-test" {
		t.Errorf("issuer = %q, want %q", parsed.Issuer, "clauth:broker-test")
	}
	if parsed.Audience != "clauth-broker" {
		t.Errorf("audience = %q, want %q", parsed.Audience, "clauth-broker")
	}
	if parsed.TokenID == "" {
		t.Error("expected auto-generated token ID")
	}
	if !strings.HasPrefix(parsed.TokenID, "cte_") {
		t.Errorf("token ID = %q, want prefix 'cte_'", parsed.TokenID)
	}
}

// --- Validation Tests ---

func TestValidator_InvalidJWTFormat(t *testing.T) {
	rootPub, _, _, _, _ := testSetup(t)
	validator := NewValidator(rootPub)

	_, err := validator.ValidateCTTE("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid JWT format")
	}
}

func TestValidator_InvalidBase64Header(t *testing.T) {
	rootPub, _, _, _, _ := testSetup(t)
	validator := NewValidator(rootPub)

	_, err := validator.ValidateCTTE("!!!.valid.valid")
	if err == nil {
		t.Fatal("expected error for invalid base64 header")
	}
}

func TestValidator_InvalidSignature(t *testing.T) {
	rootPub, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the signature.
	parts := strings.SplitN(tokenStr, ".", 3)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sigBytes[0] ^= 0xFF // flip a byte
	parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
	tamperedToken := strings.Join(parts, ".")

	validator := NewValidator(rootPub)
	validator.AddDelegation(cert)

	_, err = validator.ValidateCTTE(tamperedToken)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
	if !strings.Contains(err.Error(), "invalid token signature") {
		t.Errorf("expected signature error, got: %v", err)
	}
}

func TestValidator_TamperedPayload(t *testing.T) {
	rootPub, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the payload.
	parts := strings.SplitN(tokenStr, ".", 3)
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]interface{}
	json.Unmarshal(payloadJSON, &payload)
	payload["sub"] = "evil-agent"
	newPayloadJSON, _ := json.Marshal(payload)
	parts[1] = base64.RawURLEncoding.EncodeToString(newPayloadJSON)
	tamperedToken := strings.Join(parts, ".")

	validator := NewValidator(rootPub)
	validator.AddDelegation(cert)

	_, err = validator.ValidateCTTE(tamperedToken)
	if err == nil {
		t.Fatal("expected error for tampered payload")
	}
}

func TestValidator_ExpiredToken(t *testing.T) {
	rootPub, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	claims.ExpiresAt = time.Now().Add(-1 * time.Minute) // already expired

	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	validator := NewValidator(rootPub)
	validator.AddDelegation(cert)

	_, err = validator.ValidateCTTE(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "token expired") {
		t.Errorf("expected expiration error, got: %v", err)
	}
}

func TestValidator_WrongAudience(t *testing.T) {
	rootPub, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	claims.Audience = "wrong-audience"

	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	validator := NewValidator(rootPub)
	validator.AddDelegation(cert)

	_, err = validator.ValidateCTTE(tokenStr)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
	if !strings.Contains(err.Error(), "unexpected audience") {
		t.Errorf("expected audience error, got: %v", err)
	}
}

func TestValidator_ExpiredDelegationCert(t *testing.T) {
	rootPub, rootPriv, _, brokerPriv, _ := testSetup(t)

	// Create an already-expired delegation cert.
	brokerPub := brokerPriv.Public().(ed25519.PublicKey)
	past := time.Now().Add(-2 * time.Hour)
	payload := &DelegationPayload{
		CertID:    "deleg-expired",
		BrokerID:  "broker-test",
		PublicKey:  []byte(brokerPub),
		IssuedAt:  past.Unix(),
		ExpiresAt: past.Add(1 * time.Hour).Unix(), // expired 1h ago
	}
	expiredCert, err := SignDelegationCert(payload, rootPriv)
	if err != nil {
		t.Fatal(err)
	}

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, expiredCert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	validator := NewValidator(rootPub)
	validator.AddDelegation(expiredCert)

	_, err = validator.ValidateCTTE(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired delegation cert")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expiration error, got: %v", err)
	}
}

func TestValidator_WrongDelegationSigner(t *testing.T) {
	_, _, _, brokerPriv, _ := testSetup(t)

	// Different root key pair.
	wrongRootPub, wrongRootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Real root key (validator trusts this one).
	realRootPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	brokerPub := brokerPriv.Public().(ed25519.PublicKey)
	now := time.Now()
	payload := &DelegationPayload{
		CertID:    "deleg-wrong-signer",
		BrokerID:  "broker-test",
		PublicKey:  []byte(brokerPub),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
	}

	// Sign with wrong root key.
	cert, err := SignDelegationCert(payload, wrongRootPriv)
	if err != nil {
		t.Fatal(err)
	}

	_ = wrongRootPub // the cert was signed with this, but validator doesn't trust it

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Validator trusts realRootPub, but cert was signed by wrongRootPriv.
	validator := NewValidator(realRootPub)
	validator.AddDelegation(cert)

	_, err = validator.ValidateCTTE(tokenStr)
	if err == nil {
		t.Fatal("expected error for delegation cert signed by wrong key")
	}
	if !strings.Contains(err.Error(), "signature invalid") {
		t.Errorf("expected signature error, got: %v", err)
	}
}

func TestValidator_UnknownKeyID(t *testing.T) {
	rootPub, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Validator with no delegations registered.
	validator := NewValidator(rootPub)

	_, err = validator.ValidateCTTE(tokenStr)
	if err == nil {
		t.Fatal("expected error for unknown key ID")
	}
	if !strings.Contains(err.Error(), "unknown delegation key ID") {
		t.Errorf("expected unknown key ID error, got: %v", err)
	}
}

func TestValidator_UnsupportedAlgorithm(t *testing.T) {
	rootPub, _, _, _, cert := testSetup(t)

	// Craft a token with wrong algorithm.
	header := jwtHeader{Algorithm: "RS256", Type: string(TokenTypeCTTE), KeyID: cert.ID}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte("{}"))
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))
	tokenStr := headerB64 + "." + payloadB64 + "." + sigB64

	validator := NewValidator(rootPub)
	validator.AddDelegation(cert)

	_, err := validator.ValidateCTTE(tokenStr)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("expected algorithm error, got: %v", err)
	}
}

func TestValidator_WrongTokenType(t *testing.T) {
	rootPub, _, _, _, cert := testSetup(t)

	// Craft a token with wrong type.
	header := jwtHeader{Algorithm: "EdDSA", Type: "CTT-D", KeyID: cert.ID}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte("{}"))
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))
	tokenStr := headerB64 + "." + payloadB64 + "." + sigB64

	validator := NewValidator(rootPub)
	validator.AddDelegation(cert)

	_, err := validator.ValidateCTTE(tokenStr)
	if err == nil {
		t.Fatal("expected error for wrong token type")
	}
	if !strings.Contains(err.Error(), "unexpected token type") {
		t.Errorf("expected token type error, got: %v", err)
	}
}

// --- ParseUnverified Tests ---

func TestParseUnverified_ValidToken(t *testing.T) {
	_, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseUnverified(tokenStr)
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}

	if parsed.Subject != "test-agent" {
		t.Errorf("subject = %q, want %q", parsed.Subject, "test-agent")
	}
}

func TestParseUnverified_TamperedToken(t *testing.T) {
	_, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with signature -- ParseUnverified should still work.
	parts := strings.SplitN(tokenStr, ".", 3)
	parts[2] = "AAAA" // garbage signature
	tampered := strings.Join(parts, ".")

	parsed, err := ParseUnverified(tampered)
	if err != nil {
		t.Fatalf("parse unverified should work even with bad sig: %v", err)
	}
	if parsed.Subject != "test-agent" {
		t.Errorf("subject = %q, want %q", parsed.Subject, "test-agent")
	}
}

func TestParseUnverified_InvalidFormat(t *testing.T) {
	_, err := ParseUnverified("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestParseUnverified_InvalidBase64Payload(t *testing.T) {
	_, err := ParseUnverified("valid." + "!!!" + ".valid")
	if err == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

// --- Key Rotation Tests ---

func TestIssuer_KeyRotation(t *testing.T) {
	rootPub, rootPriv, _, brokerPriv1, cert1 := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv1, cert1)

	// Sign a token with key 1.
	claims1 := testClaims()
	token1, err := issuer.SignCTTE(claims1)
	if err != nil {
		t.Fatal(err)
	}

	// Generate new broker key and delegation cert.
	brokerPub2, brokerPriv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	payload2 := &DelegationPayload{
		CertID:    "deleg-test-002",
		BrokerID:  "broker-test",
		PublicKey:  []byte(brokerPub2),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
	}
	cert2, err := SignDelegationCert(payload2, rootPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate key.
	issuer.SetDelegation(brokerPriv2, cert2)

	// Sign a token with key 2.
	claims2 := testClaims()
	token2, err := issuer.SignCTTE(claims2)
	if err != nil {
		t.Fatal(err)
	}

	// Validator with both delegations should validate both.
	validator := NewValidator(rootPub)
	validator.AddDelegation(cert1)
	validator.AddDelegation(cert2)

	parsed1, err := validator.ValidateCTTE(token1)
	if err != nil {
		t.Fatalf("validate token1 after rotation: %v", err)
	}
	if parsed1.Subject != "test-agent" {
		t.Error("token1 subject mismatch")
	}

	parsed2, err := validator.ValidateCTTE(token2)
	if err != nil {
		t.Fatalf("validate token2 after rotation: %v", err)
	}
	if parsed2.Subject != "test-agent" {
		t.Error("token2 subject mismatch")
	}

	// Key IDs should differ.
	parts1 := strings.SplitN(token1, ".", 3)
	parts2 := strings.SplitN(token2, ".", 3)
	h1, _ := base64.RawURLEncoding.DecodeString(parts1[0])
	h2, _ := base64.RawURLEncoding.DecodeString(parts2[0])
	var hdr1, hdr2 jwtHeader
	json.Unmarshal(h1, &hdr1)
	json.Unmarshal(h2, &hdr2)
	if hdr1.KeyID == hdr2.KeyID {
		t.Error("expected different key IDs after rotation")
	}
}

func TestIssuer_RotationOldTokenFailsWithoutOldDelegation(t *testing.T) {
	rootPub, rootPriv, _, brokerPriv1, cert1 := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv1, cert1)

	claims := testClaims()
	token1, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate to new key.
	brokerPub2, brokerPriv2, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	payload2 := &DelegationPayload{
		CertID:   "deleg-test-003",
		BrokerID: "broker-test",
		PublicKey: []byte(brokerPub2),
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
	}
	cert2, _ := SignDelegationCert(payload2, rootPriv)
	issuer.SetDelegation(brokerPriv2, cert2)

	// Validator only knows about cert2 (not cert1).
	validator := NewValidator(rootPub)
	validator.AddDelegation(cert2)

	_, err = validator.ValidateCTTE(token1)
	if err == nil {
		t.Fatal("expected error: old token should fail without old delegation cert")
	}
	if !strings.Contains(err.Error(), "unknown delegation key ID") {
		t.Errorf("expected unknown key ID error, got: %v", err)
	}
}

// --- JWT Structure Tests ---

func TestJWT_HeaderStructure(t *testing.T) {
	_, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.SplitN(tokenStr, ".", 3)
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	json.Unmarshal(headerJSON, &header)

	if header["alg"] != "EdDSA" {
		t.Errorf("alg = %v, want EdDSA", header["alg"])
	}
	if header["typ"] != "CTT-E" {
		t.Errorf("typ = %v, want CTT-E", header["typ"])
	}
	if header["kid"] != "deleg-test-001" {
		t.Errorf("kid = %v, want deleg-test-001", header["kid"])
	}
}

func TestJWT_PayloadTimestampsAreUnix(t *testing.T) {
	_, _, _, brokerPriv, cert := testSetup(t)

	issuer := NewIssuer("broker-test")
	issuer.SetDelegation(brokerPriv, cert)

	claims := testClaims()
	tokenStr, err := issuer.SignCTTE(claims)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.SplitN(tokenStr, ".", 3)
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]interface{}
	json.Unmarshal(payloadJSON, &payload)

	// iat and exp should be numbers (Unix timestamps), not strings.
	iat, ok := payload["iat"].(float64) // JSON numbers decode as float64
	if !ok {
		t.Fatalf("iat is not a number: %T", payload["iat"])
	}
	if iat < 1e9 {
		t.Errorf("iat seems too small for a Unix timestamp: %v", iat)
	}

	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatalf("exp is not a number: %T", payload["exp"])
	}
	if exp <= iat {
		t.Errorf("exp (%v) should be after iat (%v)", exp, iat)
	}
}

// --- Edge Case Tests ---

func TestValidator_AddNilDelegation(t *testing.T) {
	rootPub, _, _, _, _ := testSetup(t)
	validator := NewValidator(rootPub)
	// Should not panic.
	validator.AddDelegation(nil)
}

func TestDelegationCert_NilInputs(t *testing.T) {
	rootPub, _, _, _, _ := testSetup(t)

	err := VerifyDelegationCert(nil, nil, rootPub)
	if err == nil {
		t.Fatal("expected error for nil cert")
	}
}

func TestEnvelope_EmptySlices(t *testing.T) {
	e := Envelope{}
	if e.ContainsTarget("anything") {
		t.Error("empty targets should not contain anything")
	}
	if e.ContainsRole("anything") {
		t.Error("empty roles should not contain anything")
	}
	if e.ContainsService("anything") {
		t.Error("empty services should not contain anything")
	}
	if e.ContainsMethod("anything") {
		t.Error("empty methods should not contain anything")
	}
	if e.ContainsRemote("anything") {
		t.Error("empty remotes should not contain anything")
	}
}
