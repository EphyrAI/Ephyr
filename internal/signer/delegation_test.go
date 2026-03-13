package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// testCA creates a CA from a freshly generated Ed25519 keypair.
func testCA(t *testing.T) *CA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ca, err := NewCAFromKey(priv)
	if err != nil {
		t.Fatalf("new ca from key: %v", err)
	}
	return ca
}

// testBrokerKey generates a fresh Ed25519 keypair for use as a broker key.
func testBrokerKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate broker key: %v", err)
	}
	return pub, priv
}

func TestSignDelegation_Success(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	result, err := SignDelegation(ca, brokerPub, "broker-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	if result.CertID == "" {
		t.Error("CertID is empty")
	}
	if len(result.CertID) != 32 { // 16 bytes hex-encoded
		t.Errorf("CertID length = %d, want 32", len(result.CertID))
	}
	if len(result.Signature) != ed25519.SignatureSize {
		t.Errorf("Signature length = %d, want %d", len(result.Signature), ed25519.SignatureSize)
	}
	if result.IssuedAt.IsZero() {
		t.Error("IssuedAt is zero")
	}
	if result.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}
	if result.ExpiresAt.Before(result.IssuedAt) {
		t.Error("ExpiresAt before IssuedAt")
	}
}

func TestSignDelegation_VerifySignature(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	result, err := SignDelegation(ca, brokerPub, "broker-verify", 2*time.Hour)
	if err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	// Reconstruct the canonical payload and verify the signature.
	ok := VerifyDelegation(
		ca.RawPublicKey(),
		result.CertID,
		"broker-verify",
		brokerPub,
		result.IssuedAt,
		result.ExpiresAt,
		result.Signature,
	)
	if !ok {
		t.Error("signature verification failed")
	}
}

func TestSignDelegation_TamperedPayload_BrokerID(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	result, err := SignDelegation(ca, brokerPub, "broker-original", 1*time.Hour)
	if err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	// Tamper: use wrong broker ID.
	ok := VerifyDelegation(
		ca.RawPublicKey(),
		result.CertID,
		"broker-tampered",
		brokerPub,
		result.IssuedAt,
		result.ExpiresAt,
		result.Signature,
	)
	if ok {
		t.Error("verification should fail with tampered broker_id")
	}
}

func TestSignDelegation_TamperedPayload_PublicKey(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)
	otherPub, _ := testBrokerKey(t)

	result, err := SignDelegation(ca, brokerPub, "broker-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	// Tamper: use different broker public key.
	ok := VerifyDelegation(
		ca.RawPublicKey(),
		result.CertID,
		"broker-1",
		otherPub,
		result.IssuedAt,
		result.ExpiresAt,
		result.Signature,
	)
	if ok {
		t.Error("verification should fail with tampered public key")
	}
}

func TestSignDelegation_TamperedPayload_CertID(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	result, err := SignDelegation(ca, brokerPub, "broker-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	// Tamper: use different cert ID.
	ok := VerifyDelegation(
		ca.RawPublicKey(),
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"broker-1",
		brokerPub,
		result.IssuedAt,
		result.ExpiresAt,
		result.Signature,
	)
	if ok {
		t.Error("verification should fail with tampered cert_id")
	}
}

func TestSignDelegation_TamperedPayload_Timestamps(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	result, err := SignDelegation(ca, brokerPub, "broker-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	// Tamper: shift issued_at by 1 second.
	ok := VerifyDelegation(
		ca.RawPublicKey(),
		result.CertID,
		"broker-1",
		brokerPub,
		result.IssuedAt.Add(1*time.Second),
		result.ExpiresAt,
		result.Signature,
	)
	if ok {
		t.Error("verification should fail with tampered issued_at")
	}

	// Tamper: shift expires_at by 1 second.
	ok = VerifyDelegation(
		ca.RawPublicKey(),
		result.CertID,
		"broker-1",
		brokerPub,
		result.IssuedAt,
		result.ExpiresAt.Add(1*time.Second),
		result.Signature,
	)
	if ok {
		t.Error("verification should fail with tampered expires_at")
	}
}

func TestSignDelegation_WrongVerificationKey(t *testing.T) {
	ca := testCA(t)
	otherCA := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	result, err := SignDelegation(ca, brokerPub, "broker-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	// Verify with wrong CA public key.
	ok := VerifyDelegation(
		otherCA.RawPublicKey(),
		result.CertID,
		"broker-1",
		brokerPub,
		result.IssuedAt,
		result.ExpiresAt,
		result.Signature,
	)
	if ok {
		t.Error("verification should fail with wrong root public key")
	}
}

func TestSignDelegation_TTL_TooLarge(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	_, err := SignDelegation(ca, brokerPub, "broker-1", 25*time.Hour)
	if err == nil {
		t.Error("expected error for TTL > 24h")
	}
}

func TestSignDelegation_TTL_Zero(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	_, err := SignDelegation(ca, brokerPub, "broker-1", 0)
	if err == nil {
		t.Error("expected error for TTL = 0")
	}
}

func TestSignDelegation_TTL_Negative(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	_, err := SignDelegation(ca, brokerPub, "broker-1", -1*time.Hour)
	if err == nil {
		t.Error("expected error for negative TTL")
	}
}

func TestSignDelegation_TTL_Exactly24h(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	result, err := SignDelegation(ca, brokerPub, "broker-1", 24*time.Hour)
	if err != nil {
		t.Fatalf("24h TTL should be allowed: %v", err)
	}
	if result.CertID == "" {
		t.Error("CertID is empty for 24h TTL")
	}
}

func TestSignDelegation_EmptyBrokerID(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	_, err := SignDelegation(ca, brokerPub, "", 1*time.Hour)
	if err == nil {
		t.Error("expected error for empty broker_id")
	}
}

func TestSignDelegation_InvalidPubKeySize(t *testing.T) {
	ca := testCA(t)

	// 16 bytes instead of 32.
	shortKey := make([]byte, 16)
	_, err := SignDelegation(ca, shortKey, "broker-1", 1*time.Hour)
	if err == nil {
		t.Error("expected error for short public key")
	}

	// 64 bytes instead of 32.
	longKey := make([]byte, 64)
	_, err = SignDelegation(ca, longKey, "broker-1", 1*time.Hour)
	if err == nil {
		t.Error("expected error for long public key")
	}
}

func TestBuildCanonicalPayload_Deterministic(t *testing.T) {
	brokerPub, _ := testBrokerKey(t)
	issuedAt := time.Unix(1700000000, 0)
	expiresAt := time.Unix(1700003600, 0)

	p1, err := BuildCanonicalPayload("cert-abc", "broker-1", brokerPub, issuedAt, expiresAt)
	if err != nil {
		t.Fatalf("BuildCanonicalPayload: %v", err)
	}

	p2, err := BuildCanonicalPayload("cert-abc", "broker-1", brokerPub, issuedAt, expiresAt)
	if err != nil {
		t.Fatalf("BuildCanonicalPayload: %v", err)
	}

	if string(p1) != string(p2) {
		t.Errorf("payloads differ:\n  p1: %s\n  p2: %s", p1, p2)
	}
}

func TestBuildCanonicalPayload_JSONStructure(t *testing.T) {
	brokerPub, _ := testBrokerKey(t)
	issuedAt := time.Unix(1700000000, 0)
	expiresAt := time.Unix(1700003600, 0)

	payload, err := BuildCanonicalPayload("cert-123", "broker-x", brokerPub, issuedAt, expiresAt)
	if err != nil {
		t.Fatalf("BuildCanonicalPayload: %v", err)
	}

	// Verify it's valid JSON with expected fields.
	var parsed map[string]interface{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}

	expectedKeys := []string{"cert_id", "broker_id", "public_key", "issued_at", "expires_at"}
	for _, key := range expectedKeys {
		if _, ok := parsed[key]; !ok {
			t.Errorf("missing key %q in payload", key)
		}
	}
	if len(parsed) != len(expectedKeys) {
		t.Errorf("unexpected number of keys: got %d, want %d", len(parsed), len(expectedKeys))
	}

	if parsed["cert_id"] != "cert-123" {
		t.Errorf("cert_id = %v, want cert-123", parsed["cert_id"])
	}
	if parsed["broker_id"] != "broker-x" {
		t.Errorf("broker_id = %v, want broker-x", parsed["broker_id"])
	}
	if parsed["public_key"] != base64.StdEncoding.EncodeToString(brokerPub) {
		t.Error("public_key mismatch")
	}
	// JSON numbers are float64.
	if parsed["issued_at"].(float64) != 1700000000 {
		t.Errorf("issued_at = %v, want 1700000000", parsed["issued_at"])
	}
	if parsed["expires_at"].(float64) != 1700003600 {
		t.Errorf("expires_at = %v, want 1700003600", parsed["expires_at"])
	}
}

func TestBuildCanonicalPayload_Base64PublicKey(t *testing.T) {
	brokerPub, _ := testBrokerKey(t)
	issuedAt := time.Unix(1700000000, 0)
	expiresAt := time.Unix(1700003600, 0)

	payload, err := BuildCanonicalPayload("cert-b64", "broker-1", brokerPub, issuedAt, expiresAt)
	if err != nil {
		t.Fatalf("BuildCanonicalPayload: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify the public key field is valid base64 that decodes to 32 bytes.
	pkStr, ok := parsed["public_key"].(string)
	if !ok {
		t.Fatal("public_key is not a string")
	}

	decoded, err := base64.StdEncoding.DecodeString(pkStr)
	if err != nil {
		t.Fatalf("base64 decode public_key: %v", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		t.Errorf("decoded key size = %d, want %d", len(decoded), ed25519.PublicKeySize)
	}
}

func TestGenerateCertID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := GenerateCertID()
		if err != nil {
			t.Fatalf("GenerateCertID: %v", err)
		}
		if len(id) != 32 {
			t.Errorf("cert ID length = %d, want 32", len(id))
		}
		if seen[id] {
			t.Errorf("duplicate cert ID: %s", id)
		}
		seen[id] = true
	}
}

func TestGenerateCertID_HexEncoded(t *testing.T) {
	id, err := GenerateCertID()
	if err != nil {
		t.Fatalf("GenerateCertID: %v", err)
	}

	// Verify all characters are valid hex.
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character %q in cert ID %q", c, id)
		}
	}
}

func TestCAKeyMethods(t *testing.T) {
	ca := testCA(t)

	rawPriv := ca.RawPrivateKey()
	rawPub := ca.RawPublicKey()

	if len(rawPriv) != ed25519.PrivateKeySize {
		t.Errorf("RawPrivateKey size = %d, want %d", len(rawPriv), ed25519.PrivateKeySize)
	}
	if len(rawPub) != ed25519.PublicKeySize {
		t.Errorf("RawPublicKey size = %d, want %d", len(rawPub), ed25519.PublicKeySize)
	}

	// Verify public key matches private key.
	derivedPub := rawPriv.Public().(ed25519.PublicKey)
	if !derivedPub.Equal(rawPub) {
		t.Error("RawPublicKey does not match public key derived from RawPrivateKey")
	}
}

func TestSignDelegation_MultipleCerts_UniqueCertIDs(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		result, err := SignDelegation(ca, brokerPub, "broker-1", 1*time.Hour)
		if err != nil {
			t.Fatalf("SignDelegation iteration %d: %v", i, err)
		}
		if seen[result.CertID] {
			t.Errorf("duplicate cert ID at iteration %d: %s", i, result.CertID)
		}
		seen[result.CertID] = true
	}
}

func TestSignDelegation_ExpiryMatchesTTL(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	ttl := 3 * time.Hour
	before := time.Now()
	result, err := SignDelegation(ca, brokerPub, "broker-1", ttl)
	if err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	after := time.Now()

	// IssuedAt should be between before and after.
	if result.IssuedAt.Before(before) || result.IssuedAt.After(after) {
		t.Errorf("IssuedAt %v not in range [%v, %v]", result.IssuedAt, before, after)
	}

	// ExpiresAt should be IssuedAt + TTL.
	expectedExpiry := result.IssuedAt.Add(ttl)
	if !result.ExpiresAt.Equal(expectedExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", result.ExpiresAt, expectedExpiry)
	}
}

func TestSignDelegation_SmallTTL(t *testing.T) {
	ca := testCA(t)
	brokerPub, _ := testBrokerKey(t)

	// 1 second TTL should work.
	result, err := SignDelegation(ca, brokerPub, "broker-1", 1*time.Second)
	if err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	if result.CertID == "" {
		t.Error("CertID is empty for 1s TTL")
	}
}
