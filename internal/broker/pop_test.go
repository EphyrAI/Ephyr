package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// makeTestProof creates a valid PopProof signed by the given private key.
// macBinary and requestBody are used to compute the correct digests.
func makeTestProof(t *testing.T, privKey ed25519.PrivateKey, taskID string, macBinary, requestBody []byte) *PopProof {
	t.Helper()

	bodyHash := sha256.Sum256(requestBody)
	macHash := sha256.Sum256(macBinary)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	payload := ProofPayload{
		TaskID:    taskID,
		ReqType:   "ssh_exec",
		Resource:  "dockerhost",
		Method:    "operator",
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     hex.EncodeToString(nonce),
		Ts:        time.Now().UTC().Format(time.RFC3339),
	}

	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	sig := ed25519.Sign(privKey, canonical)

	return &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Payload: payload,
	}
}

func TestVerifyPoP_Valid(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	macBinary := []byte("fake-macaroon-binary-data")
	requestBody := []byte(`{"tool":"exec","args":{"target":"dockerhost","command":"ls"}}`)
	taskID := "01HTEST000000000000000001"
	nc := NewNonceCache(5 * time.Minute)

	proof := makeTestProof(t, privKey, taskID, macBinary, requestBody)

	err = VerifyPoP(proof, []byte(pubKey), macBinary, requestBody, 30*time.Second, nc)
	if err != nil {
		t.Fatalf("expected valid proof, got error: %v", err)
	}
}

func TestVerifyPoP_WrongKey(t *testing.T) {
	_, privKeyA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen A: %v", err)
	}
	pubKeyB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen B: %v", err)
	}

	macBinary := []byte("fake-macaroon")
	requestBody := []byte(`{"test":"data"}`)
	taskID := "01HTEST000000000000000002"
	nc := NewNonceCache(5 * time.Minute)

	// Sign with key A, verify with key B.
	proof := makeTestProof(t, privKeyA, taskID, macBinary, requestBody)

	err = VerifyPoP(proof, []byte(pubKeyB), macBinary, requestBody, 30*time.Second, nc)
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}
	if got := err.Error(); got != "pop: signature verification failed" {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestVerifyPoP_TamperedBody(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	macBinary := []byte("fake-macaroon")
	originalBody := []byte(`{"original":"body"}`)
	tamperedBody := []byte(`{"tampered":"body"}`)
	taskID := "01HTEST000000000000000003"
	nc := NewNonceCache(5 * time.Minute)

	// Create proof with original body hash, but verify with tampered body.
	proof := makeTestProof(t, privKey, taskID, macBinary, originalBody)

	err = VerifyPoP(proof, []byte(pubKey), macBinary, tamperedBody, 30*time.Second, nc)
	if err == nil {
		t.Fatal("expected error for tampered body, got nil")
	}
	if got := err.Error(); got != "pop: body_hash mismatch: request body has been tampered with" {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestVerifyPoP_WrongMacDigest(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	macBinaryA := []byte("macaroon-version-A")
	macBinaryB := []byte("macaroon-version-B")
	requestBody := []byte(`{"test":"data"}`)
	taskID := "01HTEST000000000000000004"
	nc := NewNonceCache(5 * time.Minute)

	// Create proof with macaroon A's digest, but verify with macaroon B.
	proof := makeTestProof(t, privKey, taskID, macBinaryA, requestBody)

	err = VerifyPoP(proof, []byte(pubKey), macBinaryB, requestBody, 30*time.Second, nc)
	if err == nil {
		t.Fatal("expected error for wrong mac digest, got nil")
	}
	if got := err.Error(); got != "pop: mac_digest mismatch: proof does not match presented macaroon" {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestVerifyPoP_ReplayedNonce(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	macBinary := []byte("fake-macaroon")
	requestBody := []byte(`{"test":"data"}`)
	taskID := "01HTEST000000000000000005"
	nc := NewNonceCache(5 * time.Minute)

	proof := makeTestProof(t, privKey, taskID, macBinary, requestBody)

	// First verification should succeed.
	err = VerifyPoP(proof, []byte(pubKey), macBinary, requestBody, 30*time.Second, nc)
	if err != nil {
		t.Fatalf("first verification should succeed: %v", err)
	}

	// Second verification with same nonce should fail.
	err = VerifyPoP(proof, []byte(pubKey), macBinary, requestBody, 30*time.Second, nc)
	if err == nil {
		t.Fatal("expected replay error on second use, got nil")
	}
	if got := err.Error(); got != "pop: replay detected: nonce already used" {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestVerifyPoP_ExpiredTimestamp(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	macBinary := []byte("fake-macaroon")
	requestBody := []byte(`{"test":"data"}`)
	taskID := "01HTEST000000000000000006"
	nc := NewNonceCache(5 * time.Minute)

	bodyHash := sha256.Sum256(requestBody)
	macHash := sha256.Sum256(macBinary)

	nonce := make([]byte, 16)
	rand.Read(nonce)

	// Set timestamp 5 minutes in the past (skew is 30s).
	payload := ProofPayload{
		TaskID:    taskID,
		ReqType:   "ssh_exec",
		Resource:  "dockerhost",
		Method:    "operator",
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     hex.EncodeToString(nonce),
		Ts:        time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339),
	}

	canonical, _ := json.Marshal(payload)
	sig := ed25519.Sign(privKey, canonical)

	proof := &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Payload: payload,
	}

	err = VerifyPoP(proof, []byte(pubKey), macBinary, requestBody, 30*time.Second, nc)
	if err == nil {
		t.Fatal("expected error for expired timestamp, got nil")
	}
	if got := err.Error(); got != "pop: timestamp too old (skew 30s)" {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestVerifyPoP_FutureTimestamp(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	macBinary := []byte("fake-macaroon")
	requestBody := []byte(`{"test":"data"}`)
	taskID := "01HTEST000000000000000007"
	nc := NewNonceCache(5 * time.Minute)

	bodyHash := sha256.Sum256(requestBody)
	macHash := sha256.Sum256(macBinary)

	nonce := make([]byte, 16)
	rand.Read(nonce)

	// Set timestamp 5 minutes in the future (skew is 30s).
	payload := ProofPayload{
		TaskID:    taskID,
		ReqType:   "ssh_exec",
		Resource:  "dockerhost",
		Method:    "operator",
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     hex.EncodeToString(nonce),
		Ts:        time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339),
	}

	canonical, _ := json.Marshal(payload)
	sig := ed25519.Sign(privKey, canonical)

	proof := &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Payload: payload,
	}

	err = VerifyPoP(proof, []byte(pubKey), macBinary, requestBody, 30*time.Second, nc)
	if err == nil {
		t.Fatal("expected error for future timestamp, got nil")
	}
	if got := err.Error(); got != "pop: timestamp too far in future (skew 30s)" {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestNonceCache_Cleanup(t *testing.T) {
	nc := NewNonceCache(50 * time.Millisecond)

	// Store some nonces.
	if err := nc.CheckAndStore("task1", "nonce-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := nc.CheckAndStore("task1", "nonce-b"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nc.Count() != 2 {
		t.Fatalf("expected 2 entries, got %d", nc.Count())
	}

	// Wait for TTL to expire.
	time.Sleep(60 * time.Millisecond)

	// Run cleanup.
	nc.Cleanup()

	if nc.Count() != 0 {
		t.Fatalf("expected 0 entries after cleanup, got %d", nc.Count())
	}

	// The nonce should be accepted again after cleanup.
	if err := nc.CheckAndStore("task1", "nonce-a"); err != nil {
		t.Fatalf("nonce-a should be accepted after cleanup: %v", err)
	}
}

func TestNonceCache_ConcurrentAccess(t *testing.T) {
	nc := NewNonceCache(5 * time.Minute)
	const goroutines = 50
	const noncesPerGoroutine = 100

	var wg sync.WaitGroup
	errors := make(chan error, goroutines*noncesPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for n := 0; n < noncesPerGoroutine; n++ {
				nonce := fmt.Sprintf("g%d-n%d", gid, n)
				taskID := fmt.Sprintf("task-%d", gid)
				if err := nc.CheckAndStore(taskID, nonce); err != nil {
					errors <- fmt.Errorf("goroutine %d nonce %d: %v", gid, n, err)
				}
			}
		}(g)
	}

	// Also run cleanup concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			nc.Cleanup()
		}
	}()

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent error: %v", err)
	}

	expected := goroutines * noncesPerGoroutine
	if nc.Count() != expected {
		t.Errorf("expected %d entries, got %d", expected, nc.Count())
	}
}

func TestVerifyPoP_NilProof(t *testing.T) {
	nc := NewNonceCache(5 * time.Minute)
	err := VerifyPoP(nil, make([]byte, 32), nil, nil, 30*time.Second, nc)
	if err == nil {
		t.Fatal("expected error for nil proof")
	}
	if got := err.Error(); got != "pop: proof is nil" {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestVerifyPoP_InvalidPubKeySize(t *testing.T) {
	nc := NewNonceCache(5 * time.Minute)
	proof := &PopProof{Sig: "AAAA", Payload: ProofPayload{}}
	err := VerifyPoP(proof, make([]byte, 16), nil, nil, 30*time.Second, nc)
	if err == nil {
		t.Fatal("expected error for invalid pub key size")
	}
}

func TestVerifyPoP_InvalidSignatureEncoding(t *testing.T) {
	nc := NewNonceCache(5 * time.Minute)
	proof := &PopProof{
		Sig:     "!!!invalid-base64!!!",
		Payload: ProofPayload{},
	}
	err := VerifyPoP(proof, make([]byte, 32), nil, nil, 30*time.Second, nc)
	if err == nil {
		t.Fatal("expected error for invalid signature encoding")
	}
}

func TestVerifyPoP_NilNonceCache(t *testing.T) {
	// Verify that VerifyPoP works when NonceCache is nil (nonce check skipped).
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	macBinary := []byte("fake-macaroon")
	requestBody := []byte(`{"test":"data"}`)
	taskID := "01HTEST000000000000000008"

	proof := makeTestProof(t, privKey, taskID, macBinary, requestBody)

	// Pass nil NonceCache -- should succeed (nonce check skipped).
	err = VerifyPoP(proof, []byte(pubKey), macBinary, requestBody, 30*time.Second, nil)
	if err != nil {
		t.Fatalf("expected success with nil nonce cache, got: %v", err)
	}
}

func BenchmarkVerifyPoP(b *testing.B) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}

	macBinary := []byte("fake-macaroon-binary-data-for-benchmark")
	requestBody := []byte(`{"tool":"exec","args":{"target":"dockerhost","command":"uptime"}}`)
	taskID := "01HBENCH00000000000000001"

	bodyHash := sha256.Sum256(requestBody)
	macHash := sha256.Sum256(macBinary)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate unique nonce per iteration.
		nonce := make([]byte, 16)
		rand.Read(nonce)

		payload := ProofPayload{
			TaskID:    taskID,
			ReqType:   "ssh_exec",
			Resource:  "dockerhost",
			Method:    "operator",
			BodyHash:  hex.EncodeToString(bodyHash[:]),
			MacDigest: hex.EncodeToString(macHash[:]),
			Nonce:     hex.EncodeToString(nonce),
			Ts:        time.Now().UTC().Format(time.RFC3339),
		}

		canonical, _ := json.Marshal(payload)
		sig := ed25519.Sign(privKey, canonical)

		proof := &PopProof{
			Sig:     base64.RawURLEncoding.EncodeToString(sig),
			Payload: payload,
		}

		// Use a new nonce cache to avoid nonce collisions in benchmark.
		nc := NewNonceCache(5 * time.Minute)
		if err := VerifyPoP(proof, []byte(pubKey), macBinary, requestBody, 30*time.Second, nc); err != nil {
			b.Fatalf("unexpected verification error: %v", err)
		}
	}
}
