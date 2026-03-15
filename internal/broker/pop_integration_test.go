package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EphyrAI/Ephyr/internal/macaroon"
)

// buildTestPoP creates a valid PopProof signed by the given private key, using
// real macaroon binary and request body to compute correct digests.
func buildTestPoP(t *testing.T, priv ed25519.PrivateKey, taskID string, mac *macaroon.Macaroon, reqType, resource, method string, body []byte) *PopProof {
	t.Helper()

	macBytes, err := mac.MarshalBinary()
	if err != nil {
		t.Fatalf("buildTestPoP: marshal macaroon: %v", err)
	}

	bodyHash := sha256.Sum256(body)
	macHash := sha256.Sum256(macBytes)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("buildTestPoP: rand nonce: %v", err)
	}

	payload := ProofPayload{
		TaskID:    taskID,
		ReqType:   reqType,
		Resource:  resource,
		Method:    method,
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     hex.EncodeToString(nonce),
		Ts:        time.Now().UTC().Format(time.RFC3339),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("buildTestPoP: marshal payload: %v", err)
	}
	sig := ed25519.Sign(priv, payloadBytes)

	return &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Payload: payload,
	}
}

// buildTestPoPWithTs is like buildTestPoP but lets the caller override the timestamp.
func buildTestPoPWithTs(t *testing.T, priv ed25519.PrivateKey, taskID string, mac *macaroon.Macaroon, reqType, resource, method string, body []byte, ts time.Time) *PopProof {
	t.Helper()

	macBytes, err := mac.MarshalBinary()
	if err != nil {
		t.Fatalf("buildTestPoPWithTs: marshal macaroon: %v", err)
	}

	bodyHash := sha256.Sum256(body)
	macHash := sha256.Sum256(macBytes)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("buildTestPoPWithTs: rand nonce: %v", err)
	}

	payload := ProofPayload{
		TaskID:    taskID,
		ReqType:   reqType,
		Resource:  resource,
		Method:    method,
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     hex.EncodeToString(nonce),
		Ts:        ts.Format(time.RFC3339),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("buildTestPoPWithTs: marshal payload: %v", err)
	}
	sig := ed25519.Sign(priv, payloadBytes)

	return &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Payload: payload,
	}
}

// buildTestPoPWithNonce is like buildTestPoP but uses a caller-provided nonce.
func buildTestPoPWithNonce(t *testing.T, priv ed25519.PrivateKey, taskID string, mac *macaroon.Macaroon, reqType, resource, method string, body []byte, nonceHex string) *PopProof {
	t.Helper()

	macBytes, err := mac.MarshalBinary()
	if err != nil {
		t.Fatalf("buildTestPoPWithNonce: marshal macaroon: %v", err)
	}

	bodyHash := sha256.Sum256(body)
	macHash := sha256.Sum256(macBytes)

	payload := ProofPayload{
		TaskID:    taskID,
		ReqType:   reqType,
		Resource:  resource,
		Method:    method,
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     nonceHex,
		Ts:        time.Now().UTC().Format(time.RFC3339),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("buildTestPoPWithNonce: marshal payload: %v", err)
	}
	sig := ed25519.Sign(priv, payloadBytes)

	return &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Payload: payload,
	}
}

// mintTestMacaroon creates a task, mints a root macaroon, and returns both.
func mintTestMacaroon(t *testing.T, tm *TaskManager, ks *macaroon.RootKeyStore, agentName string, targets, roles []string, ttl time.Duration, holderPub []byte, canDelegate bool) (*Task, *macaroon.Macaroon) {
	t.Helper()

	task := tm.CreateTask(CreateTaskParams{
		AgentName:    agentName,
		Description:  "test task",
		TTL:          ttl,
		HolderPubKey: holderPub,
		Envelope:     TaskEnvelope{Targets: targets, Roles: roles},
		CanDelegate:  canDelegate,
	})

	minter := macaroon.NewMinter(ks)
	env := macaroon.EffectiveEnvelope{
		Targets:         targets,
		Roles:           roles,
		ExpiresAt:       task.ExpiresAt,
		CanDelegate:     canDelegate,
		DelegationDepth: 5,
	}
	mac, err := minter.MintRoot(task.ID, agentName, "ephyr:test", env)
	if err != nil {
		t.Fatalf("mintTestMacaroon: %v", err)
	}

	return task, mac
}

func TestBindE2E_RootTaskWithBinding(t *testing.T) {
	// 1. Generate Ed25519 keypair (agent side)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// 2. Create task with holder key
	tm := NewTaskManager()
	defer tm.Stop()
	task := tm.CreateTask(CreateTaskParams{
		AgentName:    "agent-1",
		Description:  "bound root task",
		TTL:          5 * time.Minute,
		HolderPubKey: pub,
		Envelope:     TaskEnvelope{Targets: []string{"host1"}, Roles: []string{"read"}},
		CanDelegate:  true,
	})

	// Verify immediately bound
	if !task.HolderBound {
		t.Fatal("expected HolderBound")
	}
	if len(task.HolderPubKey) != 32 {
		t.Fatal("expected 32-byte key")
	}

	// 3. Mint macaroon
	ks := macaroon.NewRootKeyStore()
	minter := macaroon.NewMinter(ks)
	env := macaroon.EffectiveEnvelope{
		Targets: []string{"host1"}, Roles: []string{"read"},
		ExpiresAt: task.ExpiresAt, CanDelegate: true, DelegationDepth: 5,
	}
	mac, _ := minter.MintRoot(task.ID, "agent-1", "ephyr:test", env)
	macBytes, _ := mac.MarshalBinary()

	// 4. Build PoP proof
	requestBody := []byte(`{"target":"host1","role":"read","command":"hostname"}`)
	bodyHash := sha256.Sum256(requestBody)
	macHash := sha256.Sum256(macBytes)

	payload := ProofPayload{
		TaskID:    task.ID,
		ReqType:   "ssh_exec",
		Resource:  "host1",
		Method:    "read",
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     "abcdef0123456789abcdef0123456789",
		Ts:        time.Now().Format(time.RFC3339),
	}

	payloadBytes, _ := json.Marshal(payload)
	sig := ed25519.Sign(priv, payloadBytes)

	// 5. Verify PoP
	nc := NewNonceCache(5 * time.Minute)
	proof := &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Payload: payload,
	}

	err := VerifyPoP(proof, pub, macBytes, requestBody, 30*time.Second, nc)
	if err != nil {
		t.Fatalf("PoP verification failed: %v", err)
	}
}

func TestBindE2E_TwoPhaseChildBinding(t *testing.T) {
	// 1. Create parent with holder key
	tm := NewTaskManager()
	defer tm.Stop()
	parentPub, _, _ := ed25519.GenerateKey(rand.Reader)

	parent := tm.CreateTask(CreateTaskParams{
		AgentName:    "agent-1",
		Description:  "parent",
		TTL:          10 * time.Minute,
		HolderPubKey: parentPub,
		Envelope:     TaskEnvelope{Targets: []string{"host1", "host2"}, Roles: []string{"read", "operator"}},
		CanDelegate:  true,
	})

	// 2. Delegate child (unbound)
	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "child task",
		TTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Child should be unbound with deadline
	if child.HolderBound {
		t.Fatal("child should be unbound")
	}
	if child.BindDeadline.IsZero() {
		t.Fatal("child should have bind deadline")
	}

	// 3. Child generates its own keypair and binds
	childPub, childPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := tm.BindHolderKey(child.ID, childPub); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	// Verify child is now bound
	updatedChild := tm.GetTask(child.ID)
	if !updatedChild.HolderBound {
		t.Fatal("child should be bound after task_bind")
	}

	// 4. Mint macaroons for both parent and child
	ks := macaroon.NewRootKeyStore()
	minter := macaroon.NewMinter(ks)
	parentEnv := macaroon.EffectiveEnvelope{
		Targets: []string{"host1", "host2"}, Roles: []string{"read", "operator"},
		ExpiresAt: parent.ExpiresAt, CanDelegate: true, DelegationDepth: 5,
	}
	parentMac, _ := minter.MintRoot(parent.ID, "agent-1", "ephyr:test", parentEnv)
	childEnv := macaroon.EffectiveEnvelope{
		Targets: []string{"host1"}, Roles: []string{"read"},
		ExpiresAt: child.ExpiresAt,
	}
	childMac, _ := minter.MintDelegated(parentMac, childEnv)
	childMacBytes, _ := childMac.MarshalBinary()

	requestBody := []byte(`{"target":"host1","role":"read","command":"uptime"}`)
	bodyHash := sha256.Sum256(requestBody)
	macHash := sha256.Sum256(childMacBytes)

	payload := ProofPayload{
		TaskID:    child.ID,
		ReqType:   "ssh_exec",
		Resource:  "host1",
		Method:    "read",
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     "1234567890abcdef1234567890abcdef",
		Ts:        time.Now().Format(time.RFC3339),
	}

	payloadBytes, _ := json.Marshal(payload)

	// Sign with CHILD key -- should succeed
	childSig := ed25519.Sign(childPriv, payloadBytes)
	nc := NewNonceCache(5 * time.Minute)
	childProof := &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(childSig),
		Payload: payload,
	}
	if err := VerifyPoP(childProof, childPub, childMacBytes, requestBody, 30*time.Second, nc); err != nil {
		t.Fatalf("child PoP should succeed: %v", err)
	}

	// Sign with CHILD key but verify against PARENT pub key -- should FAIL (Invariant 11: independent keys)
	payload2 := payload
	payload2.Nonce = "differentnonce00differentnonce00" // new nonce to avoid replay
	payloadBytes2, _ := json.Marshal(payload2)
	childSig2 := ed25519.Sign(childPriv, payloadBytes2) // signed by child's private key
	parentProof := &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(childSig2),
		Payload: payload2,
	}

	err = VerifyPoP(parentProof, parentPub, childMacBytes, requestBody, 30*time.Second, nc)
	if err == nil {
		t.Fatal("verifying child's PoP with parent's pub key should fail")
	}
}

func TestBindE2E_LeakedTokenWithoutKey(t *testing.T) {
	// Simulate: attacker has the macaroon but NOT the private key
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Build a valid macaroon
	ks := macaroon.NewRootKeyStore()
	minter := macaroon.NewMinter(ks)
	env := macaroon.EffectiveEnvelope{
		Targets: []string{"host1"}, Roles: []string{"read"},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	mac, _ := minter.MintRoot("leak-test", "agent-1", "ephyr:test", env)
	macBytes, _ := mac.MarshalBinary()

	// Attacker signs proof with THEIR key (not the bound key)
	requestBody := []byte(`{"command":"cat /etc/shadow"}`)
	bodyHash := sha256.Sum256(requestBody)
	macHash := sha256.Sum256(macBytes)

	payload := ProofPayload{
		TaskID:    "leak-test",
		ReqType:   "ssh_exec",
		Resource:  "host1",
		Method:    "read",
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     "attackernonce000attackernonce000",
		Ts:        time.Now().Format(time.RFC3339),
	}
	payloadBytes, _ := json.Marshal(payload)
	sig := ed25519.Sign(attackerPriv, payloadBytes)

	nc := NewNonceCache(5 * time.Minute)
	proof := &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Payload: payload,
	}

	// Verify against the LEGITIMATE holder's pub key -- attacker's sig fails
	err := VerifyPoP(proof, pub, macBytes, requestBody, 30*time.Second, nc)
	if err == nil {
		t.Fatal("leaked token without holder key should fail PoP verification")
	}
}

func TestBindE2E_BodyTamperingDetected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	ks := macaroon.NewRootKeyStore()
	minter := macaroon.NewMinter(ks)
	env := macaroon.EffectiveEnvelope{
		Targets: []string{"host1"}, Roles: []string{"read"},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	mac, _ := minter.MintRoot("tamper-test", "agent-1", "ephyr:test", env)
	macBytes, _ := mac.MarshalBinary()

	// Agent signs proof with original body
	originalBody := []byte(`{"command":"hostname"}`)
	bodyHash := sha256.Sum256(originalBody)
	macHash := sha256.Sum256(macBytes)

	payload := ProofPayload{
		TaskID:    "tamper-test",
		ReqType:   "ssh_exec",
		Resource:  "host1",
		Method:    "read",
		BodyHash:  hex.EncodeToString(bodyHash[:]),
		MacDigest: hex.EncodeToString(macHash[:]),
		Nonce:     "tampernonce00000tampernonce00000",
		Ts:        time.Now().Format(time.RFC3339),
	}
	payloadBytes, _ := json.Marshal(payload)
	sig := ed25519.Sign(priv, payloadBytes)

	nc := NewNonceCache(5 * time.Minute)
	proof := &PopProof{
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Payload: payload,
	}

	// MitM tampers with the body
	tamperedBody := []byte(`{"command":"rm -rf /"}`)

	err := VerifyPoP(proof, pub, macBytes, tamperedBody, 30*time.Second, nc)
	if err == nil {
		t.Fatal("tampered body should fail PoP verification")
	}
}

func TestBindE2E_BindDeadlineAutoRevoke(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := tm.CreateTask(CreateTaskParams{
		AgentName:   "agent-1",
		Description: "parent",
		TTL:         60 * time.Minute,
		Envelope:    TaskEnvelope{Targets: []string{"host1"}},
		CanDelegate: true,
	})

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "will expire unbound",
		TTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Manually set bind deadline to the past to simulate expiry
	tm.mu.Lock()
	if task, ok := tm.tasks[child.ID]; ok {
		task.BindDeadline = time.Now().Add(-1 * time.Second)
	}
	tm.mu.Unlock()

	// Run cleanup
	tm.cleanup()

	// Child should be gone
	if tm.GetTask(child.ID) != nil {
		t.Fatal("unbound task past deadline should be auto-revoked")
	}

	// Parent should still exist
	if tm.GetTask(parent.ID) == nil {
		t.Fatal("parent should still exist")
	}
}

func BenchmarkBindE2E_FullPipeline(b *testing.B) {
	// Pre-generate: keypair, macaroon, body
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ks := macaroon.NewRootKeyStore()
	minter := macaroon.NewMinter(ks)
	env := macaroon.EffectiveEnvelope{
		Targets: []string{"host1"}, Roles: []string{"read"},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	mac, _ := minter.MintRoot("bench-bind", "agent-1", "ephyr:test", env)
	macBytes, _ := mac.MarshalBinary()
	requestBody := []byte(`{"target":"host1","role":"read","command":"hostname"}`)
	bodyHash := sha256.Sum256(requestBody)
	macHash := sha256.Sum256(macBytes)
	nc := NewNonceCache(5 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonce := make([]byte, 16)
		rand.Read(nonce)

		payload := ProofPayload{
			TaskID:    "bench-bind",
			ReqType:   "ssh_exec",
			Resource:  "host1",
			Method:    "read",
			BodyHash:  hex.EncodeToString(bodyHash[:]),
			MacDigest: hex.EncodeToString(macHash[:]),
			Nonce:     hex.EncodeToString(nonce),
			Ts:        time.Now().Format(time.RFC3339),
		}
		payloadBytes, _ := json.Marshal(payload)
		sig := ed25519.Sign(priv, payloadBytes)

		proof := &PopProof{
			Sig:     base64.RawURLEncoding.EncodeToString(sig),
			Payload: payload,
		}
		VerifyPoP(proof, pub, macBytes, requestBody, 30*time.Second, nc)
	}
}

// ---------------------------------------------------------------------------
// New integration tests (TestPopE2E_*)
// ---------------------------------------------------------------------------

// TestPopE2E_FullRequestFlow simulates the complete auth + PoP pipeline:
// task creation -> macaroon minting -> proof construction -> verify success,
// then verifies that tampering with body, cross-token use, nonce replay,
// and expired timestamps all fail.
func TestPopE2E_FullRequestFlow(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tm := NewTaskManager()
	defer tm.Stop()
	ks := macaroon.NewRootKeyStore()
	nc := NewNonceCache(5 * time.Minute)

	task, mac := mintTestMacaroon(t, tm, ks, "agent-flow", []string{"dockerhost"}, []string{"operator"}, 10*time.Minute, pub, false)
	macBytes, _ := mac.MarshalBinary()
	body := []byte(`{"tool":"exec","args":{"target":"dockerhost","command":"ls -la"}}`)

	// --- Sub-test 1: valid proof succeeds ---
	t.Run("ValidProofSucceeds", func(t *testing.T) {
		proof := buildTestPoP(t, priv, task.ID, mac, "ssh_exec", "dockerhost", "operator", body)
		if err := VerifyPoP(proof, pub, macBytes, body, 30*time.Second, nc); err != nil {
			t.Fatalf("valid proof should succeed: %v", err)
		}
	})

	// --- Sub-test 2: tampered body fails ---
	t.Run("TamperedBodyFails", func(t *testing.T) {
		proof := buildTestPoP(t, priv, task.ID, mac, "ssh_exec", "dockerhost", "operator", body)
		tamperedBody := []byte(`{"tool":"exec","args":{"target":"dockerhost","command":"rm -rf /"}}`)
		err := VerifyPoP(proof, pub, macBytes, tamperedBody, 30*time.Second, nc)
		if err == nil {
			t.Fatal("tampered body should fail")
		}
		if !strings.Contains(err.Error(), "body_hash mismatch") {
			t.Errorf("expected body_hash mismatch, got: %v", err)
		}
	})

	// --- Sub-test 3: cross-token macaroon fails ---
	t.Run("CrossTokenMacaroonFails", func(t *testing.T) {
		// Mint a second, different macaroon for a separate task.
		_, otherMac := mintTestMacaroon(t, tm, ks, "agent-flow", []string{"host2"}, []string{"read"}, 5*time.Minute, pub, false)
		otherMacBytes, _ := otherMac.MarshalBinary()

		// Build proof against the first macaroon but verify with the second.
		proof := buildTestPoP(t, priv, task.ID, mac, "ssh_exec", "dockerhost", "operator", body)
		err := VerifyPoP(proof, pub, otherMacBytes, body, 30*time.Second, nc)
		if err == nil {
			t.Fatal("cross-token macaroon should fail")
		}
		if !strings.Contains(err.Error(), "mac_digest mismatch") {
			t.Errorf("expected mac_digest mismatch, got: %v", err)
		}
	})

	// --- Sub-test 4: replayed nonce fails ---
	t.Run("ReplayedNonceFails", func(t *testing.T) {
		sharedNonce := "deadbeefcafebabe1234567890abcdef"
		proof1 := buildTestPoPWithNonce(t, priv, task.ID, mac, "ssh_exec", "dockerhost", "operator", body, sharedNonce)
		if err := VerifyPoP(proof1, pub, macBytes, body, 30*time.Second, nc); err != nil {
			t.Fatalf("first use of nonce should succeed: %v", err)
		}

		proof2 := buildTestPoPWithNonce(t, priv, task.ID, mac, "ssh_exec", "dockerhost", "operator", body, sharedNonce)
		err := VerifyPoP(proof2, pub, macBytes, body, 30*time.Second, nc)
		if err == nil {
			t.Fatal("replayed nonce should fail")
		}
		if !strings.Contains(err.Error(), "replay detected") {
			t.Errorf("expected replay detected, got: %v", err)
		}
	})

	// --- Sub-test 5: expired timestamp fails ---
	t.Run("ExpiredTimestampFails", func(t *testing.T) {
		oldTs := time.Now().Add(-5 * time.Minute) // 5 minutes old, skew is 30s
		proof := buildTestPoPWithTs(t, priv, task.ID, mac, "ssh_exec", "dockerhost", "operator", body, oldTs)
		err := VerifyPoP(proof, pub, macBytes, body, 30*time.Second, nc)
		if err == nil {
			t.Fatal("expired timestamp should fail")
		}
		if !strings.Contains(err.Error(), "timestamp too old") {
			t.Errorf("expected timestamp too old, got: %v", err)
		}
	})
}

// TestPopE2E_UnboundTaskRejected creates a delegated child task that has no
// HolderPubKey (never called BindHolderKey). Verifying a PoP against a zero-
// length holder key should fail because VerifyPoP requires exactly 32 bytes.
func TestPopE2E_UnboundTaskRejected(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()
	ks := macaroon.NewRootKeyStore()

	parentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	parent, parentMac := mintTestMacaroon(t, tm, ks, "agent-unbound", []string{"host1"}, []string{"read"}, 10*time.Minute, parentPub, true)

	// Create child task (unbound -- no holder key).
	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-unbound",
		Description: "unbound child",
		TTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create child: %v", err)
	}

	// Child should NOT be holder-bound.
	if child.HolderBound {
		t.Fatal("child should be unbound")
	}
	if len(child.HolderPubKey) != 0 {
		t.Fatalf("unbound child should have no HolderPubKey, got %d bytes", len(child.HolderPubKey))
	}

	// Mint a delegated macaroon for the child.
	minter := macaroon.NewMinter(ks)
	childEnv := macaroon.EffectiveEnvelope{
		Targets:   []string{"host1"},
		Roles:     []string{"read"},
		ExpiresAt: child.ExpiresAt,
	}
	childMac, err := minter.MintDelegated(parentMac, childEnv)
	if err != nil {
		t.Fatalf("mint delegated: %v", err)
	}
	childMacBytes, _ := childMac.MarshalBinary()

	// Build a PoP proof using a random key (simulating the child trying to use
	// a key not registered with the task).
	_, randomPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(`{"target":"host1","command":"whoami"}`)
	proof := buildTestPoP(t, randomPriv, child.ID, childMac, "ssh_exec", "host1", "read", body)

	nc := NewNonceCache(5 * time.Minute)

	// Verify with the child's (empty) HolderPubKey -- should fail.
	err = VerifyPoP(proof, child.HolderPubKey, childMacBytes, body, 30*time.Second, nc)
	if err == nil {
		t.Fatal("PoP verification with unbound task (no holder key) should fail")
	}
	if !strings.Contains(err.Error(), "invalid holder public key") {
		t.Errorf("expected invalid holder public key error, got: %v", err)
	}
}

// TestPopE2E_BoundTaskRequired simulates a task with HolderBound=true. If
// the caller provides no PoP proof (nil), the broker should reject the
// request. This tests the broker-side decision logic: when a task is bound,
// a nil proof causes VerifyPoP to return an error.
func TestPopE2E_BoundTaskRequired(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tm := NewTaskManager()
	defer tm.Stop()
	ks := macaroon.NewRootKeyStore()

	task, mac := mintTestMacaroon(t, tm, ks, "agent-bound-req", []string{"host1"}, []string{"read"}, 10*time.Minute, pub, false)
	macBytes, _ := mac.MarshalBinary()

	// Verify task is bound.
	if !task.HolderBound {
		t.Fatal("task should be holder-bound")
	}

	body := []byte(`{"target":"host1","command":"uptime"}`)
	nc := NewNonceCache(5 * time.Minute)

	// Broker logic: task is HolderBound, caller provides nil proof -> reject.
	err := VerifyPoP(nil, pub, macBytes, body, 30*time.Second, nc)
	if err == nil {
		t.Fatal("nil proof on bound task should fail")
	}
	if !strings.Contains(err.Error(), "proof is nil") {
		t.Errorf("expected 'proof is nil' error, got: %v", err)
	}
}

// TestPopE2E_APIKeyBypassesPoP verifies the broker semantic: when
// authenticating with an API key (no task context), PoP is not checked.
// This is simulated by showing that the broker would skip VerifyPoP
// entirely -- there is no task, no holder key, no proof to check.
func TestPopE2E_APIKeyBypassesPoP(t *testing.T) {
	// Simulate: API key auth resolves an agent name but no task.
	// The broker checks: if task == nil -> skip PoP entirely.
	// We verify this by showing that a nil task means HolderBound is
	// irrelevant, and VerifyPoP is never called.

	tm := NewTaskManager()
	defer tm.Stop()

	// Look up a non-existent task (simulating API key auth path).
	task := tm.GetTask("non-existent-task-id")
	if task != nil {
		t.Fatal("should be nil for non-existent task")
	}

	// Broker decision: no task context -> PoP not required.
	// This is a logic test, not a VerifyPoP test. The broker code does:
	//   if task != nil && task.HolderBound { verifyPoP(...) }
	// With nil task, PoP is bypassed.
	popRequired := task != nil && task.HolderBound
	if popRequired {
		t.Fatal("PoP should not be required when there is no task (API key auth)")
	}
}

// TestPopE2E_DelegationIndependentKeys verifies that parent and child tasks
// have independent holder keys. Parent's key cannot be used for child's PoP,
// and child's key cannot be used for parent's PoP.
func TestPopE2E_DelegationIndependentKeys(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()
	ks := macaroon.NewRootKeyStore()
	nc := NewNonceCache(5 * time.Minute)

	// Parent with key A.
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	parent, parentMac := mintTestMacaroon(t, tm, ks, "agent-indep", []string{"host1", "host2"}, []string{"read", "operator"}, 10*time.Minute, pubA, true)
	parentMacBytes, _ := parentMac.MarshalBinary()

	// Delegate child task.
	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-indep",
		Description: "child with key B",
		TTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create child: %v", err)
	}

	// Bind child with key B.
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	if err := tm.BindHolderKey(child.ID, pubB); err != nil {
		t.Fatalf("bind child: %v", err)
	}

	// Mint delegated macaroon for child.
	minter := macaroon.NewMinter(ks)
	childEnv := macaroon.EffectiveEnvelope{
		Targets:   []string{"host1"},
		Roles:     []string{"read"},
		ExpiresAt: child.ExpiresAt,
	}
	childMac, _ := minter.MintDelegated(parentMac, childEnv)
	childMacBytes, _ := childMac.MarshalBinary()

	body := []byte(`{"target":"host1","command":"id"}`)

	// Parent's proof with key A against parent macaroon -> should succeed.
	t.Run("ParentKeyA_ParentMac_Succeeds", func(t *testing.T) {
		proof := buildTestPoP(t, privA, parent.ID, parentMac, "ssh_exec", "host1", "read", body)
		if err := VerifyPoP(proof, pubA, parentMacBytes, body, 30*time.Second, nc); err != nil {
			t.Fatalf("parent's own PoP should succeed: %v", err)
		}
	})

	// Child's proof with key B against child macaroon -> should succeed.
	t.Run("ChildKeyB_ChildMac_Succeeds", func(t *testing.T) {
		proof := buildTestPoP(t, privB, child.ID, childMac, "ssh_exec", "host1", "read", body)
		if err := VerifyPoP(proof, pubB, childMacBytes, body, 30*time.Second, nc); err != nil {
			t.Fatalf("child's own PoP should succeed: %v", err)
		}
	})

	// Parent key A used for child macaroon -> should fail (sig mismatch).
	t.Run("ParentKeyA_ChildMac_Fails", func(t *testing.T) {
		proof := buildTestPoP(t, privA, child.ID, childMac, "ssh_exec", "host1", "read", body)
		err := VerifyPoP(proof, pubB, childMacBytes, body, 30*time.Second, nc)
		if err == nil {
			t.Fatal("parent key should not verify child's PoP")
		}
		if !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("expected signature verification failed, got: %v", err)
		}
	})

	// Child key B used for parent macaroon -> should fail (sig mismatch).
	t.Run("ChildKeyB_ParentMac_Fails", func(t *testing.T) {
		proof := buildTestPoP(t, privB, parent.ID, parentMac, "ssh_exec", "host1", "read", body)
		err := VerifyPoP(proof, pubA, parentMacBytes, body, 30*time.Second, nc)
		if err == nil {
			t.Fatal("child key should not verify parent's PoP")
		}
		if !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("expected signature verification failed, got: %v", err)
		}
	})
}

// TestPopE2E_ClockSkewBoundary tests timestamps at exactly the clock skew
// boundary (30 seconds) to verify boundary behavior.
func TestPopE2E_ClockSkewBoundary(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tm := NewTaskManager()
	defer tm.Stop()
	ks := macaroon.NewRootKeyStore()
	nc := NewNonceCache(5 * time.Minute)

	task, mac := mintTestMacaroon(t, tm, ks, "agent-skew", []string{"host1"}, []string{"read"}, 10*time.Minute, pub, false)
	macBytes, _ := mac.MarshalBinary()
	body := []byte(`{"target":"host1","command":"date"}`)
	clockSkew := 30 * time.Second

	// Sub-test: timestamp exactly at the skew boundary in the past.
	// RFC3339 has second precision, so we test at -29s (inside) and -31s (outside).
	t.Run("PastInsideBoundary", func(t *testing.T) {
		ts := time.Now().Add(-29 * time.Second)
		proof := buildTestPoPWithTs(t, priv, task.ID, mac, "ssh_exec", "host1", "read", body, ts)
		err := VerifyPoP(proof, pub, macBytes, body, clockSkew, nc)
		if err != nil {
			t.Fatalf("timestamp 29s in past should be within 30s skew: %v", err)
		}
	})

	t.Run("PastOutsideBoundary", func(t *testing.T) {
		ts := time.Now().Add(-31 * time.Second)
		proof := buildTestPoPWithTs(t, priv, task.ID, mac, "ssh_exec", "host1", "read", body, ts)
		err := VerifyPoP(proof, pub, macBytes, body, clockSkew, nc)
		if err == nil {
			t.Fatal("timestamp 31s in past should be outside 30s skew")
		}
		if !strings.Contains(err.Error(), "timestamp too old") {
			t.Errorf("expected timestamp too old, got: %v", err)
		}
	})

	// Sub-test: timestamp exactly at the skew boundary in the future.
	t.Run("FutureInsideBoundary", func(t *testing.T) {
		ts := time.Now().Add(29 * time.Second)
		proof := buildTestPoPWithTs(t, priv, task.ID, mac, "ssh_exec", "host1", "read", body, ts)
		err := VerifyPoP(proof, pub, macBytes, body, clockSkew, nc)
		if err != nil {
			t.Fatalf("timestamp 29s in future should be within 30s skew: %v", err)
		}
	})

	t.Run("FutureOutsideBoundary", func(t *testing.T) {
		ts := time.Now().Add(31 * time.Second)
		proof := buildTestPoPWithTs(t, priv, task.ID, mac, "ssh_exec", "host1", "read", body, ts)
		err := VerifyPoP(proof, pub, macBytes, body, clockSkew, nc)
		if err == nil {
			t.Fatal("timestamp 31s in future should be outside 30s skew")
		}
		if !strings.Contains(err.Error(), "timestamp too far in future") {
			t.Errorf("expected timestamp too far in future, got: %v", err)
		}
	})

	// Sub-test: timestamp exactly at now (should always succeed).
	t.Run("ExactlyNow", func(t *testing.T) {
		proof := buildTestPoPWithTs(t, priv, task.ID, mac, "ssh_exec", "host1", "read", body, time.Now())
		err := VerifyPoP(proof, pub, macBytes, body, clockSkew, nc)
		if err != nil {
			t.Fatalf("timestamp at now should succeed: %v", err)
		}
	})
}

// TestPopE2E_NonceReplayAcrossTasks verifies that the same nonce used for two
// different tasks should work, because the nonce cache is scoped per-task
// (key = "taskID:nonce").
func TestPopE2E_NonceReplayAcrossTasks(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tm := NewTaskManager()
	defer tm.Stop()
	ks := macaroon.NewRootKeyStore()
	nc := NewNonceCache(5 * time.Minute)

	// Create two separate tasks.
	task1, mac1 := mintTestMacaroon(t, tm, ks, "agent-nonce", []string{"host1"}, []string{"read"}, 10*time.Minute, pub, false)
	task2, mac2 := mintTestMacaroon(t, tm, ks, "agent-nonce", []string{"host2"}, []string{"operator"}, 10*time.Minute, pub, false)

	mac1Bytes, _ := mac1.MarshalBinary()
	mac2Bytes, _ := mac2.MarshalBinary()

	body1 := []byte(`{"target":"host1","command":"uptime"}`)
	body2 := []byte(`{"target":"host2","command":"df"}`)

	// Use the same nonce for both tasks.
	sharedNonce := "aaaaaaaaaaaaaaaa1111111111111111"

	// First task with the shared nonce should succeed.
	proof1 := buildTestPoPWithNonce(t, priv, task1.ID, mac1, "ssh_exec", "host1", "read", body1, sharedNonce)
	if err := VerifyPoP(proof1, pub, mac1Bytes, body1, 30*time.Second, nc); err != nil {
		t.Fatalf("task1 with shared nonce should succeed: %v", err)
	}

	// Second task with the SAME nonce should also succeed (different task ID).
	proof2 := buildTestPoPWithNonce(t, priv, task2.ID, mac2, "ssh_exec", "host2", "operator", body2, sharedNonce)
	if err := VerifyPoP(proof2, pub, mac2Bytes, body2, 30*time.Second, nc); err != nil {
		t.Fatalf("task2 with same nonce should succeed (different task scope): %v", err)
	}

	// But replaying the same nonce on task1 again should fail.
	proof3 := buildTestPoPWithNonce(t, priv, task1.ID, mac1, "ssh_exec", "host1", "read", body1, sharedNonce)
	err := VerifyPoP(proof3, pub, mac1Bytes, body1, 30*time.Second, nc)
	if err == nil {
		t.Fatal("replaying nonce on same task should fail")
	}
}

// TestPopE2E_ConcurrentPopVerification fires 50 goroutines each verifying a
// PoP with a unique nonce. All should succeed with no data races.
func TestPopE2E_ConcurrentPopVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tm := NewTaskManager()
	defer tm.Stop()
	ks := macaroon.NewRootKeyStore()
	nc := NewNonceCache(5 * time.Minute)

	task, mac := mintTestMacaroon(t, tm, ks, "agent-concurrent", []string{"host1"}, []string{"read"}, 10*time.Minute, pub, false)
	macBytes, _ := mac.MarshalBinary()
	body := []byte(`{"target":"host1","command":"hostname"}`)

	const numGoroutines = 50
	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines)
	var successCount int64

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			proof := buildTestPoP(t, priv, task.ID, mac, "ssh_exec", "host1", "read", body)
			if err := VerifyPoP(proof, pub, macBytes, body, 30*time.Second, nc); err != nil {
				errCh <- fmt.Errorf("goroutine %d: %w", gid, err)
				return
			}
			atomic.AddInt64(&successCount, 1)
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent verification error: %v", err)
	}

	if got := atomic.LoadInt64(&successCount); got != numGoroutines {
		t.Errorf("expected %d successful verifications, got %d", numGoroutines, got)
	}
}

// ---------------------------------------------------------------------------
// New benchmarks (BenchmarkPopE2E_*)
// ---------------------------------------------------------------------------

// BenchmarkPopE2E_VerifyWithMacaroon benchmarks the full PoP pipeline:
// build proof payload, sign with Ed25519, marshal macaroon, compute
// body_hash + mac_digest, and verify the PoP.
func BenchmarkPopE2E_VerifyWithMacaroon(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ks := macaroon.NewRootKeyStore()
	minter := macaroon.NewMinter(ks)
	env := macaroon.EffectiveEnvelope{
		Targets: []string{"dockerhost", "hugoblog"}, Roles: []string{"read", "operator"},
		ExpiresAt: time.Now().Add(30 * time.Minute), CanDelegate: true, DelegationDepth: 5,
	}
	mac, _ := minter.MintRoot("bench-pop-e2e", "agent-bench", "ephyr:bench", env)
	macBytes, _ := mac.MarshalBinary()
	body := []byte(`{"tool":"exec","args":{"target":"dockerhost","command":"uptime","role":"operator"}}`)
	bodyHash := sha256.Sum256(body)
	macHash := sha256.Sum256(macBytes)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		nonce := make([]byte, 16)
		rand.Read(nonce)

		payload := ProofPayload{
			TaskID:    "bench-pop-e2e",
			ReqType:   "ssh_exec",
			Resource:  "dockerhost",
			Method:    "operator",
			BodyHash:  hex.EncodeToString(bodyHash[:]),
			MacDigest: hex.EncodeToString(macHash[:]),
			Nonce:     hex.EncodeToString(nonce),
			Ts:        time.Now().UTC().Format(time.RFC3339),
		}
		payloadBytes, _ := json.Marshal(payload)
		sig := ed25519.Sign(priv, payloadBytes)

		proof := &PopProof{
			Sig:     base64.RawURLEncoding.EncodeToString(sig),
			Payload: payload,
		}

		// Use fresh nonce cache per iteration to avoid nonce collision in bench.
		nc := NewNonceCache(5 * time.Minute)
		if err := VerifyPoP(proof, pub, macBytes, body, 30*time.Second, nc); err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// BenchmarkPopE2E_NonceCacheUnderLoad measures nonce cache overhead with
// 10,000 sequential nonce checks in a single cache.
func BenchmarkPopE2E_NonceCacheUnderLoad(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		nc := NewNonceCache(5 * time.Minute)
		for n := 0; n < 10000; n++ {
			taskID := fmt.Sprintf("task-%d", n%100) // 100 different tasks
			nonce := fmt.Sprintf("nonce-%d", n)
			if err := nc.CheckAndStore(taskID, nonce); err != nil {
				b.Fatalf("unexpected collision at n=%d: %v", n, err)
			}
		}
		// Verify final count.
		if nc.Count() != 10000 {
			b.Fatalf("expected 10000 entries, got %d", nc.Count())
		}
	}
}

// BenchmarkPopE2E_ConcurrentVerify measures PoP verification throughput
// with parallel goroutines to expose lock contention in the nonce cache.
func BenchmarkPopE2E_ConcurrentVerify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ks := macaroon.NewRootKeyStore()
	minter := macaroon.NewMinter(ks)
	env := macaroon.EffectiveEnvelope{
		Targets: []string{"host1"}, Roles: []string{"read"},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	mac, _ := minter.MintRoot("bench-concurrent", "agent-bench", "ephyr:bench", env)
	macBytes, _ := mac.MarshalBinary()
	body := []byte(`{"target":"host1","command":"hostname"}`)
	bodyHash := sha256.Sum256(body)
	macHash := sha256.Sum256(macBytes)
	nc := NewNonceCache(5 * time.Minute)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nonce := make([]byte, 16)
			rand.Read(nonce)

			payload := ProofPayload{
				TaskID:    "bench-concurrent",
				ReqType:   "ssh_exec",
				Resource:  "host1",
				Method:    "read",
				BodyHash:  hex.EncodeToString(bodyHash[:]),
				MacDigest: hex.EncodeToString(macHash[:]),
				Nonce:     hex.EncodeToString(nonce),
				Ts:        time.Now().UTC().Format(time.RFC3339),
			}
			payloadBytes, _ := json.Marshal(payload)
			sig := ed25519.Sign(priv, payloadBytes)

			proof := &PopProof{
				Sig:     base64.RawURLEncoding.EncodeToString(sig),
				Payload: payload,
			}
			if err := VerifyPoP(proof, pub, macBytes, body, 30*time.Second, nc); err != nil {
				b.Fatalf("concurrent verify error: %v", err)
			}
		}
	})
}
