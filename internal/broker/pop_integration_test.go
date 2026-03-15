package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/EphyrAI/Ephyr/internal/macaroon"
)

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
