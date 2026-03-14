package macaroon

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func testKey() []byte {
	return []byte("ephyr-test-root-key-32-bytes!!")
}

func testID() []byte {
	return []byte("01JQTEST000000000000000000")
}

func TestNew(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)

	if m.Location() != "ephyr-broker" {
		t.Fatalf("location = %q, want %q", m.Location(), "ephyr-broker")
	}
	if !bytes.Equal(m.Id(), id) {
		t.Fatalf("id mismatch")
	}

	// Verify signature is HMAC-SHA256(key, id).
	h := hmac.New(sha256.New, key)
	h.Write(id)
	var expected [32]byte
	copy(expected[:], h.Sum(nil))
	if m.Signature() != expected {
		t.Fatalf("initial signature mismatch:\n  got  %x\n  want %x", m.Signature(), expected)
	}
}

func TestAddCaveat(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)

	sig0 := m.Signature()
	caveat := []byte("target IN [dockerhost]")
	m.AddFirstPartyCaveat(caveat)

	// New sig should be HMAC(sig0, caveat).
	expected := hmacSHA256(sig0[:], caveat)
	if m.Signature() != expected {
		t.Fatalf("signature after caveat mismatch:\n  got  %x\n  want %x", m.Signature(), expected)
	}

	// Caveats list should have one entry.
	caveats := m.Caveats()
	if len(caveats) != 1 {
		t.Fatalf("caveats count = %d, want 1", len(caveats))
	}
	if !bytes.Equal(caveats[0], caveat) {
		t.Fatalf("caveat mismatch")
	}
}

func TestVerify_Valid(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)
	m.AddFirstPartyCaveat([]byte("target IN [dockerhost,hugoblog]"))
	m.AddFirstPartyCaveat([]byte("role IN [read]"))
	m.AddFirstPartyCaveat([]byte("expires_before = 2026-12-31T23:59:59Z"))

	caveats, err := m.Verify(key)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if len(caveats) != 3 {
		t.Fatalf("caveats count = %d, want 3", len(caveats))
	}
	if caveats[0] != "target IN [dockerhost,hugoblog]" {
		t.Fatalf("caveat[0] = %q", caveats[0])
	}
}

func TestVerify_WrongKey(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)
	m.AddFirstPartyCaveat([]byte("target IN [dockerhost]"))

	wrongKey := []byte("wrong-key-that-should-not-work!")
	_, err := m.Verify(wrongKey)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerify_TamperedCaveat(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)
	m.AddFirstPartyCaveat([]byte("target IN [dockerhost]"))
	m.AddFirstPartyCaveat([]byte("role IN [read]"))

	// Tamper with a caveat directly (bypass the API by reaching into the struct).
	m.caveats[0] = []byte("target IN [dockerhost,hugoblog,mandrake-rack]")

	_, err := m.Verify(key)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature after tampering, got %v", err)
	}
}

func TestVerify_RemovedCaveat(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)
	m.AddFirstPartyCaveat([]byte("target IN [dockerhost]"))
	m.AddFirstPartyCaveat([]byte("role IN [read]"))
	m.AddFirstPartyCaveat([]byte("can_delegate = false"))

	// Remove the middle caveat.
	m.caveats = append(m.caveats[:1], m.caveats[2:]...)

	_, err := m.Verify(key)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature after removal, got %v", err)
	}
}

func TestClone(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)
	m.AddFirstPartyCaveat([]byte("target IN [dockerhost]"))

	clone := m.Clone()

	// Clone should have same values.
	if !bytes.Equal(clone.Id(), m.Id()) {
		t.Fatal("clone id mismatch")
	}
	if clone.Location() != m.Location() {
		t.Fatal("clone location mismatch")
	}
	if clone.Signature() != m.Signature() {
		t.Fatal("clone signature mismatch")
	}
	cOrig := m.Caveats()
	cClone := clone.Caveats()
	if len(cOrig) != len(cClone) {
		t.Fatal("clone caveats count mismatch")
	}

	// Modifying clone should NOT affect original.
	clone.AddFirstPartyCaveat([]byte("role IN [read]"))
	if len(m.Caveats()) != 1 {
		t.Fatal("modifying clone affected original caveats")
	}
	if m.Signature() == clone.Signature() {
		t.Fatal("modifying clone affected original signature")
	}

	// Modifying original should NOT affect clone's previous state.
	origSigBefore := clone.Signature()
	m.AddFirstPartyCaveat([]byte("service IN [github]"))
	if clone.Signature() != origSigBefore {
		t.Fatal("modifying original affected clone signature")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)
	m.AddFirstPartyCaveat([]byte("target IN [dockerhost,hugoblog]"))
	m.AddFirstPartyCaveat([]byte("role IN [read,operator]"))
	m.AddFirstPartyCaveat([]byte("expires_before = 2026-12-31T23:59:59Z"))

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m2 Macaroon
	if err := m2.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// All fields must match.
	if m2.Location() != m.Location() {
		t.Fatalf("location: got %q, want %q", m2.Location(), m.Location())
	}
	if !bytes.Equal(m2.Id(), m.Id()) {
		t.Fatal("id mismatch after roundtrip")
	}
	if m2.Signature() != m.Signature() {
		t.Fatalf("signature mismatch after roundtrip:\n  got  %x\n  want %x", m2.Signature(), m.Signature())
	}

	c1 := m.Caveats()
	c2 := m2.Caveats()
	if len(c1) != len(c2) {
		t.Fatalf("caveats count: got %d, want %d", len(c2), len(c1))
	}
	for i := range c1 {
		if !bytes.Equal(c1[i], c2[i]) {
			t.Fatalf("caveat[%d] mismatch", i)
		}
	}

	// Deserialized macaroon should verify with original key.
	caveats, err := m2.Verify(key)
	if err != nil {
		t.Fatalf("verify after roundtrip: %v", err)
	}
	if len(caveats) != 3 {
		t.Fatalf("caveats count after verify: %d", len(caveats))
	}
}

func TestMarshalUnmarshal_Empty(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}

	var m2 Macaroon
	if err := m2.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}

	if !bytes.Equal(m2.Id(), m.Id()) {
		t.Fatal("id mismatch")
	}
	if m2.Signature() != m.Signature() {
		t.Fatal("signature mismatch")
	}
	if len(m2.Caveats()) != 0 {
		t.Fatal("expected 0 caveats")
	}

	_, err = m2.Verify(key)
	if err != nil {
		t.Fatalf("verify empty macaroon: %v", err)
	}
}

func TestMarshalUnmarshal_ManyCaveats(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)

	// Add 60 caveats.
	for i := 0; i < 60; i++ {
		caveat := []byte("target IN [host" + string(rune('A'+i%26)) + "]")
		m.AddFirstPartyCaveat(caveat)
	}

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal many caveats: %v", err)
	}

	var m2 Macaroon
	if err := m2.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal many caveats: %v", err)
	}

	if len(m2.Caveats()) != 60 {
		t.Fatalf("caveats count: got %d, want 60", len(m2.Caveats()))
	}

	_, err = m2.Verify(key)
	if err != nil {
		t.Fatalf("verify many caveats: %v", err)
	}
}

func TestTokenSizeLimit(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)

	// Add caveats until we exceed MaxTokenSize.
	bigCaveat := make([]byte, 512)
	for i := range bigCaveat {
		bigCaveat[i] = 'x'
	}

	for i := 0; i < 20; i++ {
		m.AddFirstPartyCaveat(bigCaveat)
	}

	_, err := m.MarshalBinary()
	if err != ErrTokenTooLarge {
		t.Fatalf("expected ErrTokenTooLarge, got %v", err)
	}
}

func TestUnmarshal_TruncatedData(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)
	m.AddFirstPartyCaveat([]byte("target IN [a]"))

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Try various truncations.
	for _, truncLen := range []int{0, 1, 5, 10, len(data) - 1, len(data) - 32} {
		var m2 Macaroon
		err := m2.UnmarshalBinary(data[:truncLen])
		if err == nil {
			t.Fatalf("expected error for truncated data (len=%d), got nil", truncLen)
		}
	}
}

func TestUnmarshal_WrongVersion(t *testing.T) {
	data := []byte{0x01, 0, 0, 0, 0} // wrong version
	var m Macaroon
	if err := m.UnmarshalBinary(data); err != ErrMalformedToken {
		t.Fatalf("expected ErrMalformedToken for wrong version, got %v", err)
	}
}

func TestUnmarshal_ExtraTrailingBytes(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Append extra byte.
	data = append(data, 0xFF)
	var m2 Macaroon
	if err := m2.UnmarshalBinary(data); err != ErrMalformedToken {
		t.Fatalf("expected ErrMalformedToken for trailing bytes, got %v", err)
	}
}

func TestUnmarshal_Oversized(t *testing.T) {
	data := make([]byte, MaxTokenSize+1)
	data[0] = formatVersion
	var m Macaroon
	if err := m.UnmarshalBinary(data); err != ErrTokenTooLarge {
		t.Fatalf("expected ErrTokenTooLarge, got %v", err)
	}
}

func TestId_ReturnsCopy(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)

	got := m.Id()
	got[0] = 0xFF // mutate returned slice

	// Original should be unchanged.
	if m.Id()[0] == 0xFF {
		t.Fatal("Id() did not return a copy")
	}
}

func TestCaveats_ReturnsCopy(t *testing.T) {
	key := testKey()
	id := testID()
	m := New("ephyr-broker", id, key)
	m.AddFirstPartyCaveat([]byte("target IN [a]"))

	got := m.Caveats()
	got[0][0] = 0xFF // mutate returned slice

	// Original should be unchanged.
	if m.Caveats()[0][0] == 0xFF {
		t.Fatal("Caveats() did not return a deep copy")
	}
}

func TestNew_KeyIsolation(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	id := testID()

	m := New("ephyr-broker", id, key)
	sig1 := m.Signature()

	// Mutating the key after creation should not affect the macaroon.
	key[0] ^= 0xFF
	sig2 := m.Signature()

	if sig1 != sig2 {
		t.Fatal("mutating key after New() affected macaroon signature")
	}
}
