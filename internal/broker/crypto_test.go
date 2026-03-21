package broker

import (
	"os"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	os.Setenv("EPHYR_ENCRYPTION_KEY", "test-secret-key-12345")
	defer os.Unsetenv("EPHYR_ENCRYPTION_KEY")

	key, err := deriveEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}

	original := "ghp_abc123secrettoken"
	encrypted, err := encryptValue(original, key)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(encrypted, "enc:") {
		t.Fatalf("expected enc: prefix, got %s", encrypted)
	}
	if encrypted == original {
		t.Fatal("encrypted should differ from original")
	}

	decrypted, err := decryptValue(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != original {
		t.Fatalf("expected %s, got %s", original, decrypted)
	}
}

func TestNoKeyPlaintextPassthrough(t *testing.T) {
	encrypted, err := encryptValue("secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted != "secret" {
		t.Fatalf("expected passthrough, got %s", encrypted)
	}

	decrypted, err := decryptValue("secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != "secret" {
		t.Fatalf("expected passthrough, got %s", decrypted)
	}
}

func TestDecryptPlaintextLegacy(t *testing.T) {
	os.Setenv("EPHYR_ENCRYPTION_KEY", "test-key")
	defer os.Unsetenv("EPHYR_ENCRYPTION_KEY")

	key, _ := deriveEncryptionKey()
	// Legacy plaintext value (no "enc:" prefix) should pass through
	decrypted, err := decryptValue("plain-api-key", key)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != "plain-api-key" {
		t.Fatal("legacy plaintext should pass through")
	}
}

func TestEncryptedWithoutKeyFails(t *testing.T) {
	_, err := decryptValue("enc:abc:def", nil)
	if err == nil {
		t.Fatal("should fail when key not set")
	}
}

func TestEmptyStringPassthrough(t *testing.T) {
	key := make([]byte, 32)
	encrypted, err := encryptValue("", key)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted != "" {
		t.Fatal("empty string should pass through")
	}
}
