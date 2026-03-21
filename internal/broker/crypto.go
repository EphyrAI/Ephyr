package broker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
)

// deriveEncryptionKey derives a 32-byte AES key from the EPHYR_ENCRYPTION_KEY
// environment variable using SHA-256. Returns nil if the variable is not set,
// which disables encryption (plaintext mode for backward compatibility).
func deriveEncryptionKey() ([]byte, error) {
	keyStr := os.Getenv("EPHYR_ENCRYPTION_KEY")
	if keyStr == "" {
		return nil, nil // no encryption configured — plaintext mode
	}
	hash := sha256.Sum256([]byte(keyStr))
	return hash[:], nil
}

// encryptValue encrypts a plaintext string with AES-256-GCM.
// Returns base64-encoded "enc:nonce:ciphertext" or original if no key.
func encryptValue(plaintext string, key []byte) (string, error) {
	if key == nil || plaintext == "" {
		return plaintext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return "enc:" + base64.StdEncoding.EncodeToString(nonce) + ":" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptValue decrypts an "enc:nonce:ciphertext" string.
// Returns plaintext as-is if not prefixed with "enc:".
func decryptValue(encoded string, key []byte) (string, error) {
	if !strings.HasPrefix(encoded, "enc:") {
		return encoded, nil // plaintext, not encrypted
	}
	if key == nil {
		return "", errors.New("encrypted value found but EPHYR_ENCRYPTION_KEY not set")
	}
	parts := strings.SplitN(encoded, ":", 3)
	if len(parts) != 3 {
		return "", errors.New("invalid encrypted value format")
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
