package signer

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// CA holds the loaded certificate authority signing key.
type CA struct {
	signer  ssh.Signer
	pubKey  ssh.PublicKey
	rawPriv ed25519.PrivateKey
	rawPub  ed25519.PublicKey
}

// LoadCA reads an OpenSSH private key file (e.g. from ssh-keygen -t ed25519),
// validates that it is an Ed25519 key with correct file permissions (0600),
// and returns a CA ready to sign certificates.
func LoadCA(path string) (*CA, error) {
	// Check file permissions before reading.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ca: stat %s: %w", path, err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		return nil, fmt.Errorf("ca: %s has permissions %04o, want 0600", path, perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca: read %s: %w", path, err)
	}

	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("ca: parse private key: %w", err)
	}

	// Ensure the key is Ed25519.
	privKey, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca: key type %T is not Ed25519", raw)
	}

	signer, err := ssh.NewSignerFromKey(*privKey)
	if err != nil {
		return nil, fmt.Errorf("ca: create signer: %w", err)
	}

	return &CA{
		signer:  signer,
		pubKey:  signer.PublicKey(),
		rawPriv: *privKey,
		rawPub:  privKey.Public().(ed25519.PublicKey),
	}, nil
}

// NewCAFromKey creates a CA from an existing Ed25519 private key.
// Used in tests to avoid reading from disk.
func NewCAFromKey(privKey ed25519.PrivateKey) (*CA, error) {
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("ca: create signer: %w", err)
	}

	return &CA{
		signer:  signer,
		pubKey:  signer.PublicKey(),
		rawPriv: privKey,
		rawPub:  privKey.Public().(ed25519.PublicKey),
	}, nil
}

// Signer returns the ssh.Signer for signing certificates.
func (c *CA) Signer() ssh.Signer {
	return c.signer
}

// PublicKey returns the CA's public key.
func (c *CA) PublicKey() ssh.PublicKey {
	return c.pubKey
}

// RawPrivateKey returns the underlying Ed25519 private key for non-SSH signing.
func (c *CA) RawPrivateKey() ed25519.PrivateKey {
	return c.rawPriv
}

// RawPublicKey returns the Ed25519 public key bytes.
func (c *CA) RawPublicKey() ed25519.PublicKey {
	return c.rawPub
}
