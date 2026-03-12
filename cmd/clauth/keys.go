package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// cmdInit generates an Ed25519 keypair at ~/.clauth/id_ed25519{,.pub}.
func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	force := fs.Bool("force", false, "Overwrite existing keypair")
	configDir := fs.String("config-dir", defaultConfigDir(), "Config directory")
	_ = fs.Parse(args)

	privPath := filepath.Join(*configDir, "id_ed25519")
	pubPath := filepath.Join(*configDir, "id_ed25519.pub")

	// Check if key already exists.
	if !*force {
		if _, err := os.Stat(privPath); err == nil {
			fmt.Fprintf(os.Stderr, "error: keypair already exists at %s\n", privPath)
			fmt.Fprintln(os.Stderr, "Use --force to overwrite.")
			os.Exit(1)
		}
	}

	// Ensure config directory exists.
	if err := os.MkdirAll(*configDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot create config dir %s: %v\n", *configDir, err)
		os.Exit(1)
	}

	// Ensure certs subdirectory exists.
	certsDir := filepath.Join(*configDir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot create certs dir %s: %v\n", certsDir, err)
		os.Exit(1)
	}

	// Generate Ed25519 keypair.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: keygen failed: %v\n", err)
		os.Exit(1)
	}

	// Marshal private key to OpenSSH PEM format.
	privPEM, err := ssh.MarshalPrivateKey(privKey, "clauth agent key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal private key: %v\n", err)
		os.Exit(1)
	}

	privPEMBytes := pem.EncodeToMemory(privPEM)

	// Write private key with 0600 permissions.
	if err := os.WriteFile(privPath, privPEMBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error: write private key: %v\n", err)
		os.Exit(1)
	}

	// Marshal public key to authorized_keys format.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: convert public key: %v\n", err)
		os.Exit(1)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)

	// Write public key with 0644 permissions.
	if err := os.WriteFile(pubPath, pubBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write public key: %v\n", err)
		os.Exit(1)
	}

	// Print fingerprint.
	fingerprint := sha256Fingerprint(sshPub)
	fmt.Printf("Keypair generated:\n")
	fmt.Printf("  Private: %s\n", privPath)
	fmt.Printf("  Public:  %s\n", pubPath)
	fmt.Printf("  Fingerprint: SHA256:%s\n", fingerprint)
}

// sha256Fingerprint returns the SHA256 fingerprint of an SSH public key
// in the standard base64 format (matching ssh-keygen -l).
func sha256Fingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	// Use base64 RawStdEncoding (no padding) to match OpenSSH format.
	return base64RawEncode(hash[:])
}

// base64RawEncode encodes bytes to base64 without padding (matching OpenSSH).
func base64RawEncode(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(data)*4+2)/3)
	for i := 0; i < len(data); i += 3 {
		var b0, b1, b2 byte
		b0 = data[i]
		if i+1 < len(data) {
			b1 = data[i+1]
		}
		if i+2 < len(data) {
			b2 = data[i+2]
		}

		result = append(result, alphabet[b0>>2])
		result = append(result, alphabet[((b0&0x03)<<4)|(b1>>4)])
		if i+1 < len(data) {
			result = append(result, alphabet[((b1&0x0F)<<2)|(b2>>6)])
		}
		if i+2 < len(data) {
			result = append(result, alphabet[b2&0x3F])
		}
	}
	return string(result)
}

// defaultConfigDir returns the default clauth config directory.
func defaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".clauth"
	}
	return filepath.Join(home, ".clauth")
}

// readPublicKey reads the agent's public key from the config directory.
func readPublicKey(configDir string) (string, error) {
	pubPath := filepath.Join(configDir, "id_ed25519.pub")
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return "", fmt.Errorf("read public key %s: %w (run 'clauth init' first)", pubPath, err)
	}
	return string(data), nil
}
