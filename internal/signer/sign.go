package signer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// SignParams contains all parameters needed to issue an SSH certificate.
type SignParams struct {
	// PublicKey is the raw authorized_key-format public key to certify.
	PublicKey []byte
	// Principals is the list of usernames/hosts the cert is valid for.
	Principals []string
	// Duration is how long the certificate is valid from now.
	Duration time.Duration
	// KeyID is the agent or entity identifier (used in Key ID field).
	KeyID string
	// ForceCommand, if non-empty, restricts the cert to a single command.
	ForceCommand string
}

// SignResult is returned after a successful signing operation.
type SignResult struct {
	// CertBytes is the certificate in authorized_key (MarshalAuthorizedKey) format.
	CertBytes []byte
	// Serial is the random serial number assigned to the certificate.
	Serial uint64
	// ExpiresAt is the wall-clock expiry time.
	ExpiresAt time.Time
}

// Sign creates and signs an SSH user certificate using the CA key.
func Sign(ca *CA, p SignParams) (*SignResult, error) {
	// Parse the user's public key.
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(p.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sign: parse public key: %w", err)
	}

	// Generate a cryptographically random serial number.
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("sign: generate serial: %w", err)
	}

	now := time.Now()
	validAfter := now.Add(-30 * time.Second)  // clock skew grace
	validBefore := now.Add(p.Duration)

	// Build Key ID: ephyr:{agent}@{target}:{serial_hex}
	keyID := fmt.Sprintf("ephyr:%s:%016x", p.KeyID, serial)

	// Standard extensions for interactive sessions.
	extensions := map[string]string{
		"permit-pty":              "",
		"permit-port-forwarding":  "",
		"permit-agent-forwarding": "",
	}

	// Critical options (e.g., force-command).
	var criticalOptions map[string]string
	if p.ForceCommand != "" {
		criticalOptions = map[string]string{
			"force-command": p.ForceCommand,
		}
	}

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pubKey,
		KeyId:           keyID,
		Serial:          serial,
		ValidPrincipals: p.Principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: ssh.Permissions{
			Extensions:      extensions,
			CriticalOptions: criticalOptions,
		},
	}

	// Sign the certificate with the CA key.
	if err := cert.SignCert(rand.Reader, ca.Signer()); err != nil {
		return nil, fmt.Errorf("sign: sign certificate: %w", err)
	}

	// Marshal to authorized_key format.
	certBytes := ssh.MarshalAuthorizedKey(cert)

	return &SignResult{
		CertBytes: certBytes,
		Serial:    serial,
		ExpiresAt: validBefore,
	}, nil
}

// randomSerial generates a cryptographically random uint64 serial number.
func randomSerial() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}
