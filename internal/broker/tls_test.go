package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCACert creates a self-signed CA certificate and returns
// the PEM-encoded certificate and private key bytes.
func generateSelfSignedCACert(t *testing.T) (certPEM []byte, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func TestBuildTLSConfig_Insecure(t *testing.T) {
	cfg := TLSSettings{TLSVerify: false}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true when TLSVerify is false")
	}
}

func TestBuildTLSConfig_SystemCA(t *testing.T) {
	cfg := TLSSettings{TLSVerify: true}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=false when TLSVerify is true")
	}
	if tlsCfg.RootCAs != nil {
		t.Error("expected RootCAs to be nil (system store) when no custom CA is provided")
	}
	if tlsCfg.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Errorf("expected MinVersion=TLS1.2 (0x0303), got 0x%04x", tlsCfg.MinVersion)
	}
}

func TestBuildTLSConfig_CustomCAFile(t *testing.T) {
	certPEM, _ := generateSelfSignedCACert(t)

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	cfg := TLSSettings{
		TLSVerify: true,
		TLSCA:     caPath,
	}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected RootCAs to be set when custom CA file is provided")
	}
}

func TestBuildTLSConfig_InlineCA(t *testing.T) {
	certPEM, _ := generateSelfSignedCACert(t)

	cfg := TLSSettings{
		TLSVerify:   true,
		TLSCAInline: string(certPEM),
	}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected RootCAs to be set when inline CA PEM is provided")
	}
}

func TestBuildTLSConfig_Fingerprint(t *testing.T) {
	// Just verify that VerifyPeerCertificate is set when fingerprint is provided.
	cfg := TLSSettings{
		TLSVerify:      true,
		TLSFingerprint: "SHA256:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
	}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("expected VerifyPeerCertificate to be set when fingerprint is provided")
	}

	// Test the callback with a matching fingerprint.
	certPEM, _ := generateSelfSignedCACert(t)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	rawCert := block.Bytes
	hash := sha256.Sum256(rawCert)
	fingerprint := hex.EncodeToString(hash[:])

	cfg2 := TLSSettings{
		TLSVerify:      true,
		TLSFingerprint: fingerprint,
	}
	tlsCfg2, err := buildTLSConfig(cfg2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should pass with correct cert.
	if err := tlsCfg2.VerifyPeerCertificate([][]byte{rawCert}, nil); err != nil {
		t.Errorf("expected fingerprint match to pass, got: %v", err)
	}

	// Should fail with wrong cert.
	wrongCert := make([]byte, len(rawCert))
	copy(wrongCert, rawCert)
	wrongCert[0] ^= 0xFF // flip a byte
	if err := tlsCfg2.VerifyPeerCertificate([][]byte{wrongCert}, nil); err == nil {
		t.Error("expected fingerprint mismatch to fail")
	}

	// Should fail with no certs.
	if err := tlsCfg2.VerifyPeerCertificate([][]byte{}, nil); err == nil {
		t.Error("expected error when no certificates presented")
	}
}

func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	cfg := TLSSettings{
		TLSVerify: true,
		TLSCA:     "/nonexistent/path/ca.pem",
	}
	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Error("expected error for nonexistent CA file")
	}
}

func TestBuildTLSConfig_InvalidCAContent(t *testing.T) {
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "bad-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a valid PEM"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg := TLSSettings{
		TLSVerify: true,
		TLSCA:     caPath,
	}
	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid CA content")
	}
}

func TestBuildTLSConfig_InvalidInlineCA(t *testing.T) {
	cfg := TLSSettings{
		TLSVerify:   true,
		TLSCAInline: "not a valid PEM",
	}
	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid inline CA PEM")
	}
}

func TestNormalizeTLSFingerprint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "SHA256:AA:BB:CC:DD",
			expected: "aabbccdd",
		},
		{
			input:    "sha256:aa:bb:cc:dd",
			expected: "aabbccdd",
		},
		{
			input:    "AA:BB:CC:DD",
			expected: "aabbccdd",
		},
		{
			input:    "aabbccdd",
			expected: "aabbccdd",
		},
		{
			input:    "AABBCCDD",
			expected: "aabbccdd",
		},
		{
			input:    "SHA256:aAbBcCdD",
			expected: "aabbccdd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeTLSFingerprint(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeTLSFingerprint(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsTLSError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "x509 error",
			err:      &x509.UnknownAuthorityError{},
			expected: true,
		},
		{
			name:     "certificate string",
			err:      fmt.Errorf("certificate has expired"),
			expected: true,
		},
		{
			name:     "tls string",
			err:      fmt.Errorf("tls: handshake failure"),
			expected: true,
		},
		{
			name:     "fingerprint mismatch",
			err:      fmt.Errorf("TLS fingerprint mismatch: expected abc, got def"),
			expected: true,
		},
		{
			name:     "non-tls error",
			err:      fmt.Errorf("connection refused"),
			expected: false,
		},
		{
			name:     "timeout error",
			err:      fmt.Errorf("i/o timeout"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTLSError(tt.err)
			if result != tt.expected {
				t.Errorf("isTLSError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}
