package broker

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// TLSSettings holds per-service/per-remote TLS verification configuration.
// When TLSVerify is false (the default), certificate verification is skipped
// for backward compatibility with self-signed or internal PKI deployments.
type TLSSettings struct {
	TLSVerify      bool   `json:"tls_verify,omitempty"`
	TLSCA          string `json:"tls_ca,omitempty"`
	TLSCAInline    string `json:"tls_ca_inline,omitempty"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
}

// buildTLSConfig constructs a *tls.Config from the given TLSSettings.
//
// When TLSVerify is false, InsecureSkipVerify is set to true (backward
// compatible default). When TLSVerify is true, the system CA store is used
// unless a custom CA file or inline PEM is provided. An optional SHA-256
// fingerprint pins the leaf certificate.
func buildTLSConfig(cfg TLSSettings) (*tls.Config, error) {
	if !cfg.TLSVerify {
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec // intentional opt-out
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	// Load custom CA bundle from file or inline PEM.
	if cfg.TLSCA != "" || cfg.TLSCAInline != "" {
		pool := x509.NewCertPool()
		if cfg.TLSCA != "" {
			caCert, err := os.ReadFile(cfg.TLSCA)
			if err != nil {
				return nil, fmt.Errorf("read TLS CA %s: %w", cfg.TLSCA, err)
			}
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("no valid certs in %s", cfg.TLSCA)
			}
		}
		if cfg.TLSCAInline != "" {
			if !pool.AppendCertsFromPEM([]byte(cfg.TLSCAInline)) {
				return nil, fmt.Errorf("no valid certs in tls_ca_inline")
			}
		}
		tlsConfig.RootCAs = pool
	}

	// Certificate fingerprint pinning (SHA-256 of the leaf DER).
	if cfg.TLSFingerprint != "" {
		expected := normalizeTLSFingerprint(cfg.TLSFingerprint)
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server certificate presented")
			}
			hash := sha256.Sum256(rawCerts[0])
			actual := hex.EncodeToString(hash[:])
			if actual != expected {
				return fmt.Errorf("TLS fingerprint mismatch: expected %s, got %s", expected, actual)
			}
			return nil
		}
	}

	return tlsConfig, nil
}

// normalizeTLSFingerprint strips common prefixes, lowercases, and removes
// colon separators from a certificate fingerprint string.
func normalizeTLSFingerprint(fp string) string {
	fp = strings.TrimPrefix(fp, "SHA256:")
	fp = strings.TrimPrefix(fp, "sha256:")
	fp = strings.ToLower(fp)
	fp = strings.ReplaceAll(fp, ":", "")
	return fp
}

// isTLSError returns true if the error appears to be TLS-related, useful for
// providing targeted diagnostics in log messages.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "x509:") ||
		strings.Contains(s, "tls:") ||
		strings.Contains(s, "certificate") ||
		strings.Contains(s, "TLS fingerprint")
}
