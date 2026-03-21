package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/EphyrAI/Ephyr/internal/signer"
)

func main() {
	var (
		caKeyPath  = flag.String("ca-key", envOr("EPHYR_CA_KEY", "/etc/ephyr/ca_key"), "path to CA private key")
		socketPath = flag.String("socket", envOr("EPHYR_SOCKET", "/run/ephyr/signer.sock"), "Unix socket path")
		brokerUID  = flag.Int("broker-uid", envOrInt("EPHYR_BROKER_UID", -1), "allowed caller UID (-1 = any)")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("ephyr-signer: ")

	// Load the CA key.
	ca, err := signer.LoadCA(*caKeyPath)
	if err != nil {
		log.Fatalf("failed to load CA key: %v", err)
	}
	log.Printf("CA loaded: %s", *caKeyPath)

	// Ensure the socket directory exists.
	sockDir := filepath.Dir(*socketPath)
	if err := os.MkdirAll(sockDir, 0750); err != nil {
		log.Fatalf("failed to create socket directory %s: %v", sockDir, err)
	}

	// Remove stale socket file if it exists.
	if err := os.Remove(*socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to remove stale socket %s: %v", *socketPath, err)
	}

	// Listen on the Unix socket.
	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *socketPath, err)
	}

	// Set socket permissions to 0660.
	if err := os.Chmod(*socketPath, 0660); err != nil {
		log.Fatalf("failed to chmod socket: %v", err)
	}

	log.Printf("listening on %s (broker-uid=%d)", *socketPath, *brokerUID)

	// Initialize signing rate limiter from environment.
	maxRate := 60 // default: 60 certs per window
	if v := os.Getenv("EPHYR_SIGNER_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			maxRate = n
		}
	}
	windowSecs := 60 // default: 60 second window
	if v := os.Getenv("EPHYR_SIGNER_RATE_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			windowSecs = n
		}
	}
	rateLimiter := signer.NewSignerRateLimiter(maxRate, time.Duration(windowSecs)*time.Second)
	log.Printf("[signer] rate limit: %d requests per %ds window", maxRate, windowSecs)

	// Graceful shutdown on SIGTERM/SIGINT.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-shutdown
		log.Printf("received %s, shutting down", sig)
		ln.Close()
	}()

	// Accept loop.
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if listener was closed (graceful shutdown).
			select {
			case <-shutdown:
				log.Println("listener closed, exiting")
				os.Remove(*socketPath)
				return
			default:
			}
			log.Printf("accept error: %v", err)
			continue
		}

		go handleConn(conn, ca, *brokerUID, rateLimiter)
	}
}

// handleConn processes a single IPC connection.
func handleConn(conn net.Conn, ca *signer.CA, allowedUID int, rl *signer.SignerRateLimiter) {
	defer conn.Close()

	// Set a generous deadline for the entire exchange.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Validate caller UID via SO_PEERCRED if configured.
	if allowedUID >= 0 {
		if err := validatePeerUID(conn, allowedUID); err != nil {
			writeError(conn, fmt.Sprintf("unauthorized: %v", err))
			return
		}
	}

	// Decode request.
	var req signer.SignRequest
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		writeError(conn, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Rate limit signing operations.
	if req.Action == "sign" || req.Action == "sign_delegation" {
		if !rl.Allow() {
			writeError(conn, "rate limit exceeded: too many signing requests")
			log.Printf("[signer] rate limit exceeded (%d in window)", rl.Count())
			return
		}
	}

	switch req.Action {
	case "ping":
		writeJSON(conn, signer.SignResponse{Status: "ok"})

	case "sign":
		handleSign(conn, ca, req)

	case "sign_delegation":
		handleSignDelegation(conn, ca, req)

	case "root_public_key":
		handleRootPublicKey(conn, ca)

	default:
		writeError(conn, fmt.Sprintf("unknown action: %q", req.Action))
	}
}

// handleSign processes a signing request.
func handleSign(conn net.Conn, ca *signer.CA, req signer.SignRequest) {
	// Validate required fields.
	if req.PublicKey == "" {
		writeError(conn, "public_key is required")
		return
	}
	if len(req.Principals) == 0 {
		writeError(conn, "at least one principal is required")
		return
	}
	if req.Duration == "" {
		writeError(conn, "duration is required")
		return
	}
	if req.KeyID == "" {
		writeError(conn, "key_id is required")
		return
	}

	duration, err := time.ParseDuration(req.Duration)
	if err != nil {
		writeError(conn, fmt.Sprintf("invalid duration %q: %v", req.Duration, err))
		return
	}

	// Cap maximum certificate lifetime at 24 hours.
	if duration > 24*time.Hour {
		writeError(conn, "duration exceeds maximum of 24h")
		return
	}

	if duration <= 0 {
		writeError(conn, "duration must be positive")
		return
	}

	result, err := signer.Sign(ca, signer.SignParams{
		PublicKey:    []byte(req.PublicKey),
		Principals:   req.Principals,
		Duration:     duration,
		KeyID:        req.KeyID,
		ForceCommand: req.ForceCommand,
	})
	if err != nil {
		writeError(conn, fmt.Sprintf("signing failed: %v", err))
		return
	}

	resp := signer.SignResponse{
		Certificate: base64.StdEncoding.EncodeToString(result.CertBytes),
		Serial:      fmt.Sprintf("%016x", result.Serial),
		ExpiresAt:   result.ExpiresAt.UTC().Format(time.RFC3339),
	}
	writeJSON(conn, resp)

	log.Printf("signed cert serial=%s key_id=%s principals=%v expires=%s",
		resp.Serial, req.KeyID, req.Principals, resp.ExpiresAt)
}

// handleSignDelegation processes a delegation signing request.
func handleSignDelegation(conn net.Conn, ca *signer.CA, req signer.SignRequest) {
	// Validate required fields.
	if req.BrokerPublicKey == "" {
		writeError(conn, "broker_public_key is required")
		return
	}
	if req.BrokerID == "" {
		writeError(conn, "broker_id is required")
		return
	}
	if req.DelegationTTL == "" {
		writeError(conn, "delegation_ttl is required")
		return
	}

	// Decode the broker's public key from base64.
	brokerPubBytes, err := base64.StdEncoding.DecodeString(req.BrokerPublicKey)
	if err != nil {
		writeError(conn, fmt.Sprintf("invalid broker_public_key base64: %v", err))
		return
	}

	// Parse the TTL.
	ttl, err := time.ParseDuration(req.DelegationTTL)
	if err != nil {
		writeError(conn, fmt.Sprintf("invalid delegation_ttl %q: %v", req.DelegationTTL, err))
		return
	}

	// Delegate to the extracted signing function.
	result, err := signer.SignDelegation(ca, brokerPubBytes, req.BrokerID, ttl)
	if err != nil {
		writeError(conn, fmt.Sprintf("delegation signing failed: %v", err))
		return
	}

	resp := signer.SignResponse{
		DelegationCertID: result.CertID,
		DelegationSig:    base64.StdEncoding.EncodeToString(result.Signature),
		ExpiresAt:        result.ExpiresAt.UTC().Format(time.RFC3339),
	}
	writeJSON(conn, resp)

	log.Printf("signed delegation cert_id=%s broker_id=%s expires=%s",
		result.CertID, req.BrokerID, resp.ExpiresAt)
}

// handleRootPublicKey returns the signer's root Ed25519 public key.
func handleRootPublicKey(conn net.Conn, ca *signer.CA) {
	pubKey := ca.RawPublicKey()
	resp := signer.SignResponse{
		RootPublicKey: base64.StdEncoding.EncodeToString(pubKey),
	}
	writeJSON(conn, resp)

	log.Printf("returned root public key")
}

// validatePeerUID checks the connecting process UID via SO_PEERCRED.
func validatePeerUID(conn net.Conn, allowedUID int) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get syscall conn: %w", err)
	}

	var cred *syscall.Ucred
	var credErr error

	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return fmt.Errorf("raw control: %w", err)
	}
	if credErr != nil {
		return fmt.Errorf("getsockopt peercred: %w", credErr)
	}

	if int(cred.Uid) != allowedUID {
		return fmt.Errorf("caller uid %d not allowed (want %d)", cred.Uid, allowedUID)
	}

	return nil
}

// writeError sends an error response.
func writeError(conn net.Conn, msg string) {
	log.Printf("error: %s", msg)
	writeJSON(conn, signer.SignResponse{Error: msg})
}

// writeJSON encodes a value as JSON and writes it to the connection.
func writeJSON(conn net.Conn, v interface{}) {
	enc := json.NewEncoder(conn)
	if err := enc.Encode(v); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}

// envOr returns the environment variable value or the default.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envOrInt returns the environment variable as int or the default.
func envOrInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
