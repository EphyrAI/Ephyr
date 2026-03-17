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

func cmdSigner(args []string) {
	fs := flag.NewFlagSet("signer", flag.ExitOnError)

	var (
		caKeyPath  = fs.String("ca-key", envOrDefault("EPHYR_CA_KEY", "/etc/ephyr/ca_key"), "path to CA private key")
		socketPath = fs.String("socket", envOrDefault("EPHYR_SOCKET", "/run/ephyr/signer.sock"), "Unix socket path")
		brokerUID  = fs.Int("broker-uid", envOrDefaultInt("EPHYR_BROKER_UID", -1), "allowed caller UID (-1 = any)")
	)
	fs.Parse(args)

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

		go signerHandleConn(conn, ca, *brokerUID)
	}
}

// signerHandleConn processes a single IPC connection.
func signerHandleConn(conn net.Conn, ca *signer.CA, allowedUID int) {
	defer conn.Close()

	// Set a generous deadline for the entire exchange.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Validate caller UID via SO_PEERCRED if configured.
	if allowedUID >= 0 {
		if err := signerValidatePeerUID(conn, allowedUID); err != nil {
			signerWriteError(conn, fmt.Sprintf("unauthorized: %v", err))
			return
		}
	}

	// Decode request.
	var req signer.SignRequest
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		signerWriteError(conn, fmt.Sprintf("invalid request: %v", err))
		return
	}

	switch req.Action {
	case "ping":
		signerWriteJSON(conn, signer.SignResponse{Status: "ok"})

	case "sign":
		signerHandleSign(conn, ca, req)

	case "sign_delegation":
		signerHandleSignDelegation(conn, ca, req)

	case "root_public_key":
		signerHandleRootPublicKey(conn, ca)

	default:
		signerWriteError(conn, fmt.Sprintf("unknown action: %q", req.Action))
	}
}

// signerHandleSign processes a signing request.
func signerHandleSign(conn net.Conn, ca *signer.CA, req signer.SignRequest) {
	// Validate required fields.
	if req.PublicKey == "" {
		signerWriteError(conn, "public_key is required")
		return
	}
	if len(req.Principals) == 0 {
		signerWriteError(conn, "at least one principal is required")
		return
	}
	if req.Duration == "" {
		signerWriteError(conn, "duration is required")
		return
	}
	if req.KeyID == "" {
		signerWriteError(conn, "key_id is required")
		return
	}

	duration, err := time.ParseDuration(req.Duration)
	if err != nil {
		signerWriteError(conn, fmt.Sprintf("invalid duration %q: %v", req.Duration, err))
		return
	}

	// Cap maximum certificate lifetime at 24 hours.
	if duration > 24*time.Hour {
		signerWriteError(conn, "duration exceeds maximum of 24h")
		return
	}

	if duration <= 0 {
		signerWriteError(conn, "duration must be positive")
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
		signerWriteError(conn, fmt.Sprintf("signing failed: %v", err))
		return
	}

	resp := signer.SignResponse{
		Certificate: base64.StdEncoding.EncodeToString(result.CertBytes),
		Serial:      fmt.Sprintf("%016x", result.Serial),
		ExpiresAt:   result.ExpiresAt.UTC().Format(time.RFC3339),
	}
	signerWriteJSON(conn, resp)

	log.Printf("signed cert serial=%s key_id=%s principals=%v expires=%s",
		resp.Serial, req.KeyID, req.Principals, resp.ExpiresAt)
}

// signerHandleSignDelegation processes a delegation signing request.
func signerHandleSignDelegation(conn net.Conn, ca *signer.CA, req signer.SignRequest) {
	// Validate required fields.
	if req.BrokerPublicKey == "" {
		signerWriteError(conn, "broker_public_key is required")
		return
	}
	if req.BrokerID == "" {
		signerWriteError(conn, "broker_id is required")
		return
	}
	if req.DelegationTTL == "" {
		signerWriteError(conn, "delegation_ttl is required")
		return
	}

	// Decode the broker's public key from base64.
	brokerPubBytes, err := base64.StdEncoding.DecodeString(req.BrokerPublicKey)
	if err != nil {
		signerWriteError(conn, fmt.Sprintf("invalid broker_public_key base64: %v", err))
		return
	}

	// Parse the TTL.
	ttl, err := time.ParseDuration(req.DelegationTTL)
	if err != nil {
		signerWriteError(conn, fmt.Sprintf("invalid delegation_ttl %q: %v", req.DelegationTTL, err))
		return
	}

	// Delegate to the extracted signing function.
	result, err := signer.SignDelegation(ca, brokerPubBytes, req.BrokerID, ttl)
	if err != nil {
		signerWriteError(conn, fmt.Sprintf("delegation signing failed: %v", err))
		return
	}

	resp := signer.SignResponse{
		DelegationCertID: result.CertID,
		DelegationSig:    base64.StdEncoding.EncodeToString(result.Signature),
		ExpiresAt:        result.ExpiresAt.UTC().Format(time.RFC3339),
	}
	signerWriteJSON(conn, resp)

	log.Printf("signed delegation cert_id=%s broker_id=%s expires=%s",
		result.CertID, req.BrokerID, resp.ExpiresAt)
}

// signerHandleRootPublicKey returns the signer's root Ed25519 public key.
func signerHandleRootPublicKey(conn net.Conn, ca *signer.CA) {
	pubKey := ca.RawPublicKey()
	resp := signer.SignResponse{
		RootPublicKey: base64.StdEncoding.EncodeToString(pubKey),
	}
	signerWriteJSON(conn, resp)

	log.Printf("returned root public key")
}

// signerValidatePeerUID checks the connecting process UID via SO_PEERCRED.
func signerValidatePeerUID(conn net.Conn, allowedUID int) error {
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

// signerWriteError sends an error response.
func signerWriteError(conn net.Conn, msg string) {
	log.Printf("error: %s", msg)
	signerWriteJSON(conn, signer.SignResponse{Error: msg})
}

// signerWriteJSON encodes a value as JSON and writes it to the connection.
func signerWriteJSON(conn net.Conn, v interface{}) {
	enc := json.NewEncoder(conn)
	if err := enc.Encode(v); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}

// envOrDefaultInt returns the environment variable as int or the default.
func envOrDefaultInt(key string, def int) int {
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
