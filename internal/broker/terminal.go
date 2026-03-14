package broker

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ben-spanswick/ephyr/internal/audit"
	"golang.org/x/crypto/ssh"
)

// TerminalRequest is sent as the first WebSocket message to specify the target
// host and authentication method for the SSH terminal session.
type TerminalRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`      // default 22
	User     string `json:"user"`
	AuthType string `json:"auth_type"`           // "password", "key", "certificate"
	Password string `json:"password,omitempty"`
	KeyData  string `json:"key_data,omitempty"`  // PEM-encoded private key
	Cols     int    `json:"cols,omitempty"`       // default 80
	Rows     int    `json:"rows,omitempty"`       // default 24
}

// TerminalMessage carries input data or resize events from the WebSocket client.
type TerminalMessage struct {
	Type string `json:"type"`           // "resize", "input"
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
	Data string `json:"data,omitempty"`
}

// terminalSession tracks the resources for a single terminal proxy connection.
type terminalSession struct {
	mu        sync.Mutex
	ws        *websocket.Conn
	sshClient *ssh.Client
	session   *ssh.Session
	stdin     io.WriteCloser
	closed    bool
}

// close tears down all resources associated with the terminal session.
func (ts *terminalSession) close() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.closed {
		return
	}
	ts.closed = true

	if ts.stdin != nil {
		ts.stdin.Close()
	}
	if ts.session != nil {
		ts.session.Close()
	}
	if ts.sshClient != nil {
		ts.sshClient.Close()
	}
	if ts.ws != nil {
		_ = ts.ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"))
		ts.ws.Close()
	}
}

// isClosed reports whether the session has been torn down.
func (ts *terminalSession) isClosed() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.closed
}

// terminalUpgrader allows all origins, matching the EventHub pattern.
var terminalUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// HandleTerminal handles WebSocket terminal proxy connections.
// Route: GET /v1/dashboard/terminal (on the TCP dashboard listener).
//
// Protocol:
//  1. Client connects via WebSocket (authenticated by dashboard token).
//  2. Client sends a TerminalRequest JSON message within 10 seconds.
//  3. Broker dials SSH to the target, requests a PTY, and starts a shell.
//  4. Bidirectional I/O is piped between WebSocket and SSH until either side closes.
func (bs *BrokerServer) HandleTerminal(w http.ResponseWriter, r *http.Request) {
	// Step 1: Upgrade to WebSocket.
	conn, err := terminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[terminal] websocket upgrade error: %v", err)
		return
	}

	// Step 2: Read first message as TerminalRequest (10s timeout).
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("[terminal] failed to read terminal request: %v", err)
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseProtocolError, "expected terminal request"))
		conn.Close()
		return
	}

	var req TerminalRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		writeWSError(conn, "invalid terminal request JSON: "+err.Error())
		conn.Close()
		return
	}

	// Apply defaults.
	if req.Port == 0 {
		req.Port = 22
	}
	if req.Cols == 0 {
		req.Cols = 80
	}
	if req.Rows == 0 {
		req.Rows = 24
	}

	// Step 3: Validate the request.
	if req.Host == "" {
		writeWSError(conn, "host is required")
		conn.Close()
		return
	}
	if req.User == "" {
		writeWSError(conn, "user is required")
		conn.Close()
		return
	}
	if req.AuthType == "" {
		writeWSError(conn, "auth_type is required")
		conn.Close()
		return
	}

	// Validate that the target host exists in policy.
	targetName := bs.findTargetByHost(req.Host, req.Port)
	if targetName == "" {
		writeWSError(conn, fmt.Sprintf("host %s:%d is not a known target in policy", req.Host, req.Port))
		conn.Close()
		return
	}

	// Step 4: Build SSH client config.
	sshConfig, err := buildSSHConfig(req)
	if err != nil {
		writeWSError(conn, "failed to configure SSH auth: "+err.Error())
		conn.Close()
		return
	}

	// Step 5: Dial SSH to the target.
	addr := net.JoinHostPort(req.Host, fmt.Sprintf("%d", req.Port))
	sshClient, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		writeWSError(conn, "SSH connection failed: "+err.Error())
		conn.Close()
		return
	}

	// Step 6: Open session, request PTY, start shell.
	session, err := sshClient.NewSession()
	if err != nil {
		writeWSError(conn, "failed to create SSH session: "+err.Error())
		sshClient.Close()
		conn.Close()
		return
	}

	// Request a pseudo-terminal.
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", req.Rows, req.Cols, modes); err != nil {
		writeWSError(conn, "PTY request failed: "+err.Error())
		session.Close()
		sshClient.Close()
		conn.Close()
		return
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		writeWSError(conn, "failed to get SSH stdin: "+err.Error())
		session.Close()
		sshClient.Close()
		conn.Close()
		return
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		writeWSError(conn, "failed to get SSH stdout: "+err.Error())
		session.Close()
		sshClient.Close()
		conn.Close()
		return
	}

	if err := session.Shell(); err != nil {
		writeWSError(conn, "failed to start shell: "+err.Error())
		session.Close()
		sshClient.Close()
		conn.Close()
		return
	}

	ts := &terminalSession{
		ws:        conn,
		sshClient: sshClient,
		session:   session,
		stdin:     stdin,
	}

	// Audit log: terminal session opened.
	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "terminal_open",
		Target:    targetName,
		Details: map[string]string{
			"host":      req.Host,
			"port":      fmt.Sprintf("%d", req.Port),
			"user":      req.User,
			"auth_type": req.AuthType,
			"remote":    r.RemoteAddr,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "terminal_open",
		Data: map[string]string{
			"target": targetName,
			"host":   req.Host,
			"user":   req.User,
		},
	})

	startTime := time.Now()

	// Clear the read deadline set earlier for the initial request.
	_ = conn.SetReadDeadline(time.Time{})

	// Step 7: Set up ping/pong keepalive (30s interval, same as EventHub).
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Time{})
		return nil
	})

	var wg sync.WaitGroup

	// Goroutine A: SSH stdout -> WebSocket (binary messages).
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer ts.close()

		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				if writeErr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
					log.Printf("[terminal] write to websocket error: %v", writeErr)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[terminal] read from SSH stdout error: %v", err)
				}
				return
			}
		}
	}()

	// Goroutine B: WebSocket -> SSH stdin (with resize handling).
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer ts.close()

		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("[terminal] read from websocket error: %v", err)
				}
				return
			}

			if ts.isClosed() {
				return
			}

			switch msgType {
			case websocket.TextMessage:
				// Try to parse as TerminalMessage for resize/input.
				var tmsg TerminalMessage
				if json.Unmarshal(data, &tmsg) == nil && tmsg.Type != "" {
					switch tmsg.Type {
					case "resize":
						if tmsg.Cols > 0 && tmsg.Rows > 0 {
							if err := session.WindowChange(tmsg.Rows, tmsg.Cols); err != nil {
								log.Printf("[terminal] window resize error: %v", err)
							}
						}
					case "input":
						if tmsg.Data != "" {
							if _, err := stdin.Write([]byte(tmsg.Data)); err != nil {
								log.Printf("[terminal] write to SSH stdin error: %v", err)
								return
							}
						}
					}
				} else {
					// Unparseable text: write directly to SSH stdin.
					if _, err := stdin.Write(data); err != nil {
						log.Printf("[terminal] write to SSH stdin error: %v", err)
						return
					}
				}

			case websocket.BinaryMessage:
				// Binary data: write directly to SSH stdin.
				if _, err := stdin.Write(data); err != nil {
					log.Printf("[terminal] write to SSH stdin error: %v", err)
					return
				}
			}
		}
	}()

	// Goroutine C: Ping keepalive (30s interval).
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(wsPingInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if ts.isClosed() {
					return
				}
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(wsWriteTimeout)); err != nil {
					log.Printf("[terminal] ping error: %v", err)
					ts.close()
					return
				}
			}
		}
	}()

	// Wait for SSH session to finish (shell exited).
	_ = session.Wait()

	// Ensure cleanup.
	ts.close()
	wg.Wait()

	duration := time.Since(startTime)

	// Audit log: terminal session closed.
	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "terminal_close",
		Target:    targetName,
		Duration:  duration.Round(time.Second).String(),
		Details: map[string]string{
			"host":   req.Host,
			"user":   req.User,
			"remote": r.RemoteAddr,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "terminal_close",
		Data: map[string]string{
			"target":   targetName,
			"host":     req.Host,
			"user":     req.User,
			"duration": duration.Round(time.Second).String(),
		},
	})
}

// buildSSHConfig creates an ssh.ClientConfig from the terminal request.
func buildSSHConfig(req TerminalRequest) (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            req.User,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	switch req.AuthType {
	case "password":
		if req.Password == "" {
			return nil, fmt.Errorf("password is required for auth_type \"password\"")
		}
		config.Auth = []ssh.AuthMethod{
			ssh.Password(req.Password),
		}

	case "key":
		if req.KeyData == "" {
			return nil, fmt.Errorf("key_data is required for auth_type \"key\"")
		}
		signer, err := ssh.ParsePrivateKey([]byte(req.KeyData))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}

	case "certificate":
		// Future: use CA-signed certificate for auth.
		return nil, fmt.Errorf("certificate auth is not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported auth_type %q (expected \"password\", \"key\", or \"certificate\")", req.AuthType)
	}

	return config, nil
}

// findTargetByHost looks up a target name from the policy by matching host and port.
func (bs *BrokerServer) findTargetByHost(host string, port int) string {
	bs.policyMu.RLock()
	defer bs.policyMu.RUnlock()

	for name, target := range bs.policyCfg.Raw.Targets {
		targetPort := target.Port
		if targetPort == 0 {
			targetPort = 22
		}
		if target.Host == host && targetPort == port {
			return name
		}
	}
	return ""
}

// writeWSError sends a JSON error message over the WebSocket and logs it.
func writeWSError(conn *websocket.Conn, msg string) {
	errPayload, _ := json.Marshal(map[string]string{"error": msg})
	_ = conn.WriteMessage(websocket.TextMessage, errPayload)
	log.Printf("[terminal] error: %s", msg)
}
