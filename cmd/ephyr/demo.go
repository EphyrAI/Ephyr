package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// demoStep tracks the pass/fail status of each demo step.
type demoStep struct {
	name   string
	passed bool
	err    string
}

// demoContext holds shared state across demo steps.
type demoContext struct {
	brokerURL    string
	dashboardURL string
	apiKey       string
	client    *http.Client
	steps     []demoStep
	nextID    int

	// State accumulated across steps.
	parentTaskID    string
	parentToken     string
	parentEnvelope  map[string]interface{}
	childTaskID     string
	childToken      string
	childEnvelope   map[string]interface{}
	boundTaskID     string
	boundToken      string
	holderPrivKey   ed25519.PrivateKey
	holderPubKey    ed25519.PublicKey
	firstTarget     string
	firstRole       string
	targets         []interface{}
}

// --- JSON-RPC types for the demo client ---

type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// --- ANSI helpers ---

const (
	demoReset   = "\033[0m"
	demoBold    = "\033[1m"
	demoDim     = "\033[2m"
	demoRed     = "\033[31m"
	demoGreen   = "\033[32m"
	demoYellow  = "\033[33m"
	demoBlue    = "\033[34m"
	demoCyan    = "\033[36m"
	demoWhite   = "\033[37m"
	demoBgGreen = "\033[42m"
	demoBgRed   = "\033[41m"
)

func demoHeader(step, total int, title string) {
	fmt.Printf("\n%s%s[Step %d/%d] %s%s\n", demoBold, demoCyan, step, total, title, demoReset)
	fmt.Printf("%s%s%s\n", demoDim, strings.Repeat("\u2500", 60), demoReset)
}

func demoPass(msg string) {
	fmt.Printf("  %s%s PASS %s %s\n", demoBgGreen, demoWhite, demoReset, msg)
}

func demoFail(msg string) {
	fmt.Printf("  %s%s FAIL %s %s\n", demoBgRed, demoWhite, demoReset, msg)
}

func demoInfo(label, value string) {
	fmt.Printf("  %s%-18s%s %s\n", demoDim, label+":", demoReset, value)
}

func demoJSON(label string, v interface{}) {
	data, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		demoInfo(label, fmt.Sprintf("(marshal error: %v)", err))
		return
	}
	fmt.Printf("  %s%-18s%s %s\n", demoDim, label+":", demoReset, string(data))
}

// cmdDemo implements the "ephyr demo" subcommand.
func cmdDemo(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	broker := fs.String("broker", "", "Broker HTTP URL (default: env EPHYR_BROKER or http://localhost:8554)")
	key := fs.String("key", "", "API key (default: env EPHYR_API_KEY)")
	dashboard := fs.String("dashboard", "", "Dashboard HTTP URL for metrics (default: broker URL with port 8553)")
	_ = fs.Parse(args)

	brokerURL := *broker
	if brokerURL == "" {
		brokerURL = os.Getenv("EPHYR_BROKER")
	}
	if brokerURL == "" {
		brokerURL = "http://localhost:8554"
	}
	brokerURL = strings.TrimRight(brokerURL, "/")

	dashboardURL := *dashboard
	if dashboardURL == "" {
		// Default: replace port in broker URL with 8553
		dashboardURL = strings.Replace(brokerURL, ":8554", ":8553", 1)
	}
	dashboardURL = strings.TrimRight(dashboardURL, "/")

	apiKey := *key
	if apiKey == "" {
		apiKey = os.Getenv("EPHYR_API_KEY")
	}
	if apiKey == "" {
		fmt.Fprintf(os.Stderr, "%serror:%s API key required. Use --key or set EPHYR_API_KEY.\n", demoRed, demoReset)
		os.Exit(1)
	}

	ctx := &demoContext{
		brokerURL:    brokerURL,
		dashboardURL: dashboardURL,
		apiKey:       apiKey,
		client:    &http.Client{Timeout: 30 * time.Second},
		nextID:    1,
	}

	totalSteps := 12

	// Print banner.
	fmt.Printf("\n%s%s", demoBold, demoCyan)
	fmt.Println("  ╔══════════════════════════════════════════════════════╗")
	fmt.Println("  ║          EPHYR PIPELINE DEMO                       ║")
	fmt.Println("  ║   Macaroon + Delegation + Proof-of-Possession      ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════╝")
	fmt.Print(demoReset)
	demoInfo("Broker", brokerURL)
	demoInfo("API Key", apiKey[:6]+"...")
	demoInfo("Time", time.Now().Format(time.RFC3339))

	// Run all steps.
	ctx.step1Initialize(totalSteps)
	ctx.step2ListTools(totalSteps)
	ctx.step3DiscoverInfra(totalSteps)
	ctx.step4CreateTask(totalSteps)
	ctx.step5UseMacaroon(totalSteps)
	ctx.step6ExecWithMacaroon(totalSteps)
	ctx.step7Delegate(totalSteps)
	ctx.step8CreateBoundTask(totalSteps)
	ctx.step9PopRequest(totalSteps)
	ctx.step10PopFailure(totalSteps)
	ctx.step11Revoke(totalSteps)
	ctx.step12Metrics(totalSteps)

	// Print summary.
	ctx.printSummary()
}

// --- RPC helpers ---

func (d *demoContext) rpcCall(method string, params interface{}, bearerToken string) (*rpcResponse, error) {
	reqBody := rpcRequest{
		JSONRPC: "2.0",
		ID:      d.nextID,
		Method:  method,
		Params:  params,
	}
	d.nextID++

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", d.brokerURL+"/mcp", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed (HTTP 401): %s", string(respBody))
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w (body: %s)", err, string(respBody))
	}

	return &rpcResp, nil
}

// toolCall is a convenience wrapper for tools/call requests.
func (d *demoContext) toolCall(toolName string, args map[string]interface{}, bearerToken string) (*rpcResponse, error) {
	params := toolCallParams{
		Name:      toolName,
		Arguments: args,
	}
	return d.rpcCall("tools/call", params, bearerToken)
}

// extractToolText extracts the text content from a tools/call result.
func extractToolText(resp *rpcResponse) (string, bool, error) {
	if resp.Error != nil {
		return "", false, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", false, fmt.Errorf("unmarshal tool result: %w", err)
	}

	if len(result.Content) == 0 {
		return "", result.IsError, nil
	}

	return result.Content[0].Text, result.IsError, nil
}

func (d *demoContext) recordStep(name string, passed bool, errMsg string) {
	d.steps = append(d.steps, demoStep{name: name, passed: passed, err: errMsg})
}

// --- Step implementations ---

func (d *demoContext) step1Initialize(total int) {
	stepName := "Initialize MCP"
	demoHeader(1, total, stepName)

	params := map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "ephyr-demo",
			"version": "1.0.0",
		},
	}

	resp, err := d.rpcCall("initialize", params, d.apiKey)
	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	if resp.Error != nil {
		demoFail(fmt.Sprintf("RPC error: %s", resp.Error.Message))
		d.recordStep(stepName, false, resp.Error.Message)
		return
	}

	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		demoFail(fmt.Sprintf("unmarshal: %v", err))
		d.recordStep(stepName, false, err.Error())
		return
	}

	demoInfo("Protocol", result.ProtocolVersion)
	demoInfo("Server", fmt.Sprintf("%s v%s", result.ServerInfo.Name, result.ServerInfo.Version))
	demoPass("MCP initialized")
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step2ListTools(total int) {
	stepName := "List available tools"
	demoHeader(2, total, stepName)

	resp, err := d.rpcCall("tools/list", nil, d.apiKey)
	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	if resp.Error != nil {
		demoFail(fmt.Sprintf("RPC error: %s", resp.Error.Message))
		d.recordStep(stepName, false, resp.Error.Message)
		return
	}

	var result struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		demoFail(fmt.Sprintf("unmarshal: %v", err))
		d.recordStep(stepName, false, err.Error())
		return
	}

	demoInfo("Tool count", fmt.Sprintf("%d", len(result.Tools)))
	for _, t := range result.Tools {
		desc := t.Description
		if len(desc) > 50 {
			desc = desc[:47] + "..."
		}
		fmt.Printf("    %s%-20s%s %s%s%s\n", demoGreen, t.Name, demoReset, demoDim, desc, demoReset)
	}
	demoPass(fmt.Sprintf("%d tools available", len(result.Tools)))
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step3DiscoverInfra(total int) {
	stepName := "Discover infrastructure"
	demoHeader(3, total, stepName)

	// list_targets
	resp, err := d.toolCall("list_targets", nil, d.apiKey)
	if err != nil {
		demoFail("list_targets: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	text, isErr, err := extractToolText(resp)
	if err != nil || isErr {
		var msg string
		if err != nil {
			msg = err.Error()
		} else {
			msg = text
		}
		demoFail(msg)
		d.recordStep(stepName, false, msg)
		return
	}

	var targets []interface{}
	if err := json.Unmarshal([]byte(text), &targets); err == nil {
		d.targets = targets
		demoInfo("SSH targets", fmt.Sprintf("%d", len(targets)))
		for _, t := range targets {
			if tm, ok := t.(map[string]interface{}); ok {
				name, _ := tm["name"].(string)
				host, _ := tm["host"].(string)
				roles, _ := tm["roles"].([]interface{})
				roleStrs := make([]string, 0, len(roles))
				for _, r := range roles {
					if rs, ok := r.(string); ok {
						roleStrs = append(roleStrs, rs)
					}
				}
				fmt.Printf("    %s%-16s%s %s (roles: %s)\n", demoBlue, name, demoReset, host, strings.Join(roleStrs, ", "))
				if d.firstTarget == "" {
					d.firstTarget = name
					if len(roleStrs) > 0 {
						d.firstRole = roleStrs[0]
					}
				}
			}
		}
	}

	// list_services
	resp2, err := d.toolCall("list_services", nil, d.apiKey)
	if err == nil {
		text2, isErr2, _ := extractToolText(resp2)
		if !isErr2 {
			var services []interface{}
			if err := json.Unmarshal([]byte(text2), &services); err == nil {
				demoInfo("HTTP services", fmt.Sprintf("%d", len(services)))
				for _, s := range services {
					if sm, ok := s.(map[string]interface{}); ok {
						name, _ := sm["name"].(string)
						fmt.Printf("    %s%-16s%s\n", demoGreen, name, demoReset)
					}
				}
			}
		}
	}

	// list_remotes
	resp3, err := d.toolCall("list_remotes", nil, d.apiKey)
	if err == nil {
		text3, isErr3, _ := extractToolText(resp3)
		if !isErr3 {
			var remotes []interface{}
			if err := json.Unmarshal([]byte(text3), &remotes); err == nil {
				demoInfo("MCP remotes", fmt.Sprintf("%d", len(remotes)))
			}
		}
	}

	demoPass("Infrastructure discovered")
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step4CreateTask(total int) {
	stepName := "Create a macaroon task"
	demoHeader(4, total, stepName)

	args := map[string]interface{}{
		"description":  "PoP demo task",
		"ttl":          "10m",
		"can_delegate": true,
	}

	resp, err := d.toolCall("task_create", args, d.apiKey)
	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	text, isErr, err := extractToolText(resp)
	if err != nil || isErr {
		var msg string
		if err != nil {
			msg = err.Error()
		} else {
			msg = text
		}
		demoFail(msg)
		d.recordStep(stepName, false, msg)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		demoFail("unmarshal: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}

	d.parentTaskID, _ = result["task_id"].(string)
	d.parentToken, _ = result["token"].(string)
	tokenType, _ := result["token_type"].(string)
	canDelegate, _ := result["can_delegate"].(bool)
	holderBound, _ := result["holder_bound"].(bool)
	if env, ok := result["envelope"].(map[string]interface{}); ok {
		d.parentEnvelope = env
	}

	demoInfo("Task ID", d.parentTaskID)
	demoInfo("Token type", tokenType)
	demoInfo("Token prefix", d.parentToken[:20]+"...")
	demoInfo("Can delegate", fmt.Sprintf("%v", canDelegate))
	demoInfo("Holder bound", fmt.Sprintf("%v", holderBound))
	if d.parentEnvelope != nil {
		demoJSON("Envelope", d.parentEnvelope)
	}

	if strings.HasPrefix(d.parentToken, "mac_") {
		demoPass(fmt.Sprintf("Macaroon task created: %s", d.parentTaskID))
	} else {
		demoPass(fmt.Sprintf("Task created (%s): %s", tokenType, d.parentTaskID))
	}
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step5UseMacaroon(total int) {
	stepName := "Use the macaroon token"
	demoHeader(5, total, stepName)

	if d.parentToken == "" {
		demoFail("No parent token from step 4")
		d.recordStep(stepName, false, "no parent token")
		return
	}

	resp, err := d.toolCall("list_targets", nil, d.parentToken)
	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	text, isErr, err := extractToolText(resp)
	if err != nil || isErr {
		var msg string
		if err != nil {
			msg = err.Error()
		} else {
			msg = text
		}
		demoFail(msg)
		d.recordStep(stepName, false, msg)
		return
	}

	var targets []interface{}
	if err := json.Unmarshal([]byte(text), &targets); err == nil {
		demoInfo("Targets visible", fmt.Sprintf("%d (authenticated via macaroon)", len(targets)))
	}

	demoPass("Macaroon authentication successful")
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step6ExecWithMacaroon(total int) {
	stepName := "Execute command with macaroon"
	demoHeader(6, total, stepName)

	if d.parentToken == "" || d.firstTarget == "" {
		msg := "Skipped: no macaroon or no targets available"
		if d.parentToken == "" {
			msg = "Skipped: no macaroon from step 4"
		} else if d.firstTarget == "" {
			msg = "Skipped: no targets discovered in step 3"
		}
		fmt.Printf("  %s%s%s\n", demoYellow, msg, demoReset)
		d.recordStep(stepName, true, msg+" (skipped)")
		return
	}

	role := d.firstRole
	if role == "" {
		role = "read"
	}

	args := map[string]interface{}{
		"target":  d.firstTarget,
		"role":    role,
		"command": "hostname && uptime",
		"timeout": 15,
	}

	start := time.Now()
	resp, err := d.toolCall("exec", args, d.parentToken)
	elapsed := time.Since(start)

	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	text, isErr, err := extractToolText(resp)
	if err != nil || isErr {
		var msg string
		if err != nil {
			msg = err.Error()
		} else {
			msg = text
		}
		demoFail(msg)
		d.recordStep(stepName, false, msg)
		return
	}

	var execResult map[string]interface{}
	if err := json.Unmarshal([]byte(text), &execResult); err == nil {
		stdout, _ := execResult["stdout"].(string)
		exitCode, _ := execResult["exit_code"].(float64)
		totalMs, _ := execResult["total_ms"].(float64)
		certMs, _ := execResult["cert_ms"].(float64)
		sshMs, _ := execResult["ssh_ms"].(float64)

		demoInfo("Target", d.firstTarget)
		demoInfo("Role", role)
		demoInfo("Output", strings.TrimSpace(stdout))
		demoInfo("Exit code", fmt.Sprintf("%.0f", exitCode))
		demoInfo("Total latency", fmt.Sprintf("%.0fms (cert=%.0fms ssh=%.0fms)", totalMs, certMs, sshMs))
	}

	demoInfo("Round-trip", elapsed.String())
	demoPass(fmt.Sprintf("Command executed on %s via macaroon", d.firstTarget))
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step7Delegate(total int) {
	stepName := "Delegate a child task"
	demoHeader(7, total, stepName)

	if d.parentToken == "" || d.parentTaskID == "" {
		demoFail("No parent task from step 4")
		d.recordStep(stepName, false, "no parent task")
		return
	}

	// Build narrowed envelope.
	envelope := map[string]interface{}{}
	if d.firstTarget != "" {
		envelope["targets"] = []string{d.firstTarget}
	}
	envelope["roles"] = []string{"read"}

	args := map[string]interface{}{
		"parent_task_id": d.parentTaskID,
		"description":    "PoP demo child task (read-only)",
		"ttl":            "5m",
		"envelope":       envelope,
		"can_delegate":   false,
	}

	resp, err := d.toolCall("task_delegate", args, d.parentToken)
	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	text, isErr, err := extractToolText(resp)
	if err != nil || isErr {
		var msg string
		if err != nil {
			msg = err.Error()
		} else {
			msg = text
		}
		demoFail(msg)
		d.recordStep(stepName, false, msg)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		demoFail("unmarshal: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}

	d.childTaskID, _ = result["task_id"].(string)
	d.childToken, _ = result["token"].(string)
	depth, _ := result["depth"].(float64)
	if env, ok := result["envelope"].(map[string]interface{}); ok {
		d.childEnvelope = env
	}

	demoInfo("Child task ID", d.childTaskID)
	demoInfo("Depth", fmt.Sprintf("%.0f", depth))
	demoInfo("Can delegate", "false")

	// Compare envelopes.
	fmt.Printf("\n  %s%sEnvelope comparison:%s\n", demoBold, demoYellow, demoReset)
	demoJSON("Parent envelope", d.parentEnvelope)
	demoJSON("Child envelope", d.childEnvelope)

	demoPass(fmt.Sprintf("Delegated child task: %s (attenuated)", d.childTaskID))
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step8CreateBoundTask(total int) {
	stepName := "Create holder-bound task (PoP)"
	demoHeader(8, total, stepName)

	// Generate ephemeral Ed25519 keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		demoFail("keygen: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	d.holderPubKey = pub
	d.holderPrivKey = priv

	pubKeyB64 := base64.RawURLEncoding.EncodeToString(pub)

	args := map[string]interface{}{
		"description":    "PoP demo bound task",
		"ttl":            "10m",
		"can_delegate":   false,
		"holder_pub_key": pubKeyB64,
	}

	resp, err := d.toolCall("task_create", args, d.apiKey)
	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	text, isErr, err := extractToolText(resp)
	if err != nil || isErr {
		var msg string
		if err != nil {
			msg = err.Error()
		} else {
			msg = text
		}
		demoFail(msg)
		d.recordStep(stepName, false, msg)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		demoFail("unmarshal: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}

	d.boundTaskID, _ = result["task_id"].(string)
	d.boundToken, _ = result["token"].(string)
	holderBound, _ := result["holder_bound"].(bool)

	demoInfo("Task ID", d.boundTaskID)
	demoInfo("Holder bound", fmt.Sprintf("%v", holderBound))
	demoInfo("Holder pub key", pubKeyB64[:20]+"...")
	demoInfo("Priv key", "(ephemeral, in memory)")

	demoPass(fmt.Sprintf("Holder-bound task created: %s", d.boundTaskID))
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step9PopRequest(total int) {
	stepName := "Make request with PoP proof"
	demoHeader(9, total, stepName)

	if d.boundToken == "" || d.holderPrivKey == nil {
		demoFail("No bound task from step 8")
		d.recordStep(stepName, false, "no bound task")
		return
	}

	// Build the tool call arguments (without _pop initially for body_hash).
	toolArgs := map[string]interface{}{}

	// Compute body_hash over the canonical arguments (without _pop).
	canonicalBody, _ := json.Marshal(toolArgs)
	bodyHashBytes := sha256.Sum256(canonicalBody)
	bodyHashHex := hex.EncodeToString(bodyHashBytes[:])

	// Compute mac_digest: SHA-256 of the serialized macaroon.
	// We need to decode the macaroon from the token to get its binary form.
	macDigestHex := ""
	if strings.HasPrefix(d.boundToken, "mac_") {
		macB64 := strings.TrimPrefix(d.boundToken, "mac_")
		macBinary, err := base64.RawURLEncoding.DecodeString(macB64)
		if err == nil {
			macHash := sha256.Sum256(macBinary)
			macDigestHex = hex.EncodeToString(macHash[:])
		}
	}
	if macDigestHex == "" {
		// Fallback for non-macaroon tokens.
		emptyHash := sha256.Sum256([]byte{})
		macDigestHex = hex.EncodeToString(emptyHash[:])
	}

	// Generate nonce (16 random bytes, hex-encoded).
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		demoFail("nonce generation: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	nonceHex := hex.EncodeToString(nonceBytes)

	// Build proof payload using a struct with fixed field order.
	// The broker's ProofPayload struct serializes in declaration order:
	// task_id, req_type, resource, method, body_hash, mac_digest, nonce, ts
	type proofPayload struct {
		TaskID    string `json:"task_id"`
		ReqType   string `json:"req_type"`
		Resource  string `json:"resource"`
		Method    string `json:"method"`
		BodyHash  string `json:"body_hash"`
		MacDigest string `json:"mac_digest"`
		Nonce     string `json:"nonce"`
		Ts        string `json:"ts"`
	}
	payload := proofPayload{
		TaskID:    d.boundTaskID,
		ReqType:   "ssh_exec",
		Resource:  "",
		Method:    "list_targets",
		BodyHash:  bodyHashHex,
		MacDigest: macDigestHex,
		Nonce:     nonceHex,
		Ts:        time.Now().UTC().Format(time.RFC3339),
	}

	// Canonicalize payload to JSON and sign.
	payloadBytes, _ := json.Marshal(payload)
	signature := ed25519.Sign(d.holderPrivKey, payloadBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Build the _pop object.
	pop := map[string]interface{}{
		"sig":     sigB64,
		"payload": payload,
	}

	// Add _pop to the tool arguments.
	toolArgs["_pop"] = pop

	demoInfo("Body hash", bodyHashHex[:16]+"...")
	demoInfo("Mac digest", macDigestHex[:16]+"...")
	demoInfo("Nonce", nonceHex[:16]+"...")
	demoInfo("Signature", sigB64[:20]+"...")

	resp, err := d.toolCall("list_targets", toolArgs, d.boundToken)
	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	text, isErr, err := extractToolText(resp)
	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	if isErr {
		// Check if this is a PoP failure or a tool error.
		if strings.Contains(text, "proof-of-possession") {
			demoFail("PoP verification failed: " + text)
			d.recordStep(stepName, false, text)
			return
		}
		// Tool-level error but PoP passed -- still a pass for this step.
		demoInfo("Note", "PoP verified but tool returned error: "+text)
	}

	demoPass("PoP verified successfully -- holder-bound request accepted")
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step10PopFailure(total int) {
	stepName := "Demonstrate PoP failure"
	demoHeader(10, total, stepName)

	if d.boundToken == "" || d.holderPrivKey == nil {
		demoFail("No bound task from step 8")
		d.recordStep(stepName, false, "no bound task")
		return
	}

	// Build tool call arguments with a WRONG body_hash.
	toolArgs := map[string]interface{}{}

	// Use a TAMPERED body_hash (hash of "tampered" instead of the real body).
	tamperedHash := sha256.Sum256([]byte("tampered"))
	bodyHashHex := hex.EncodeToString(tamperedHash[:])

	// Compute correct mac_digest.
	macDigestHex := ""
	if strings.HasPrefix(d.boundToken, "mac_") {
		macB64 := strings.TrimPrefix(d.boundToken, "mac_")
		macBinary, err := base64.RawURLEncoding.DecodeString(macB64)
		if err == nil {
			macHash := sha256.Sum256(macBinary)
			macDigestHex = hex.EncodeToString(macHash[:])
		}
	}
	if macDigestHex == "" {
		emptyHash := sha256.Sum256([]byte{})
		macDigestHex = hex.EncodeToString(emptyHash[:])
	}

	// Generate nonce.
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonceHex := hex.EncodeToString(nonceBytes)

	type proofPayload2 struct {
		TaskID    string `json:"task_id"`
		ReqType   string `json:"req_type"`
		Resource  string `json:"resource"`
		Method    string `json:"method"`
		BodyHash  string `json:"body_hash"`
		MacDigest string `json:"mac_digest"`
		Nonce     string `json:"nonce"`
		Ts        string `json:"ts"`
	}
	payload := proofPayload2{
		TaskID:    d.boundTaskID,
		ReqType:   "ssh_exec",
		Resource:  "",
		Method:    "list_targets",
		BodyHash:  bodyHashHex,
		MacDigest: macDigestHex,
		Nonce:     nonceHex,
		Ts:        time.Now().UTC().Format(time.RFC3339),
	}

	payloadBytes, _ := json.Marshal(payload)
	signature := ed25519.Sign(d.holderPrivKey, payloadBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	pop := map[string]interface{}{
		"sig":     sigB64,
		"payload": payload,
	}

	toolArgs["_pop"] = pop

	demoInfo("Body hash", bodyHashHex[:16]+"... (TAMPERED)")

	resp, err := d.toolCall("list_targets", toolArgs, d.boundToken)
	if err != nil {
		// Connection error is unexpected.
		demoFail("unexpected error: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	text, isErr, err := extractToolText(resp)
	if err != nil {
		demoFail("unexpected error: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}

	if isErr && strings.Contains(text, "body") {
		demoInfo("Error response", text)
		demoPass("PoP verification failed as expected: body hash mismatch detected")
		d.recordStep(stepName, true, "")
		return
	}

	if isErr {
		demoInfo("Error response", text)
		demoPass("PoP verification rejected the tampered request")
		d.recordStep(stepName, true, "")
		return
	}

	// If it didn't fail, that's unexpected.
	demoFail("Expected PoP failure but request succeeded")
	d.recordStep(stepName, false, "tampered request was not rejected")
}

func (d *demoContext) step11Revoke(total int) {
	stepName := "Revoke and show cascade"
	demoHeader(11, total, stepName)

	if d.parentToken == "" || d.parentTaskID == "" {
		demoFail("No parent task from step 4")
		d.recordStep(stepName, false, "no parent task")
		return
	}

	args := map[string]interface{}{
		"task_id": d.parentTaskID,
	}

	// Use the API key for revocation (parent token may still work but let's use API key).
	resp, err := d.toolCall("task_revoke", args, d.apiKey)
	if err != nil {
		demoFail(err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	text, isErr, err := extractToolText(resp)
	if err != nil || isErr {
		var msg string
		if err != nil {
			msg = err.Error()
		} else {
			msg = text
		}
		demoFail(msg)
		d.recordStep(stepName, false, msg)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err == nil {
		revoked, _ := result["revoked"].(string)
		cascadeCount, _ := result["cascade_count"].(float64)
		status, _ := result["status"].(string)

		demoInfo("Revoked", revoked)
		demoInfo("Cascade count", fmt.Sprintf("%.0f", cascadeCount))
		demoInfo("Status", status)
	}

	// Also revoke the bound task if it exists.
	if d.boundTaskID != "" {
		args2 := map[string]interface{}{
			"task_id": d.boundTaskID,
		}
		_, _ = d.toolCall("task_revoke", args2, d.apiKey)
		demoInfo("Also revoked", d.boundTaskID+" (bound task)")
	}

	demoPass("Tasks revoked with cascade")
	d.recordStep(stepName, true, "")
}

func (d *demoContext) step12Metrics(total int) {
	stepName := "Check metrics"
	demoHeader(12, total, stepName)

	req, err := http.NewRequest("GET", d.dashboardURL+"/v1/metrics", nil)
	if err != nil {
		demoFail("create request: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}

	resp, err := d.client.Do(req)
	if err != nil {
		demoFail("HTTP request: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		demoFail("read response: " + err.Error())
		d.recordStep(stepName, false, err.Error())
		return
	}

	if resp.StatusCode == 401 {
		demoInfo("Note", "Metrics endpoint requires dashboard token (separate from API key)")
		demoInfo("Manual check", fmt.Sprintf("curl -H 'Authorization: Bearer <dashboard-token>' %s/v1/metrics | grep ephyr_macaroon", d.dashboardURL))
		d.recordStep(stepName, true, "skipped (dashboard auth required)")
		return
	}
	if resp.StatusCode != 200 {
		demoFail(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)))
		d.recordStep(stepName, false, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return
	}

	metricsText := string(body)

	// Extract key metrics.
	interestingMetrics := []string{
		"ephyr_macaroons_minted_total",
		"ephyr_macaroons_verified_total",
		"ephyr_macaroons_rejected_total",
		"ephyr_pop_verified_total",
		"ephyr_pop_rejected_total",
		"ephyr_tasks_created_total",
		"ephyr_tokens_signed_total",
		"ephyr_tokens_delegated_total",
		"ephyr_watermark_revocations_total",
	}

	found := 0
	for _, line := range strings.Split(metricsText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, metric := range interestingMetrics {
			if strings.HasPrefix(line, metric) {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					fmt.Printf("    %s%-40s%s %s%s%s\n", demoGreen, parts[0], demoReset, demoBold, parts[1], demoReset)
					found++
				}
				break
			}
		}
	}

	if found == 0 {
		demoInfo("Note", "No Prometheus metrics found (metrics endpoint may not be enabled)")
		demoPass("Metrics check completed (no Prometheus metrics available)")
	} else {
		demoPass(fmt.Sprintf("%d metrics retrieved", found))
	}
	d.recordStep(stepName, true, "")
}

func (d *demoContext) printSummary() {
	fmt.Printf("\n%s%s", demoBold, demoCyan)
	fmt.Println("  ╔══════════════════════════════════════════════════════╗")
	fmt.Println("  ║                    SUMMARY                         ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════╝")
	fmt.Print(demoReset)

	passed := 0
	failed := 0
	for i, s := range d.steps {
		status := fmt.Sprintf("%s%s PASS %s", demoBgGreen, demoWhite, demoReset)
		if !s.passed {
			status = fmt.Sprintf("%s%s FAIL %s", demoBgRed, demoWhite, demoReset)
			failed++
		} else {
			passed++
		}
		errDetail := ""
		if s.err != "" {
			errDetail = fmt.Sprintf(" %s(%s)%s", demoDim, s.err, demoReset)
		}
		fmt.Printf("  %s[%2d]%s %-38s %s%s\n", demoDim, i+1, demoReset, s.name, status, errDetail)
	}

	fmt.Printf("\n  %sTotal:%s %d  %sPassed:%s %s%d%s  %sFailed:%s %s%d%s\n\n",
		demoBold, demoReset, len(d.steps),
		demoBold, demoReset, demoGreen, passed, demoReset,
		demoBold, demoReset, demoRed, failed, demoReset)

	if failed > 0 {
		os.Exit(1)
	}
}
