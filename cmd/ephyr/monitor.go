package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// AuditEvent represents a single JSON line from the audit log.
// Fields mirror internal/audit.AuditEvent so we capture top-level
// target, role, serial, and duration in addition to the details map.
type AuditEvent struct {
	Timestamp string            `json:"timestamp"`
	Severity  string            `json:"severity"`
	EventType string            `json:"event_type"`
	Agent     string            `json:"agent"`
	Target    string            `json:"target"`
	Role      string            `json:"role"`
	Serial    string            `json:"serial"`
	Duration  string            `json:"duration"`
	Details   map[string]string `json:"details"`
}

// ANSI color constants.
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorBgRed   = "\033[41m"
)

// Column widths for aligned output.
const (
	colTime    = 8  // HH:MM:SS
	colIcon    = 5  // EXEC, SESS+, etc.
	colSev     = 4  // INFO, WARN, etc.
	colAgent   = 12 // agent name
	colTarget  = 14 // target/service/remote/task_id
	colRole    = 8  // role/method
	colDetail  = 40 // command/description
	colPadIcon = 1  // space after icon
	colPadSev  = 2  // spaces after severity
)

// separator is the dim horizontal line printed between event groups.
var separator = colorDim + strings.Repeat("\u2500", 93) + colorReset

// eventIcons maps event types to 5-character labels.
var eventIcons = map[string]string{
	"mcp_exec":              "EXEC ",
	"mcp_exec_error":        "XERR ",
	"mcp_session_create":    "SESS+",
	"mcp_session_close":     "SESS-",
	"http_proxy":            "HTTP ",
	"http_proxy_denied":     "XHTP ",
	"mcp_federation":        "MCP  ",
	"federation_arg_denied": "XMCP ",
	"task_create":           "TASK+",
	"task_delegate":         "DELE ",
	"task_revoke":           "REVK ",
	"task_bind":             "BIND ",
	"command_denied":        "DENY ",
	"auto_revoke":           "KILL ",
	"request_denied":        "DENY ",
	"request_body_denied":   "DENY ",
	"exec_denied":           "XSSH ",
	"session_denied":        "XSSH ",
	"cert_issued":           "CERT ",
	"cert_revoked":          "XCER ",
	"cert_denied":           "DENY ",
	"cert_pending":          "CERT?",
	"cert_approved":         "CERT+",
	"cert_expired":          "XCER ",
	"policy_reload":         "LOAD ",
	"host_toggle":           "TOGL ",
	"service_toggle":        "TOGL ",
	"remote_toggle":         "TOGL ",
	"remote_added":          "REM+ ",
	"remote_removed":        "REM- ",
	"terminal_open":         "TERM ",
	"terminal_close":        "TERM ",
	"task_revoke_dashboard": "REVK ",
	"startup":               "BOOT ",
	"shutdown":              "STOP ",
	"config_updated":        "CONF ",
	"config_deleted":        "CONF-",
	"session_start":         "SESN ",
	"session_reset":         "XSESN",
	"rate_limited":          "RATE ",
	"anomaly_detected":      "ANOM ",
}

// skipEvents are low-noise internal MCP events filtered out by default.
var skipEvents = map[string]bool{
	"mcp_request":   true,
	"mcp_tool_call": true,
	"mcp_started":   true,
}

// getEventColor returns the ANSI color string for an event type.
func getEventColor(evt string) string {
	switch {
	case evt == "mcp_exec" || evt == "mcp_exec_error" ||
		evt == "mcp_session_create" || evt == "mcp_session_close" ||
		evt == "cert_issued" || evt == "cert_revoked" ||
		evt == "cert_pending" || evt == "cert_approved" || evt == "cert_expired":
		return colorBlue
	case evt == "http_proxy" || evt == "http_proxy_denied":
		return colorGreen
	case evt == "mcp_federation" || evt == "federation_arg_denied" ||
		evt == "remote_toggle" || evt == "remote_added" || evt == "remote_removed":
		return colorMagenta
	case strings.HasPrefix(evt, "task_") && !strings.Contains(evt, "revoke"):
		return colorWhite + colorBold
	case strings.Contains(evt, "revoke"):
		return colorYellow
	case strings.Contains(evt, "denied") || evt == "auto_revoke":
		return colorRed
	case evt == "startup":
		return colorGreen
	default:
		return colorDim
	}
}

// getSeverityColor returns the ANSI color for a severity level.
func getSeverityColor(sev string) string {
	switch sev {
	case "CRIT", "ALER", "ERRO", "ERR":
		return colorRed
	case "WARN":
		return colorYellow
	case "INFO":
		return colorCyan
	default:
		return colorDim
	}
}

// truncate shortens a string with an ellipsis if it exceeds max length.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// padRight pads a string with spaces to the given width.
// If s is longer than width, it is truncated.
func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

// fmtDuration formats a millisecond string into a compact duration.
func fmtDuration(msStr string) string {
	if msStr == "" {
		return ""
	}
	// Try parsing as integer
	var ms int
	if _, err := fmt.Sscanf(msStr, "%d", &ms); err != nil {
		return msStr
	}
	if ms >= 10000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dms", ms)
}

// eventGroup categorizes an event type for separator insertion.
func eventGroup(evt string) string {
	switch {
	case evt == "mcp_exec" || evt == "mcp_exec_error" ||
		evt == "mcp_session_create" || evt == "mcp_session_close":
		return "ssh"
	case evt == "http_proxy" || evt == "http_proxy_denied":
		return "http"
	case evt == "mcp_federation" || evt == "federation_arg_denied":
		return "mcp"
	case strings.HasPrefix(evt, "task_"):
		return "task"
	case evt == "command_denied" || evt == "request_denied" ||
		evt == "request_body_denied" || evt == "auto_revoke":
		return "deny"
	case strings.HasPrefix(evt, "cert_"):
		return "cert"
	default:
		return "sys"
	}
}

// resolveField returns the value from the event's top-level field first,
// falling back to the details map. This handles the fact that the broker
// logs target/role both as top-level JSON fields and sometimes redundantly
// in the details map.
func resolveField(evt *AuditEvent, topLevel, detailKey string) string {
	if topLevel != "" {
		return topLevel
	}
	if evt.Details != nil {
		if v, ok := evt.Details[detailKey]; ok {
			return v
		}
	}
	return ""
}

// formatDetails builds a detail string based on event type, returning
// the target column, role/method column, detail/command column, and a
// right-aligned suffix.
type detailColumns struct {
	target  string // col: 14 chars
	role    string // col: 8 chars
	detail  string // col: 40 chars (may contain ANSI)
	right   string // right-aligned suffix
	indent  int    // indentation level (for task hierarchy)
}

func formatDetails(evt *AuditEvent) detailColumns {
	get := func(key string) string {
		if evt.Details == nil {
			return ""
		}
		if v, ok := evt.Details[key]; ok {
			return v
		}
		return ""
	}

	switch evt.EventType {
	case "mcp_exec":
		target := resolveField(evt, evt.Target, "target")
		role := resolveField(evt, evt.Role, "role")
		cmd := get("command")
		sessionID := get("session_id")
		exitCode := get("exit_code")

		// Check for latency breakdown fields.
		totalMs := get("total_ms")
		certMs := get("cert_ms")
		sshMs := get("ssh_ms")
		isSession := get("session")

		// Build the command display with optional [sess] tag.
		cmdDisplay := truncate(cmd, colDetail)
		if sessionID != "" {
			// Session-based exec: show [sess] tag and truncate command shorter.
			tag := colorDim + "[sess]" + colorReset
			cmdDisplay = truncate(cmd, colDetail-7) + " " + tag
		}

		var right []string

		// Use latency breakdown if available, otherwise fall back to duration_ms.
		if totalMs != "" && (certMs != "" || isSession == "true") {
			dur := fmtDuration(totalMs)
			if isSession == "true" {
				// Session-based: no cert phase.
				right = append(right, fmt.Sprintf("%s %s[sess ssh=%s]%s",
					dur, colorDim, fmtDuration(sshMs), colorReset))
			} else {
				// One-shot: show cert and ssh breakdown.
				right = append(right, fmt.Sprintf("%s %s[cert=%s ssh=%s]%s",
					dur, colorDim, fmtDuration(certMs), fmtDuration(sshMs), colorReset))
			}
		} else {
			dur := fmtDuration(get("duration_ms"))
			if dur != "" {
				right = append(right, dur)
			}
		}

		if exitCode != "" {
			right = append(right, "exit="+exitCode)
		}

		return detailColumns{
			target: target,
			role:   role,
			detail: cmdDisplay,
			right:  strings.Join(right, "  "),
		}

	case "mcp_exec_error":
		target := resolveField(evt, evt.Target, "target")
		role := resolveField(evt, evt.Role, "role")
		errMsg := get("error")
		cmd := get("command")
		info := truncate(cmd, colDetail)
		if info == "" {
			info = truncate(errMsg, colDetail)
		}
		return detailColumns{
			target: target,
			role:   role,
			detail: info,
			right:  colorRed + "ERROR" + colorReset,
		}

	case "mcp_session_create":
		target := resolveField(evt, evt.Target, "target")
		role := resolveField(evt, evt.Role, "role")
		sid := get("session_id")
		info := ""
		if sid != "" {
			info = "session=" + truncate(sid, 30)
		}
		return detailColumns{
			target: target,
			role:   role,
			detail: info,
			right:  colorGreen + colorBold + "NEW SESSION" + colorReset,
		}

	case "mcp_session_close":
		target := resolveField(evt, evt.Target, "target")
		role := resolveField(evt, evt.Role, "role")
		sid := get("session_id")
		info := ""
		if sid != "" {
			info = "session=" + truncate(sid, 30)
		}
		dur := evt.Duration
		right := colorYellow + "CLOSED" + colorReset
		if dur != "" {
			right = "dur=" + dur + "  " + right
		}
		return detailColumns{
			target: target,
			role:   role,
			detail: info,
			right:  right,
		}

	case "http_proxy":
		svc := get("service")
		method := get("method")
		if len(method) > colRole {
			method = method[:colRole]
		}
		path := get("path")
		if path == "" {
			// Extract path from full URL.
			url := get("url")
			if idx := strings.Index(url, "://"); idx >= 0 {
				rest := url[idx+3:]
				if si := strings.Index(rest, "/"); si >= 0 {
					path = rest[si:]
				} else {
					path = url
				}
			} else {
				path = url
			}
		}
		path = truncate(path, colDetail-5)
		dur := fmtDuration(get("duration_ms"))
		status := get("status_code")
		var right []string
		if dur != "" {
			right = append(right, dur)
		}
		if status != "" {
			right = append(right, "HTTP "+status)
		}
		errMsg := get("error")
		if errMsg != "" {
			right = append(right, colorRed+truncate(errMsg, 30)+colorReset)
		}
		return detailColumns{
			target: svc,
			role:   method,
			detail: path,
			right:  strings.Join(right, "  "),
		}

	case "http_proxy_denied":
		svc := get("service")
		method := get("method")
		if len(method) > colRole {
			method = method[:colRole]
		}
		url := truncate(get("url"), colDetail-5)
		return detailColumns{
			target: svc,
			role:   method,
			detail: url,
			right:  colorRed + "BLOCKED" + colorReset,
		}

	case "mcp_federation":
		remote := get("remote")
		tool := truncate(get("tool"), colDetail)
		dur := fmtDuration(get("duration_ms"))
		return detailColumns{
			target: remote,
			detail: tool,
			right:  dur,
		}

	case "federation_arg_denied":
		remote := get("remote")
		reason := truncate(get("reason"), colDetail)
		return detailColumns{
			target: remote,
			detail: reason,
			right:  colorRed + "BLOCKED" + colorReset,
		}

	case "task_create":
		tid := get("task_id")
		tidShort := truncate(tid, 10) + "..."
		if len(tid) <= 12 {
			tidShort = tid
		}
		desc := truncate(get("description"), colDetail-2)
		canDeleg := get("can_delegate")
		var right []string
		right = append(right, "depth=0")
		if canDeleg == "true" {
			right = append(right, "can_delegate")
		}
		if ttl := get("ttl"); ttl != "" {
			right = append(right, "TTL="+ttl)
		}
		if ttype := get("token_type"); ttype != "" {
			right = append(right, ttype)
		}
		return detailColumns{
			target: tidShort,
			detail: desc,
			right:  strings.Join(right, "  "),
			indent: 0,
		}

	case "task_delegate":
		tid := get("child_task_id")
		if tid == "" {
			tid = get("task_id")
		}
		tidShort := truncate(tid, 10) + "..."
		if len(tid) <= 12 {
			tidShort = tid
		}
		desc := truncate(get("description"), colDetail-2)
		depthStr := get("depth")
		depth := 0
		if depthStr != "" {
			if d, err := strconv.Atoi(depthStr); err == nil {
				depth = d
			}
		}
		var right []string
		if depthStr != "" {
			right = append(right, "depth="+depthStr)
		}
		if pid := get("parent_task_id"); pid != "" {
			right = append(right, "parent="+truncate(pid, 12))
		}
		if ttl := get("ttl"); ttl != "" {
			right = append(right, "TTL="+ttl)
		}
		return detailColumns{
			target: tidShort,
			detail: desc,
			right:  strings.Join(right, "  "),
			indent: depth,
		}

	case "task_revoke", "task_revoke_dashboard":
		tid := get("task_id")
		tidShort := truncate(tid, 10) + "..."
		if len(tid) <= 12 {
			tidShort = tid
		}
		desc := truncate(get("description"), colDetail-2)
		if desc == "" {
			desc = "revoked"
		}
		right := ""
		if cascade := get("cascade_count"); cascade != "" {
			right = "cascade=" + cascade
		}
		if evt.EventType == "task_revoke_dashboard" {
			if right != "" {
				right += "  "
			}
			right += colorDim + "(dashboard)" + colorReset
		}
		return detailColumns{
			target: tidShort,
			detail: desc,
			right:  right,
		}

	case "task_bind":
		tid := get("task_id")
		tidShort := truncate(tid, 10) + "..."
		if len(tid) <= 12 {
			tidShort = tid
		}
		return detailColumns{
			target: tidShort,
			detail: "holder key bound",
		}

	case "command_denied":
		target := resolveField(evt, evt.Target, "target")
		role := resolveField(evt, evt.Role, "role")
		cmd := colorRed + colorBold + truncate(get("command"), colDetail-8) + colorReset
		pattern := get("pattern")
		return detailColumns{
			target: target,
			role:   role,
			detail: cmd,
			right:  "pattern=" + colorRed + pattern + colorReset,
		}

	case "request_denied", "request_body_denied":
		svc := get("service")
		method := get("method")
		if len(method) > colRole {
			method = method[:colRole]
		}
		url := colorRed + colorBold + truncate(get("url"), colDetail-8) + colorReset
		pattern := get("pattern")
		return detailColumns{
			target: svc,
			role:   method,
			detail: url,
			right:  "pattern=" + colorRed + pattern + colorReset,
		}

	case "auto_revoke":
		target := resolveField(evt, evt.Target, "target")
		svc := get("service")
		col := svc
		if col == "" {
			col = target
		}
		role := resolveField(evt, evt.Role, "role")
		reason := colorRed + colorBold + truncate(get("reason"), colDetail) + colorReset
		return detailColumns{
			target: col,
			role:   role,
			detail: reason,
		}

	case "exec_denied", "session_denied":
		target := resolveField(evt, evt.Target, "target")
		reason := get("reason")
		return detailColumns{
			target: target,
			detail: reason,
		}

	case "cert_issued":
		target := resolveField(evt, evt.Target, "target")
		role := resolveField(evt, evt.Role, "role")
		serial := truncate(get("serial"), 16)
		ttl := get("ttl")
		right := ""
		if ttl != "" {
			right = "TTL=" + ttl
		}
		return detailColumns{
			target: target,
			role:   role,
			detail: "serial=" + serial,
			right:  right,
		}

	case "cert_denied":
		target := resolveField(evt, evt.Target, "target")
		role := resolveField(evt, evt.Role, "role")
		reason := truncate(get("reason"), colDetail)
		return detailColumns{
			target: target,
			role:   role,
			detail: reason,
		}

	case "cert_revoked":
		target := resolveField(evt, evt.Target, "target")
		role := resolveField(evt, evt.Role, "role")
		serial := truncate(get("serial"), 16)
		reason := truncate(get("reason"), 30)
		return detailColumns{
			target: target,
			role:   role,
			detail: "serial=" + serial,
			right:  reason,
		}

	case "startup":
		listen := get("listen")
		dash := get("dashboard")
		var parts []string
		if listen != "" {
			parts = append(parts, "listen="+listen)
		}
		if dash != "" {
			parts = append(parts, "dash="+dash)
		}
		return detailColumns{
			detail: strings.Join(parts, "  "),
		}

	case "shutdown":
		return detailColumns{
			detail: get("signal"),
		}

	case "policy_reload":
		path := truncate(get("path"), colDetail)
		return detailColumns{
			detail: path,
		}

	case "host_toggle", "service_toggle", "remote_toggle":
		target := get("target")
		if target == "" {
			target = get("service")
		}
		if target == "" {
			target = get("remote")
		}
		state := get("state")
		if state == "" {
			state = get("action")
		}
		stateStr := state
		if state == "enabled" {
			stateStr = colorGreen + "enabled" + colorReset
		} else if state == "disabled" {
			stateStr = colorYellow + "disabled" + colorReset
		}
		return detailColumns{
			target: target,
			detail: stateStr,
		}

	case "terminal_open":
		target := get("target")
		return detailColumns{
			target: target,
			detail: "terminal opened",
		}

	case "terminal_close":
		target := get("target")
		return detailColumns{
			target: target,
			detail: "terminal closed",
		}

	case "rate_limited":
		reason := get("reason")
		if reason == "" {
			reason = genericDetails(evt.Details)
		}
		return detailColumns{
			detail: truncate(reason, colDetail),
		}

	case "anomaly_detected":
		reason := get("reason")
		if reason == "" {
			reason = genericDetails(evt.Details)
		}
		return detailColumns{
			detail: truncate(reason, colDetail),
		}

	default:
		return detailColumns{
			detail: genericDetails(evt.Details),
		}
	}
}

// genericDetails formats up to 3 key=value pairs from the details map.
func genericDetails(d map[string]string) string {
	var parts []string
	i := 0
	for k, v := range d {
		if i >= 3 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, truncate(v, 25)))
		i++
	}
	return strings.Join(parts, "  ")
}

// cmdMonitor implements the "ephyr monitor" subcommand.
// It tails the audit log and renders events with color-coded, column-aligned output.
func cmdMonitor(args []string) {
	logPath := "/var/log/ephyr/audit.json"
	if len(args) > 0 {
		logPath = args[0]
	}

	// Print header.
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05")

	fmt.Print("\033[2J\033[H") // clear screen
	fmt.Printf("%s%s====================================================%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s  EPHYR LIVE MONITOR%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s  Host:    %s%s%s\n", colorDim, colorReset+colorBold, hostname, colorReset)
	fmt.Printf("%s  Log:     %s%s\n", colorDim, colorReset+logPath, "")
	fmt.Printf("%s  Started: %s%s\n", colorDim, colorReset+now, "")
	fmt.Printf("%s%s====================================================%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %sSSH%s = blue   %sHTTP%s = green   %sMCP%s = purple\n",
		colorBlue+colorBold, colorReset, colorGreen+colorBold, colorReset, colorMagenta+colorBold, colorReset)
	fmt.Printf("  %sTASK%s = white  %sDENY%s = red     %sREVOKE%s = yellow\n",
		colorWhite+colorBold, colorReset, colorRed+colorBold, colorReset, colorYellow+colorBold, colorReset)
	fmt.Printf("  %sCERT%s = dim    %s KILL %s = auto-revoke\n",
		colorDim, colorReset, colorBgRed+colorWhite+colorBold, colorReset)
	fmt.Printf("%s%s====================================================%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%-8s %-5s %-4s  %-12s %-14s %-8s %-40s %s%s\n",
		colorDim, "TIME", "ICON", "SEV", "AGENT", "TARGET", "ROLE", "COMMAND/DETAIL", "METRICS", colorReset)
	fmt.Printf("%s%s%s\n", colorDim, strings.Repeat("\u2500", 93), colorReset)
	fmt.Println()

	// Open file.
	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// Seek to end (tail -f behavior).
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		fmt.Fprintf(os.Stderr, "Error seeking: %v\n", err)
		os.Exit(1)
	}

	// Counters.
	var totalEvents, denied, revoked, errors int
	startTime := time.Now()
	prevGroup := ""

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// No new data -- sleep briefly and retry.
			time.Sleep(100 * time.Millisecond)
			reader.Reset(f)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var evt AuditEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			continue
		}

		// Skip low-noise internal events.
		if skipEvents[evt.EventType] {
			continue
		}

		totalEvents++

		// Parse timestamp.
		timeStr := "??:??:??"
		if t, err := time.Parse(time.RFC3339Nano, evt.Timestamp); err == nil {
			timeStr = t.Format("15:04:05")
		}

		// Get icon.
		icon := eventIcons[evt.EventType]
		if icon == "" {
			icon = evt.EventType
			if len(icon) > 5 {
				icon = icon[:5]
			}
			icon = strings.ToUpper(icon)
		}

		// Severity (4-char max, uppercase).
		sev := evt.Severity
		if len(sev) > 4 {
			sev = sev[:4]
		}
		sev = strings.ToUpper(sev)

		// Event color and severity color.
		evtColor := getEventColor(evt.EventType)
		sevColor := getSeverityColor(sev)

		// Update counters.
		switch evt.EventType {
		case "command_denied", "request_denied", "request_body_denied",
			"cert_denied", "http_proxy_denied", "federation_arg_denied",
			"exec_denied", "session_denied":
			denied++
		}
		switch evt.EventType {
		case "auto_revoke", "task_revoke", "task_revoke_dashboard", "cert_revoked":
			revoked++
		}
		if sev == "ERRO" || sev == "ERR" || sev == "ALER" || sev == "CRIT" ||
			evt.EventType == "mcp_exec_error" {
			errors++
		}

		// Dim separator line between different event groups.
		grp := eventGroup(evt.EventType)
		if prevGroup != "" && grp != prevGroup {
			fmt.Println(separator)
		}
		prevGroup = grp

		// Format detail columns.
		cols := formatDetails(&evt)

		// Agent name (pad to 12).
		agent := evt.Agent
		if agent == "" {
			agent = "-"
		}
		agent = truncate(agent, colAgent)

		// Target column (pad to 14).
		target := truncate(cols.target, colTarget)

		// Role column (pad to 8).
		role := truncate(cols.role, colRole)

		// Detail column: apply task indentation if present.
		detail := cols.detail
		if cols.indent > 0 {
			indentStr := strings.Repeat("  ", cols.indent)
			// Reduce detail width to make room for indentation.
			maxDetail := colDetail - (cols.indent * 2)
			if maxDetail < 10 {
				maxDetail = 10
			}
			// Re-truncate detail to fit indented width (it was already truncated
			// at colDetail by formatDetails, but may need to be shorter).
			if len(detail) > maxDetail {
				detail = truncate(detail, maxDetail)
			}
			detail = indentStr + detail
		}

		// Format the label -- auto_revoke gets inverse styling.
		var labelStr string
		if evt.EventType == "auto_revoke" {
			labelStr = fmt.Sprintf("%s%s%s %s %s",
				colorBgRed, colorWhite, colorBold, icon, colorReset)
		} else {
			labelStr = fmt.Sprintf("%s%s%-5s%s",
				evtColor, colorBold, icon, colorReset)
		}

		// Assemble and print the line with fixed-width columns.
		fmt.Printf("%s%s%s %s %s%-4s%s  %s%-12s%s %s%-14s%s %s%-8s%s %s",
			colorDim, timeStr, colorReset,
			labelStr,
			sevColor, sev, colorReset,
			colorBold, agent, colorReset,
			evtColor, padRight(target, colTarget), colorReset,
			colorDim, padRight(role, colRole), colorReset,
			detail)

		if cols.right != "" {
			fmt.Printf("  %s%s%s", colorDim, cols.right, colorReset)
		}
		fmt.Println()

		// Update status line on stderr (bottom of terminal).
		elapsed := time.Since(startTime).Truncate(time.Second)
		deniedColor := colorDim
		if denied > 0 {
			deniedColor = colorRed
		}
		revokedColor := colorDim
		if revoked > 0 {
			revokedColor = colorYellow
		}
		errorsColor := colorDim
		if errors > 0 {
			errorsColor = colorRed
		}
		fmt.Fprintf(os.Stderr, "\033[s\033[9999;1H\033[2K%sEvents: %s%d%s | Denied: %s%d%s | Revoked: %s%d%s | Errors: %s%d%s | Uptime: %s%s\033[u",
			colorDim, colorReset, totalEvents, colorDim,
			deniedColor, denied, colorReset+colorDim,
			revokedColor, revoked, colorReset+colorDim,
			errorsColor, errors, colorReset+colorDim,
			colorReset, elapsed)
	}
}
