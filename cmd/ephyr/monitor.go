package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// AuditEvent represents a single JSON line from the audit log.
type AuditEvent struct {
	Timestamp string            `json:"timestamp"`
	Severity  string            `json:"severity"`
	EventType string            `json:"event_type"`
	Agent     string            `json:"agent"`
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
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
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

// eventGroup categorizes an event type for blank-line separation.
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

// formatDetails builds a detail string based on event type, returning
// both a detail string and a right-aligned suffix.
func formatDetails(evt string, d map[string]string) (string, string) {
	get := func(key string) string {
		if v, ok := d[key]; ok {
			return v
		}
		return ""
	}

	switch evt {
	case "mcp_exec":
		target := truncate(get("target"), 14)
		role := truncate(get("role"), 8)
		cmd := truncate(get("command"), 40)
		dur := fmtDuration(get("duration_ms"))
		exitCode := get("exit_code")
		var right []string
		if dur != "" {
			right = append(right, dur)
		}
		if exitCode != "" {
			right = append(right, "exit="+exitCode)
		}
		return fmt.Sprintf("%-14s %-8s %s", target, role, cmd),
			strings.Join(right, "  ")

	case "mcp_exec_error":
		target := truncate(get("target"), 14)
		role := truncate(get("role"), 8)
		errMsg := get("error")
		cmd := get("command")
		info := truncate(cmd, 40)
		if info == "" {
			info = truncate(errMsg, 40)
		}
		return fmt.Sprintf("%-14s %-8s %s", target, role, info),
			colorRed + "ERROR" + colorReset

	case "mcp_session_create", "mcp_session_close":
		target := truncate(get("target"), 14)
		role := truncate(get("role"), 8)
		sid := get("session_id")
		info := ""
		if sid != "" {
			info = "session=" + truncate(sid, 30)
		}
		return fmt.Sprintf("%-14s %-8s %s", target, role, info), ""

	case "http_proxy":
		svc := truncate(get("service"), 14)
		method := get("method")
		if len(method) > 8 {
			method = method[:8]
		}
		path := get("path")
		if path == "" {
			// Extract path from full URL
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
		path = truncate(path, 35)
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
		return fmt.Sprintf("%-14s %-8s %s", svc, method, path),
			strings.Join(right, "  ")

	case "http_proxy_denied":
		svc := truncate(get("service"), 14)
		method := get("method")
		if len(method) > 8 {
			method = method[:8]
		}
		url := truncate(get("url"), 35)
		return fmt.Sprintf("%-14s %-8s %s", svc, method, url),
			colorRed + "BLOCKED" + colorReset

	case "mcp_federation":
		remote := truncate(get("remote"), 14)
		tool := truncate(get("tool"), 30)
		dur := fmtDuration(get("duration_ms"))
		return fmt.Sprintf("%-14s %s", remote, tool), dur

	case "federation_arg_denied":
		remote := truncate(get("remote"), 14)
		reason := truncate(get("reason"), 40)
		return fmt.Sprintf("%-14s %s", remote, reason),
			colorRed + "BLOCKED" + colorReset

	case "task_create":
		tid := truncate(get("task_id"), 12)
		desc := truncate(get("description"), 30)
		var right []string
		if ttl := get("ttl"); ttl != "" {
			right = append(right, "TTL="+ttl)
		}
		if ttype := get("token_type"); ttype != "" {
			right = append(right, ttype)
		}
		if targets := get("targets"); targets != "" {
			right = append(right, truncate(targets, 20))
		}
		return fmt.Sprintf("task=%-12s  %s", tid, desc),
			strings.Join(right, "  ")

	case "task_delegate":
		tid := truncate(get("child_task_id"), 12)
		if tid == "" {
			tid = truncate(get("task_id"), 12)
		}
		desc := truncate(get("description"), 30)
		var right []string
		if depth := get("depth"); depth != "" {
			right = append(right, "depth="+depth)
		}
		if pid := get("parent_task_id"); pid != "" {
			right = append(right, "parent="+truncate(pid, 12))
		}
		if ttl := get("ttl"); ttl != "" {
			right = append(right, "TTL="+ttl)
		}
		return fmt.Sprintf("task=%-12s  %s", tid, desc),
			strings.Join(right, "  ")

	case "task_revoke", "task_revoke_dashboard":
		tid := truncate(get("task_id"), 12)
		desc := truncate(get("description"), 30)
		if desc == "" {
			desc = "revoked"
		}
		right := ""
		if cascade := get("cascade_count"); cascade != "" {
			right = "cascade=" + cascade
		}
		if evt == "task_revoke_dashboard" {
			if right != "" {
				right += "  "
			}
			right += colorDim + "(dashboard)" + colorReset
		}
		return fmt.Sprintf("task=%-12s  %s", tid, desc), right

	case "task_bind":
		tid := truncate(get("task_id"), 12)
		return fmt.Sprintf("task=%-12s  holder key bound", tid), ""

	case "command_denied":
		target := truncate(get("target"), 14)
		role := truncate(get("role"), 8)
		cmd := colorRed + colorBold + truncate(get("command"), 32) + colorReset
		pattern := get("pattern")
		return fmt.Sprintf("%-14s %-8s %s", target, role, cmd),
			"pattern=" + colorRed + pattern + colorReset

	case "request_denied", "request_body_denied":
		svc := truncate(get("service"), 14)
		method := get("method")
		if len(method) > 8 {
			method = method[:8]
		}
		url := colorRed + colorBold + truncate(get("url"), 32) + colorReset
		pattern := get("pattern")
		return fmt.Sprintf("%-14s %-8s %s", svc, method, url),
			"pattern=" + colorRed + pattern + colorReset

	case "auto_revoke":
		target := get("target")
		svc := get("service")
		col := truncate(svc, 14)
		if col == "" {
			col = truncate(target, 14)
		}
		role := truncate(get("role"), 8)
		reason := colorRed + colorBold + truncate(get("reason"), 40) + colorReset
		return fmt.Sprintf("%-14s %-8s %s", col, role, reason), ""

	case "exec_denied", "session_denied":
		target := truncate(get("target"), 14)
		reason := get("reason")
		return fmt.Sprintf("%-14s  %s", target, reason), ""

	case "cert_issued":
		target := truncate(get("target"), 14)
		role := truncate(get("role"), 8)
		serial := truncate(get("serial"), 16)
		ttl := get("ttl")
		right := ""
		if ttl != "" {
			right = "TTL=" + ttl
		}
		return fmt.Sprintf("%-14s %-8s serial=%s", target, role, serial), right

	case "cert_denied":
		target := truncate(get("target"), 14)
		role := truncate(get("role"), 8)
		reason := truncate(get("reason"), 40)
		return fmt.Sprintf("%-14s %-8s %s", target, role, reason), ""

	case "cert_revoked":
		target := truncate(get("target"), 14)
		role := truncate(get("role"), 8)
		serial := truncate(get("serial"), 16)
		reason := truncate(get("reason"), 30)
		return fmt.Sprintf("%-14s %-8s serial=%s", target, role, serial), reason

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
		return strings.Join(parts, "  "), ""

	case "shutdown":
		return get("signal"), ""

	case "policy_reload":
		path := truncate(get("path"), 40)
		return path, ""

	case "host_toggle", "service_toggle", "remote_toggle":
		target := get("target")
		if target == "" {
			target = get("service")
		}
		if target == "" {
			target = get("remote")
		}
		target = truncate(target, 14)
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
		return fmt.Sprintf("%-14s  %s", target, stateStr), ""

	case "terminal_open":
		target := truncate(get("target"), 14)
		return fmt.Sprintf("%-14s  terminal opened", target), ""

	case "terminal_close":
		target := truncate(get("target"), 14)
		return fmt.Sprintf("%-14s  terminal closed", target), ""

	case "rate_limited":
		reason := get("reason")
		if reason == "" {
			reason = genericDetails(d)
		}
		return truncate(reason, 40), ""

	case "anomaly_detected":
		reason := get("reason")
		if reason == "" {
			reason = genericDetails(d)
		}
		return truncate(reason, 40), ""

	default:
		return genericDetails(d), ""
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
// It tails the audit log and renders events with color-coded output.
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

		// Blank line between different event groups.
		grp := eventGroup(evt.EventType)
		if prevGroup != "" && grp != prevGroup {
			fmt.Println()
		}
		prevGroup = grp

		// Format detail and right columns.
		detail, right := formatDetails(evt.EventType, evt.Details)

		// Agent name (pad to 12).
		agent := evt.Agent
		if agent == "" {
			agent = "-"
		}
		agent = truncate(agent, 12)

		// Format the label -- auto_revoke gets inverse styling.
		var labelStr string
		if evt.EventType == "auto_revoke" {
			labelStr = fmt.Sprintf("%s%s%s %s %s",
				colorBgRed, colorWhite, colorBold, icon, colorReset)
		} else {
			labelStr = fmt.Sprintf("%s%s%-5s%s",
				evtColor, colorBold, icon, colorReset)
		}

		// Assemble and print the line.
		fmt.Printf("%s%s%s %s %s%-4s%s  %s%-12s%s %s",
			colorDim, timeStr, colorReset,
			labelStr,
			sevColor, sev, colorReset,
			colorBold, agent, colorReset,
			detail)

		if right != "" {
			fmt.Printf("  %s%s%s", colorDim, right, colorReset)
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
