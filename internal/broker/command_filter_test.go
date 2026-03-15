package broker

import (
	"strings"
	"testing"
)

func TestCheckCommand_Disabled(t *testing.T) {
	// When filtering is disabled, every command should be allowed immediately.
	result := CheckCommand("rm -rf /", []string{"rm"}, []string{"ls"}, false)
	if !result.Allowed {
		t.Errorf("expected Allowed=true when filter is disabled, got false")
	}
	if result.Mode != "" {
		t.Errorf("expected empty Mode when filter is disabled, got %q", result.Mode)
	}
}

func TestCheckCommand_DenyMatch(t *testing.T) {
	deny := []string{"rm ", "dd if=", "mkfs"}
	result := CheckCommand("rm -rf /tmp/data", deny, nil, true)
	if result.Allowed {
		t.Errorf("expected command to be denied")
	}
	if result.Mode != "deny" {
		t.Errorf("expected Mode=deny, got %q", result.Mode)
	}
	if result.Pattern != "rm " {
		t.Errorf("expected Pattern='rm ', got %q", result.Pattern)
	}
	if result.Reason == "" {
		t.Error("expected non-empty Reason for denied command")
	}
}

func TestCheckCommand_DenyNoMatch(t *testing.T) {
	deny := []string{"rm ", "dd if=", "mkfs"}
	result := CheckCommand("ls -la /tmp", deny, nil, true)
	if !result.Allowed {
		t.Errorf("expected command to be allowed, got denied: %s", result.Reason)
	}
}

func TestCheckCommand_AllowMatch(t *testing.T) {
	allow := []string{"systemctl status*", "journalctl*", "uptime"}
	result := CheckCommand("systemctl status sshd", nil, allow, true)
	if !result.Allowed {
		t.Errorf("expected command to be allowed")
	}
	if result.Mode != "allow" {
		t.Errorf("expected Mode=allow, got %q", result.Mode)
	}
}

func TestCheckCommand_AllowNoMatch(t *testing.T) {
	allow := []string{"systemctl status*", "journalctl*", "uptime"}
	result := CheckCommand("cat /etc/passwd", nil, allow, true)
	if result.Allowed {
		t.Errorf("expected command to be denied (not in allow list)")
	}
	if result.Mode != "allow" {
		t.Errorf("expected Mode=allow, got %q", result.Mode)
	}
	if !strings.Contains(result.Reason, "allow") {
		t.Errorf("expected reason to mention allow list, got: %s", result.Reason)
	}
}

func TestCheckCommand_AllowTakesPrecedence(t *testing.T) {
	// When both deny and allow lists are set, allow-list takes precedence.
	deny := []string{"rm "}
	allow := []string{"ls*", "uptime"}

	// "rm -rf /" is in deny list but allow list is active, so it should be
	// denied because it's NOT in the allow list (not because of deny match).
	result := CheckCommand("rm -rf /", deny, allow, true)
	if result.Allowed {
		t.Errorf("expected command to be denied")
	}
	if result.Mode != "allow" {
		t.Errorf("expected Mode=allow (allow takes precedence), got %q", result.Mode)
	}

	// "ls -la" should be allowed because it matches allow list.
	result = CheckCommand("ls -la", deny, allow, true)
	if !result.Allowed {
		t.Errorf("expected command to be allowed via allow list")
	}
}

func TestCheckCommand_CaseInsensitive(t *testing.T) {
	deny := []string{"rm -rf"}
	result := CheckCommand("RM -RF /tmp", deny, nil, true)
	if result.Allowed {
		t.Errorf("expected case-insensitive match to deny 'RM -RF'")
	}

	allow := []string{"UPTIME"}
	result = CheckCommand("uptime", nil, allow, true)
	if !result.Allowed {
		t.Errorf("expected case-insensitive match to allow 'uptime'")
	}
}

func TestCheckCommand_WildcardPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		command string
		want    bool
	}{
		{"prefix wildcard", "systemctl status*", "systemctl status sshd", true},
		{"prefix wildcard no match", "systemctl status*", "systemctl restart sshd", false},
		{"suffix wildcard", "*.conf", "cat /etc/nginx/nginx.conf", true},
		{"suffix wildcard no match", "*.conf", "cat /etc/hosts", false},
		{"contains wildcard", "*passwd*", "cat /etc/passwd.bak", true},
		{"contains wildcard no match", "*passwd*", "cat /etc/hosts", false},
		{"bare star matches all", "*", "anything goes", true},
		{"double star matches all", "**", "anything goes", true},
		{"plain substring", "drop table", "sql drop table users;", true},
		{"plain substring no match", "drop table", "select * from users", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPattern(strings.ToLower(tt.command), strings.ToLower(tt.pattern))
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.command, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestCheckCommand_DenyReasonCategories(t *testing.T) {
	tests := []struct {
		pattern  string
		contains string
	}{
		{"rm -rf", "destructive"},
		{"dd if=", "destructive"},
		{"chmod", "privilege"},
		{"passwd", "privilege"},
		{":()", "dangerous"},
		{"custom-pattern", "prohibited pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			result := CheckCommand("some "+tt.pattern+" command", []string{tt.pattern}, nil, true)
			if result.Allowed {
				t.Fatalf("expected denial for pattern %q", tt.pattern)
			}
			lower := strings.ToLower(result.Reason)
			if !strings.Contains(lower, tt.contains) {
				t.Errorf("reason %q should contain %q", result.Reason, tt.contains)
			}
		})
	}
}

func TestCheckCommand_EmptyCommand(t *testing.T) {
	// Empty command with filtering enabled.
	result := CheckCommand("", []string{"rm"}, nil, true)
	if !result.Allowed {
		t.Errorf("expected empty command to be allowed (doesn't match 'rm')")
	}

	// Empty command with allow list should be denied (doesn't match anything).
	result = CheckCommand("", nil, []string{"ls*"}, true)
	if result.Allowed {
		t.Errorf("expected empty command to be denied against allow list")
	}
}

func TestCheckCommand_EmptyPattern(t *testing.T) {
	// Empty pattern in deny list should not match anything.
	result := CheckCommand("ls -la", []string{""}, nil, true)
	if !result.Allowed {
		t.Errorf("expected empty pattern to not match")
	}
}

func TestCheckCommand_FilterEnabledNoLists(t *testing.T) {
	// Filter enabled but no deny or allow patterns = everything allowed.
	result := CheckCommand("rm -rf /", nil, nil, true)
	if !result.Allowed {
		t.Errorf("expected command allowed when filter enabled but no patterns configured")
	}
}

// --- Benchmarks ---

func BenchmarkCheckCommand_NoFilter(b *testing.B) {
	deny := []string{"rm ", "dd if=", "mkfs", "chmod", "chown"}
	allow := []string{"ls*", "cat*", "uptime"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckCommand("ls -la /tmp", deny, allow, false)
	}
}

func BenchmarkCheckCommand_DenyList10(b *testing.B) {
	deny := []string{
		"rm ", "rm -", "rmdir", "dd if=", "mkfs",
		"drop database", "drop table", "truncate ", "> /dev/", "chmod",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckCommand("ls -la /tmp/some/path/to/file", deny, nil, true)
	}
}

func BenchmarkCheckCommand_AllowList10(b *testing.B) {
	allow := []string{
		"systemctl status*", "journalctl*", "df *", "free *", "uptime",
		"cat /proc/loadavg", "cat /proc/meminfo", "ps aux*", "top -bn1*", "netstat*",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckCommand("systemctl status sshd", nil, allow, true)
	}
}

func BenchmarkCheckCommand_DenyList10_Match(b *testing.B) {
	deny := []string{
		"rm ", "rm -", "rmdir", "dd if=", "mkfs",
		"drop database", "drop table", "truncate ", "> /dev/", "chmod",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckCommand("rm -rf /tmp/data", deny, nil, true)
	}
}

func BenchmarkCheckCommand_AllowList10_NoMatch(b *testing.B) {
	allow := []string{
		"systemctl status*", "journalctl*", "df *", "free *", "uptime",
		"cat /proc/loadavg", "cat /proc/meminfo", "ps aux*", "top -bn1*", "netstat*",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckCommand("rm -rf /important/data", nil, allow, true)
	}
}

// --- HTTP proxy filtering tests ---

func TestCheckCommand_HTTPProxy(t *testing.T) {
	tests := []struct {
		name    string
		urlPath string
		deny    []string
		allow   []string
		want    bool
	}{
		{
			name:    "deny admin path",
			urlPath: "/api/v1/admin/users",
			deny:    []string{"/api/v1/admin/*"},
			want:    false,
		},
		{
			name:    "deny delete endpoint",
			urlPath: "/api/v1/repos/myrepo/delete",
			deny:    []string{"*/delete"},
			want:    false,
		},
		{
			name:    "allow normal path with deny list",
			urlPath: "/api/v1/repos/myrepo",
			deny:    []string{"/api/v1/admin/*", "*/delete"},
			want:    true,
		},
		{
			name:    "allow-list permits matching path",
			urlPath: "/api/v1/repos/list",
			allow:   []string{"/api/v1/repos/*"},
			want:    true,
		},
		{
			name:    "allow-list blocks non-matching path",
			urlPath: "/api/v1/admin/settings",
			allow:   []string{"/api/v1/repos/*"},
			want:    false,
		},
		{
			name:    "filter disabled passes everything",
			urlPath: "/api/v1/admin/destroy",
			deny:    []string{"admin", "destroy"},
			want:    true, // tested via filterEnabled=false below
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled := true
			if tt.name == "filter disabled passes everything" {
				enabled = false
			}
			result := CheckCommand(tt.urlPath, tt.deny, tt.allow, enabled)
			if result.Allowed != tt.want {
				t.Errorf("CheckCommand(%q, deny=%v, allow=%v) = Allowed:%v, want %v (reason: %s)",
					tt.urlPath, tt.deny, tt.allow, result.Allowed, tt.want, result.Reason)
			}
		})
	}
}

func TestCheckCommand_HTTPBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		deny []string
		want bool
	}{
		{
			name: "deny drop database in body",
			body: `{"query": "DROP DATABASE production"}`,
			deny: []string{"drop database"},
			want: false,
		},
		{
			name: "deny drop table in body",
			body: `{"sql": "drop table users; --"}`,
			deny: []string{"drop database", "drop table"},
			want: false,
		},
		{
			name: "allow safe body content",
			body: `{"query": "SELECT * FROM users WHERE id = 1"}`,
			deny: []string{"drop database", "drop table", "truncate"},
			want: true,
		},
		{
			name: "deny pattern in JSON value",
			body: `{"command": "rm -rf /data"}`,
			deny: []string{"rm -rf"},
			want: false,
		},
		{
			name: "empty body always allowed",
			body: "",
			deny: []string{"drop database"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.body == "" {
				// Empty body should not be checked (filterEnabled=true but nothing to match)
				result := CheckCommand(tt.body, tt.deny, nil, true)
				if !result.Allowed {
					t.Errorf("empty body should be allowed, got denied")
				}
				return
			}
			result := CheckCommand(tt.body, tt.deny, nil, true)
			if result.Allowed != tt.want {
				t.Errorf("CheckCommand(body=%q, deny=%v) = Allowed:%v, want %v (reason: %s)",
					truncateTestStr(tt.body, 60), tt.deny, result.Allowed, tt.want, result.Reason)
			}
		})
	}
}

func TestCheckCommand_MCPArgs(t *testing.T) {
	tests := []struct {
		name string
		args string // serialized JSON arguments
		deny []string
		want bool
	}{
		{
			name: "deny rm in arguments",
			args: `{"command":"rm -rf /tmp/data","target":"server1"}`,
			deny: []string{"rm ", "format", "destroy"},
			want: false,
		},
		{
			name: "deny format in arguments",
			args: `{"action":"format","disk":"/dev/sda"}`,
			deny: []string{"rm ", "format", "destroy"},
			want: false,
		},
		{
			name: "deny destroy in arguments",
			args: `{"operation":"destroy","resource":"database"}`,
			deny: []string{"rm ", "format", "destroy"},
			want: false,
		},
		{
			name: "allow safe arguments",
			args: `{"action":"status","service":"nginx"}`,
			deny: []string{"rm ", "format", "destroy"},
			want: true,
		},
		{
			name: "case insensitive match",
			args: `{"cmd":"FORMAT disk"}`,
			deny: []string{"format"},
			want: false,
		},
		{
			name: "no deny patterns allows all",
			args: `{"anything":"goes"}`,
			deny: []string{},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled := len(tt.deny) > 0
			result := CheckCommand(tt.args, tt.deny, nil, enabled)
			if result.Allowed != tt.want {
				t.Errorf("CheckCommand(args=%q, deny=%v) = Allowed:%v, want %v (reason: %s)",
					truncateTestStr(tt.args, 60), tt.deny, result.Allowed, tt.want, result.Reason)
			}
		})
	}
}

// truncateTestStr shortens a string for test error messages.
func truncateTestStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
