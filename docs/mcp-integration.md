# Clauth MCP Integration Guide

How to connect AI agents to Clauth infrastructure operations via the Model Context
Protocol (MCP).

---

## What is MCP?

The Model Context Protocol (MCP) is a structured tool interface for large language
models. It uses JSON-RPC 2.0 over HTTP to expose server-side "tools" that any
compatible AI agent can discover and call. Clauth implements MCP Streamable HTTP
transport (protocol version `2025-03-26`), exposing homelab infrastructure
operations -- SSH command execution, session management, and authenticated HTTP
proxying -- as tools that agents can invoke programmatically.

The key benefit: agents do not need SSH keys, credentials, or direct network access
to target hosts. Clauth handles ephemeral certificate generation, credential
injection, and audit logging transparently.

---

## Architecture

```
  AI Agent (Claude Code, etc.)
       |
       | JSON-RPC 2.0 over HTTP POST /mcp
       | Authorization: Bearer {api-key}
       v
  +------------------+
  | Clauth MCP       |  TCP :8554
  | (mcp.go)         |
  +------------------+
       |
       |  Internal broker calls
       v
  +------------------+         +------------------+
  | ExecSessionPool  | ------> | Signer IPC       |
  | (mcp_exec.go)    |  sign   | (signer.sock)    |
  +------------------+         +------------------+
       |                              |
       | SSH cert auth                | Ed25519 CA
       v                              v
  +------------------+         +------------------+
  | Target Hosts     |         | CA Key           |
  | (MandrakeRack,   |         | /etc/clauth/     |
  |  DockerHost,     |         | ca_key           |
  |  HugoBlog)       |         +------------------+
  +------------------+

  +------------------+
  | ProxyEngine      |  HTTP proxy with
  | (proxy.go)       |  credential injection
  +------------------+
       |
       v
  +------------------+
  | Internal Services|
  | (Grafana, Gitea, |
  |  etc.)           |
  +------------------+
```

---

## Setup

### 1. Generate an API Key

On the Clauth host, generate a bcrypt hash for your agent API key:

```bash
# Choose a strong random key
API_KEY=$(openssl rand -base64 32)
echo "Save this key: $API_KEY"

# Generate the bcrypt hash
htpasswd -nbBC 10 "" "$API_KEY" | cut -d: -f2
```

### 2. Configure policy.yaml

Add or update the agent entry in `/etc/clauth/policy.yaml` with the bcrypt hash:

```yaml
agents:
  claude:
    uid: 1000
    max_concurrent_certs: 5
    description: "Claude Code agent on command VM"
    api_key_hash: "$2a$10$hBvBDSpWdT7..."
```

### 3. Set the MCP Listen Address

The MCP listener address is set via the broker configuration. Ensure
`CLAUTH_MCP_LISTEN` is set (default `:8554`) in the broker systemd unit
or startup command:

```bash
# In systemd override or environment
CLAUTH_MCP_LISTEN=:8554
```

### 4. Reload Policy

Send SIGHUP to the broker to pick up policy changes without restarting:

```bash
systemctl reload clauth-broker
# or
kill -HUP $(pidof clauth-broker)
```

### 5. Configure Your MCP Client

**Claude Code** (`~/.claude/settings.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "clauth": {
      "type": "url",
      "url": "http://192.168.100.75:8554/mcp",
      "headers": {
        "Authorization": "Bearer your-api-key-here"
      }
    }
  }
}
```

**Generic MCP client** -- any client that supports MCP Streamable HTTP:

```
Endpoint:  POST http://<broker-host>:8554/mcp
Auth:      Authorization: Bearer <api-key>
Content:   application/json (JSON-RPC 2.0)
```

---

## MCP Protocol Flow

1. **Initialize** -- Client sends `initialize` with protocol version and capabilities.
   Server responds with its capabilities (tools supported).

2. **Notification** -- Client sends `notifications/initialized` to confirm.

3. **List tools** -- Client sends `tools/list` to discover available tools.

4. **Call tools** -- Client sends `tools/call` with tool name and arguments.
   Server executes and returns results.

All messages use JSON-RPC 2.0 format:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "exec",
    "arguments": {
      "target": "docker-host",
      "role": "read",
      "command": "uptime"
    }
  }
}
```

---

## Available Tools

### list_targets

List available SSH targets the agent may access, filtered by the intersection
of the agent roles and each target allowed_roles.

**Parameters:** None

**Response:**

```json
[
  {
    "name": "docker-host",
    "host": "192.168.100.100",
    "port": 22,
    "vlan": 100,
    "roles": ["read", "operator"],
    "description": "DockerHost -- production Docker services (VLAN 100 Mandrake)",
    "enabled": true
  },
  {
    "name": "mandrake-rack",
    "host": "192.168.30.55",
    "port": 22,
    "vlan": 30,
    "roles": ["read", "operator"],
    "description": "MandrakeRack -- edge services + Brocade console (VLAN 30 Icebreaker)",
    "enabled": true
  }
]
```

Targets with `"enabled": false` have been toggled off via the dashboard or admin
API and will reject all exec/session requests.

---

### exec

Execute a shell command on a target host via SSH certificate authentication.
This is the primary tool for infrastructure operations.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | Yes | -- | Target host name from list_targets |
| `role` | string | Yes | -- | Role to use (`read`, `operator`, etc.) |
| `command` | string | Yes | -- | Shell command to execute on the target |
| `timeout` | integer | No | 30 | Timeout in seconds (min 1, max 300) |
| `session_id` | string | No | -- | Reuse an existing persistent SSH session |

**Response:**

```json
{
  "stdout": " 15:30:00 up 4 days,  2:15,  0 users,  load average: 0.52, 0.48, 0.41\n",
  "stderr": "",
  "exit_code": 0,
  "target": "docker-host",
  "role": "read",
  "duration_ms": 14
}
```

| Field | Type | Description |
|-------|------|-------------|
| `stdout` | string | Standard output from the command |
| `stderr` | string | Standard error from the command |
| `exit_code` | int | Process exit code (0 = success, -1 = timeout/error) |
| `target` | string | Target name |
| `role` | string | Role used |
| `duration_ms` | int64 | Execution time in milliseconds |

Non-zero exit codes are **not** MCP errors -- they are valid command results.
The `exit_code` field should be checked by the agent.

On timeout, stderr includes `[timeout after Ns]` and exit_code is -1.

**Validation performed:**

- Target must exist in policy
- Role must be in both the agent allowed roles and the target allowed_roles
- Host must be enabled (not toggled off)

---

### session_create

Create a persistent SSH session for executing multiple commands without
reconnecting. Returns a session_id that can be passed to subsequent `exec` calls.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `target` | string | Yes | Target host name |
| `role` | string | Yes | Role to use |

**Response:**

```json
{
  "session_id": "a1b2c3d4e5f67890a1b2c3d4e5f67890",
  "target": "docker-host",
  "role": "operator",
  "message": "Persistent SSH session created for claude on docker-host (role: operator)"
}
```

The session_id is a cryptographically random 32-character hex string.

---

### session_close

Close a persistent SSH session and release the underlying SSH connection.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `session_id` | string | Yes | Session ID to close |

**Response:**

```json
{
  "session_id": "a1b2c3d4e5f67890a1b2c3d4e5f67890",
  "message": "Session closed successfully"
}
```

---

### list_sessions

List active persistent SSH sessions belonging to the calling agent.

**Parameters:** None

**Response:**

```json
[
  {
    "id": "a1b2c3d4e5f67890a1b2c3d4e5f67890",
    "target": "docker-host",
    "role": "operator",
    "created_at": "2026-03-10T15:00:00Z",
    "last_used": "2026-03-10T15:02:30Z"
  }
]
```

---

### list_certs

List active SSH certificates belonging to the calling agent.

**Parameters:** None

**Response:**

```json
[
  {
    "serial": "a1b2c3d4",
    "target": "docker-host",
    "role": "operator",
    "principal": "agent-op",
    "expires_at": "2026-03-10T15:05:00Z"
  }
]
```

---

### http_request

Make an HTTP request through the broker authenticated proxy. When the request URL
matches a configured service prefix, credentials are automatically injected. The
agent never sees the actual credentials -- they are stored server-side and redacted
in all API responses.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | string | Yes | -- | Full URL to request (http or https) |
| `method` | string | No | `GET` | HTTP method: GET, POST, PUT, PATCH, DELETE, HEAD |
| `headers` | object | No | -- | Additional request headers (key-value string pairs) |
| `body` | string | No | -- | Request body (for POST/PUT/PATCH) |
| `timeout` | integer | No | 30 | Timeout in seconds (min 1, max 120) |

**Response:**

```json
{
  "status_code": 200,
  "headers": {
    "Content-Type": "application/json",
    "X-Request-Id": "abc123"
  },
  "body": "{\"dashboards\": [...]}",
  "service": "grafana",
  "url": "http://192.168.100.100:3030/api/dashboards/home",
  "method": "GET",
  "duration_ms": 45,
  "bytes_read": 1250,
  "truncated": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status_code` | int | HTTP response status code |
| `headers` | object | Response headers (single value per key) |
| `body` | string | Response body (truncated to service max_response_kb, default 1MB) |
| `service` | string | Matched service name, or `"direct"` if no service matched |
| `duration_ms` | int64 | Request duration in milliseconds |
| `bytes_read` | int | Actual bytes read from response |
| `truncated` | bool | True if response body was truncated due to size limit |

**Network policy:** The proxy enforces network restrictions. By default, only
RFC 1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are
allowed. External (public) access is denied by default. Specific deny CIDRs
can block sensitive internal networks.

**Credential injection** -- When a URL matches a service url_prefix, the proxy
automatically injects credentials based on the service auth_type:

| Auth Type | Behavior |
|-----------|----------|
| `bearer` | Sets `Authorization: Bearer {credential}` |
| `basic` | Sets HTTP Basic Auth with username + credential |
| `header` | Sets custom header with optional prefix |
| `query` | Appends credential as a query parameter |
| `none` | No credentials injected |

Agents cannot override injected auth headers -- their custom headers are applied
after credential injection, but `Authorization` and custom auth headers are protected.

---

### list_services

List configured proxy services showing which have automatic credential injection.

**Parameters:** None

**Response:**

```json
[
  {
    "name": "grafana",
    "url_prefix": "http://192.168.100.100:3030",
    "description": "Grafana monitoring dashboards",
    "auth_type": "bearer",
    "allowed_methods": ["GET"]
  },
  {
    "name": "gitea",
    "url_prefix": "http://192.168.100.54:3000",
    "description": "Gitea API",
    "auth_type": "bearer",
    "allowed_methods": ["GET", "POST"]
  }
]
```

Credentials are never included in list_services output.

---

## Performance: Sessions vs One-Shot

Clauth supports two execution modes with dramatically different performance
characteristics:

### One-Shot Execution (no session_id)

Each `exec` call without a session_id performs the full certificate lifecycle:

1. Generate ephemeral Ed25519 keypair in memory (never written to disk)
2. Sign the public key via signer IPC (Unix socket to signer process)
3. Establish a new SSH connection to the target using the certificate
4. Execute the command
5. Tear down the SSH connection

**Typical latency: ~850ms** (dominated by SSH handshake and certificate signing)

### Session Execution (with session_id)

When using a persistent session created via `session_create`, the `exec` call:

1. Look up the existing SSH connection by session_id
2. Open a new SSH channel on the multiplexed connection
3. Execute the command
4. Return result (connection stays open)

**Typical latency: ~14ms** (just the command execution over an existing connection)

### When to Use Each

| Scenario | Recommendation |
|----------|---------------|
| Single ad-hoc command | One-shot (simpler, self-contained) |
| Multi-command workflow (3+ commands on same host) | Session (60x faster per command) |
| Commands across different hosts | One-shot per host, or one session per host |
| Long-running investigation | Session (keeps connection warm) |
| Simple health check | One-shot (no cleanup needed) |

### Session Lifecycle

- **Idle timeout:** Sessions are automatically closed after 5 minutes of inactivity.
  A background cleanup goroutine checks every 60 seconds.
- **Max concurrent:** Each agent can hold up to 5 concurrent persistent sessions
  (configurable via `maxPerAgent` in the ExecSessionPool).
- **Certificate TTL:** Session certificates are issued with a 5-minute TTL (or the
  global default, whichever is shorter). If the cert expires while the session is
  still open, the SSH connection remains functional until it is closed or encounters
  an error.
- **Cleanup:** Always call `session_close` when done. Abandoned sessions are cleaned
  up by the idle timeout, but explicit closure is good practice.

---

## Example Workflows

### 1. Check disk space across all servers

```
Agent: tools/call list_targets
  -> Gets: docker-host, mandrake-rack, hugoblog

Agent: tools/call session_create {target: "docker-host", role: "read"}
  -> session_id: "aaa..."

Agent: tools/call session_create {target: "mandrake-rack", role: "read"}
  -> session_id: "bbb..."

Agent: tools/call session_create {target: "hugoblog", role: "read"}
  -> session_id: "ccc..."

Agent: tools/call exec {session_id: "aaa...", target: "docker-host", role: "read", command: "df -h /"}
Agent: tools/call exec {session_id: "bbb...", target: "mandrake-rack", role: "read", command: "df -h /"}
Agent: tools/call exec {session_id: "ccc...", target: "hugoblog", role: "read", command: "df -h /"}

Agent: tools/call session_close {session_id: "aaa..."}
Agent: tools/call session_close {session_id: "bbb..."}
Agent: tools/call session_close {session_id: "ccc..."}
```

### 2. Deploy a configuration change

```
Agent: tools/call exec {target: "docker-host", role: "operator",
  command: "cat /opt/docker/myapp/docker-compose.yml"}
  -> reads current config

Agent: tools/call exec {target: "docker-host", role: "operator",
  command: "cd /opt/docker/myapp && docker compose pull && docker compose up -d"}
  -> applies update

Agent: tools/call exec {target: "docker-host", role: "operator",
  command: "docker ps --filter name=myapp --format 'table {{.Names}}\t{{.Status}}'"}
  -> verifies containers are healthy
```

### 3. Query a Grafana dashboard

```
Agent: tools/call list_services
  -> sees "grafana" with url_prefix http://192.168.100.100:3030

Agent: tools/call http_request {
  url: "http://192.168.100.100:3030/api/search?type=dash-db",
  method: "GET"
}
  -> gets list of dashboards (auth injected automatically)

Agent: tools/call http_request {
  url: "http://192.168.100.100:3030/api/dashboards/uid/abc123",
  method: "GET"
}
  -> gets dashboard details
```

### 4. Investigate a container issue

```
Agent: tools/call session_create {target: "docker-host", role: "operator"}
  -> session_id: "sess..."

Agent: tools/call exec {session_id: "sess...", command: "docker ps -a --filter status=exited"}
Agent: tools/call exec {session_id: "sess...", command: "docker logs --tail 50 myapp-web"}
Agent: tools/call exec {session_id: "sess...", command: "docker inspect myapp-web --format '{{.State.Health}}'"}
Agent: tools/call exec {session_id: "sess...", command: "docker compose -f /opt/docker/myapp/docker-compose.yml restart web"}
Agent: tools/call exec {session_id: "sess...", command: "docker ps --filter name=myapp-web"}

Agent: tools/call session_close {session_id: "sess..."}
```

---

## Security Considerations

### API Key Management

- Each agent should have a **unique API key** -- never share keys between agents.
- API keys are stored as bcrypt hashes in `policy.yaml`. The plaintext key exists
  only in the agent client configuration.
- Rotate keys by updating the `api_key_hash` in policy and sending SIGHUP to reload.

### Network Access

- The MCP listener only binds to the configured address (default `:8554`).
- The nftables firewall on the Clauth LXC restricts access to SSH and port 8553 from
  `192.168.0.0/16`. MCP access should be similarly restricted.
- The HTTP proxy enforces network policy: only RFC 1918 private ranges by default,
  with configurable allow/deny CIDRs. External access is denied by default.

### Credential Isolation

- HTTP proxy credentials are stored server-side in `/var/lib/clauth/services.json`
  (0600 permissions). Agents never see raw credentials -- they are redacted as `"***"`
  in all API responses and list_services output.
- SSH certificates are ephemeral (5-minute TTL for MCP exec operations) and the
  private keys are generated in memory (never written to disk).

### Audit Trail

All MCP operations are logged in two places:

1. **Audit log** (`/var/log/clauth/audit.json`) -- Structured JSON, one event per
   line, rotated via logrotate (30-day retention). Records cert operations, session
   lifecycle, exec commands (truncated to 200 chars), and proxy requests.

2. **Activity store** -- In-memory ring buffer (10,000 entries) powering the
   dashboard activity views. Records exec operations, HTTP proxy requests, and
   session open/close events with timing data.

Monitor the dashboard Activity view for unexpected patterns: unusual targets,
high error rates, or commands outside normal operational scope.

### Role Enforcement

- The `read` role maps to principal `agent-read` (restricted shell, rbash)
- The `operator` role maps to principal `agent-op` (bash, limited sudo)
- The `admin` role maps to principal `agent-admin` (bash, broader sudo)
- Role access is enforced at multiple levels: MCP agent config, policy evaluation,
  target allowed_roles, and the SSH principal on the target host.

---

## Troubleshooting

### "authentication failed: invalid API key"

The API key does not match any registered agent bcrypt hash.

- Verify the key matches exactly (no trailing whitespace or newlines).
- Check that the agent entry in `policy.yaml` has `api_key_hash` set.
- Ensure policy was reloaded after changes (`kill -HUP` or `systemctl reload`).

### "unknown target: X"

The target name does not exist in `policy.yaml`.

- Run `list_targets` to see available targets.
- Target names are case-sensitive and must match the YAML key exactly.

### "role X is not allowed on target Y"

The requested role is not in the target `allowed_roles` list.

- Check the target definition in `policy.yaml`.
- Use `list_targets` to see which roles are available per target.

### "role X is not in your allowed roles"

The agent does not have permission to use this role.

- Agent roles are computed as the union of all target allowed_roles in policy.
- Check the agent configuration.

### "target X is currently disabled"

The target has been toggled off via the dashboard or admin API.

- Check the dashboard Hosts view.
- Re-enable via POST /v1/dashboard/hosts/{name}/toggle.

### "agent X has reached max concurrent sessions (5)"

The per-agent session limit has been hit.

- Close unused sessions with `session_close`.
- Sessions idle for 5+ minutes are cleaned up automatically.
- Wait 60 seconds for the cleanup goroutine to run.

### "duplicate active cert" or signing errors

The previous certificate for this target/role may still be tracked.

- Old certs are auto-revoked when a new one is issued for the same agent/target/role.
- If the error persists, wait for the cert to expire (5-minute TTL).

### "rate limit exceeded"

Too many requests in the sliding window (default: 10 per 60 seconds).

- Wait for the window to expire. The `retry_after_seconds` field tells you how long.
- This limit applies to Unix socket API requests, not MCP directly, but MCP exec
  operations may trigger internal cert requests that are rate-limited.

### Exec timeout

The command took longer than the specified timeout.

- Increase the `timeout` parameter (max 300 seconds for exec, 120 for http_request).
- Check if the target host is under heavy load.
- For very long operations, consider breaking them into smaller steps.

### "proxy: policy denied"

The HTTP proxy request was blocked by network policy.

- Verify the URL resolves to an allowed CIDR (RFC 1918 by default).
- External (public internet) requests are denied by default.
- Check deny_cidrs for blocked internal ranges.

### Connection refused on port 8554

The MCP listener may not be started.

- Verify CLAUTH_MCP_LISTEN is configured in the broker environment.
- Check `journalctl -u clauth-broker` for startup errors.
- Confirm the port is not blocked by nftables.
