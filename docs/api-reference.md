# Clauth API Reference

Complete reference for all Clauth broker API endpoints across the Unix socket,
Dashboard TCP, MCP, and WebSocket interfaces.

---

## Authentication

Clauth exposes three distinct listeners, each with its own authentication scheme:

| Interface | Transport | Default Address | Auth Method |
|-----------|-----------|-----------------|-------------|
| Unix Socket API | Unix domain socket | `/run/clauth/broker.sock` | Peer credential (UID) + session token |
| Dashboard API | TCP | `:8553` | Dashboard token via `Authorization: Bearer {token}` |
| MCP API | TCP | `:8554` | API key via `Authorization: Bearer {api-key}` (bcrypt-verified) |

**Unix Socket API** -- Agents connect over the Unix socket. The broker extracts the
caller UID from SO_PEERCRED automatically. Most endpoints additionally require a
session token passed via `Authorization: Bearer {token}` or `X-Session-Token: {token}`.

**Dashboard API** -- The dashboard token is configured via the CLAUTH_DASHBOARD_TOKEN
environment variable in the broker systemd unit. All `/v1/dashboard/*` and `/v1/events`
endpoints require this token. Static file requests (`/` and `/static/*`) are exempt.
Token comparison uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

**MCP API** -- Each agent has a bcrypt-hashed API key in `policy.yaml` (field
`api_key_hash`). The broker iterates registered agents and uses
`bcrypt.CompareHashAndPassword` for constant-time verification.

---

## Rate Limiting

All Unix socket API requests are subject to a per-UID sliding window rate limiter,
configured in `policy.yaml` under `global.rate_limit`:

- **requests_per_window**: Maximum requests allowed (default: 10)
- **window_seconds**: Window duration in seconds (default: 60)

When rate limited, the response includes a `Retry-After` header:

```json
{"error": "rate limit exceeded", "retry_after_seconds": 42}
```

HTTP status: `429 Too Many Requests`

---

## Error Format

All API errors return a JSON object with an `error` field:

```json
{"error": "description of the problem"}
```

---

## Unix Socket API

Default socket path: `/run/clauth/broker.sock` (permissions 0660, group `clauth-agents`)

All curl examples use `--unix-socket` to connect:

```bash
curl --unix-socket /run/clauth/broker.sock http://localhost/v1/...
```

---

### GET /v1/health

Health check endpoint. **No authentication required.**

**Response** `200 OK`:

```json
{
  "status": "ok",
  "uptime": "2h 15m 30s",
  "active_certs": 2,
  "pending_requests": 0,
  "signer_ok": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"ok"` if the broker is running |
| `uptime` | string | Human-readable uptime (Go duration, rounded to seconds) |
| `active_certs` | int | Number of currently valid certificates in state |
| `pending_requests` | int | Number of requests awaiting admin approval |
| `signer_ok` | bool | Whether the signer IPC connection responds to ping |

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock http://localhost/v1/health
```

---

### POST /v1/session

Create a new agent session. Requires valid UID (peer credential). The agent name
is auto-resolved from the UID via policy lookup if `agent_name` is not provided
in the request body.

**Request body** (optional -- empty body is valid):

```json
{
  "agent_name": "claude"
}
```

**Response** `200 OK`:

```json
{
  "token": "a1b2c3d4e5f67890abcdef1234567890",
  "agent_name": "claude",
  "uid": 1000
}
```

| Field | Type | Description |
|-------|------|-------------|
| `token` | string | Session token for subsequent authenticated requests |
| `agent_name` | string | Resolved agent name from policy |
| `uid` | uint32 | Unix UID of the caller |

**Errors:**

| Status | Reason |
|--------|--------|
| 401 | Unable to identify caller (no peer credential) |
| 403 | UID not registered as any agent in policy |
| 500 | Internal session creation failure |

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock \
  -X POST http://localhost/v1/session
```

---

### GET /v1/session

Whoami -- retrieve current session information. Requires a valid session token
that matches the calling UID.

**Headers:** `Authorization: Bearer {token}` or `X-Session-Token: {token}`

**Response** `200 OK`:

```json
{
  "token": "a1b2c3d4...7890abcd",
  "agent_name": "claude",
  "uid": 1000,
  "created_at": "2026-03-10T12:00:00Z",
  "last_seen": "2026-03-10T12:05:30Z"
}
```

The `token` field is masked: first 8 characters + `...` + last 8 characters.

**Errors:**

| Status | Reason |
|--------|--------|
| 401 | Missing session token, invalid session, or UID mismatch |
| 404 | Session not found |

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost/v1/session
```

---

### POST /v1/request

Request an SSH certificate. This is the core certificate issuance pipeline.
Requires a valid session token. The broker evaluates the request against the
policy engine (role check, concurrent cert limits, target TTL), checks the
host access controller, and returns one of three outcomes:

- **granted** -- Certificate issued immediately (auto-approve targets)
- **pending** -- Queued for admin approval
- **denied** -- Policy or host access check failed

**Headers:** `Authorization: Bearer {token}` or `X-Session-Token: {token}`

**Request body:**

```json
{
  "target": "webserver",
  "role": "operator",
  "duration": "5m",
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Target name from policy (e.g., `webserver`) |
| `role` | string | Yes | Role to request (e.g., `read`, `operator`, `admin`) |
| `duration` | string | No | Go duration (e.g., `5m`, `10m`). Clamped to target max_ttl. Uses policy default if omitted |
| `public_key` | string | Yes | SSH public key in authorized_keys format |

**Response** `200 OK` (granted):

```json
{
  "status": "granted",
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "serial": "a1b2c3d4",
  "expires_at": "2026-03-10T12:10:00Z",
  "principal": "agent-op",
  "host": "TARGET_HOST",
  "port": 22
}
```

**Response** `202 Accepted` (pending):

```json
{
  "status": "pending",
  "reason": "requires admin approval",
  "request_id": "req-abc123"
}
```

**Response** `403 Forbidden` (denied):

```json
{
  "status": "denied",
  "reason": "host access is currently disabled"
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| 400 | Invalid JSON, missing `target`/`role`, or bad duration format |
| 401 | Missing or invalid session token |
| 403 | Policy denied, host disabled, or session UID mismatch |
| 500 | Signer IPC failure |

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"webserver","role":"read","duration":"5m","public_key":"ssh-ed25519 AAAA..."}' \
  http://localhost/v1/request
```

---

### GET /v1/certs

List active certificates. Non-admin agents see only their own certs;
admin UIDs (configured in BrokerConfig) see all active certs.
On Dashboard TCP connections (no Unix peer credential), all certs are returned.

**Response** `200 OK`:

```json
[
  {
    "serial": "a1b2c3d4",
    "agent_name": "claude",
    "agent_uid": 1000,
    "target": "webserver",
    "role": "operator",
    "principal": "agent-op",
    "issued_at": "2026-03-10T12:00:00Z",
    "expires_at": "2026-03-10T12:10:00Z",
    "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA..."
  }
]
```

Returns an empty array `[]` (never null) when no certs are active.

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock http://localhost/v1/certs
```

---

### DELETE /v1/certs/{serial}

Revoke an active certificate by hex serial number. Agents can only revoke their
own certificates; admin UIDs can revoke any certificate. The cert is also removed
from the policy engine tracking (frees a concurrent cert slot).

**Response** `200 OK`:

```json
{
  "status": "revoked",
  "serial": "a1b2c3d4"
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| 400 | Serial is required |
| 403 | Non-admin attempting to revoke another agent certificate |
| 404 | Certificate not found |

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock \
  -X DELETE http://localhost/v1/certs/a1b2c3d4
```

---

### GET /v1/targets

List available targets and their allowed roles. On Unix socket connections,
requires a valid session token. On Dashboard TCP connections, authentication
is handled by the dashboard token middleware.

**Headers:** `Authorization: Bearer {token}` or `X-Session-Token: {token}`

**Response** `200 OK`:

```json
[
  {
    "name": "webserver",
    "host": "TARGET_HOST",
    "port": 22,
    "allowed_roles": ["read", "operator"],
    "auto_approve": true,
    "description": "Production Docker host"
  }
]
```

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost/v1/targets
```

---

### POST /v1/approve/{request_id}

Admin-only: approve a pending certificate request. Issues the certificate via
the signer and moves the request from pending to active state.

**Response** `200 OK`: Same structure as a granted POST /v1/request response,
with the additional `request_id` field.

**Errors:**

| Status | Reason |
|--------|--------|
| 400 | request_id is required |
| 403 | Admin access required |
| 404 | Pending request not found |
| 500 | Signing failed |

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock \
  -X POST http://localhost/v1/approve/req-abc123
```

---

### POST /v1/deny/{request_id}

Admin-only: deny a pending certificate request. Removes the request from
the pending queue without issuing a certificate.

**Response** `200 OK`:

```json
{
  "status": "denied",
  "reason": "request denied by admin",
  "request_id": "req-abc123"
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| 400 | request_id is required |
| 403 | Admin access required |
| 404 | Pending request not found |

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock \
  -X POST http://localhost/v1/deny/req-abc123
```

---

### POST /v1/admin/hosts/{name}/toggle

Admin-only (UID-based auth): toggle host access on or off. When a host is
disabled, all certificate requests for that target are denied with "host access
is currently disabled". The toggle state is tracked in-memory by the
HostController (defaults to enabled on startup).

**Response** `200 OK`:

```json
{
  "host": "webserver",
  "access_enabled": false
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| 400 | Host name is required |
| 403 | Admin access required |
| 404 | Host not found in policy |

**Example:**

```bash
curl --unix-socket /run/clauth/broker.sock \
  -X POST http://localhost/v1/admin/hosts/webserver/toggle
```

---

## Dashboard API

Default listen address: TCP `:8553`

All endpoints require the dashboard token via `Authorization: Bearer {token}`
header, except `/` and `/static/*` (static file serving). CORS is permissive
(all origins allowed) for dashboard flexibility.

---

### GET /v1/dashboard/summary

Overview statistics for the dashboard home view.

**Response** `200 OK`:

```json
{
  "hostname": "Clauth",
  "ip": "BROKER_HOST",
  "uptime": "4h 32m",
  "broker_status": "healthy",
  "ca_key_status": "loaded",
  "active_certs": 2,
  "pending_requests": 0,
  "total_granted": 145,
  "total_denied": 3,
  "agents_active": 1,
  "hosts_online": 3,
  "hosts_enabled": 3,
  "signer_ok": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `agents_active` | int | Unique agent names with at least one active cert |
| `hosts_online` | int | Total targets in policy |
| `hosts_enabled` | int | Targets with access enabled (not toggled off) |
| `ca_key_status` | string | `"loaded"` if signer responds to ping, `"unavailable"` otherwise |

**Example:**

```bash
curl -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  http://BROKER_HOST:8553/v1/dashboard/summary
```

---

### GET /v1/dashboard/hosts

List all policy targets with access status, VLAN, and active session counts.

**Response** `200 OK`:

```json
[
  {
    "name": "webserver",
    "host": "TARGET_HOST",
    "vlan": 100,
    "status": "online",
    "role": "Production Docker host",
    "access_enabled": true,
    "active_sessions": 1
  }
]
```

---

### GET /v1/dashboard/sessions

List active certificate sessions with real-time TTL countdown.

**Response** `200 OK`:

```json
[
  {
    "serial": "a1b2c3d4",
    "agent": "claude",
    "target": "webserver",
    "role": "operator",
    "principal": "agent-op",
    "cert_ttl": 280,
    "max_ttl": 600,
    "issued_at": "2026-03-10T12:00:00Z",
    "expires_at": "2026-03-10T12:10:00Z",
    "status": "active"
  }
]
```

`cert_ttl` and `max_ttl` are in seconds. `status` is `"active"` or `"expired"`.

---

### GET /v1/dashboard/audit

Recent entries from the on-disk audit log (`/var/log/clauth/audit.json`).

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Number of most recent entries to return |
| `type` | string | -- | Filter by event_type substring (e.g., `grant`, `denied`, `toggle`) |

**Response** `200 OK`: Array of raw JSON audit objects (one per line from the log file).

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://BROKER_HOST:8553/v1/dashboard/audit?limit=20&type=denied"
```

---

### POST /v1/dashboard/hosts/{name}/toggle

Toggle host access via the dashboard. Functionally identical to the Unix socket
admin toggle, but additionally **revokes all active certificates** for the host
when toggled off. Audit trail includes the HTTP `source_ip`.

**Response** `200 OK`:

```json
{"host": "webserver", "access_enabled": false}
```

---

### POST /v1/dashboard/sessions/{serial}/revoke

Revoke an active certificate from the dashboard by serial number.

**Response** `200 OK`:

```json
{"status": "revoked", "serial": "a1b2c3d4"}
```

---

### GET /v1/dashboard/activity

Query the agent activity ring buffer (10,000 entry capacity) with filtering.

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `agent` | string | -- | Filter by agent name |
| `type` | string | -- | Activity type: `exec`, `http_proxy`, `session_open`, `session_close`, `cert_issued`, `cert_denied`, `mcp_call` |
| `target` | string | -- | Filter by target name |
| `service` | string | -- | Filter by proxy service name |
| `limit` | int | 100 | Max entries (capped at 1000) |
| `since` | string | -- | RFC3339 start time |
| `until` | string | -- | RFC3339 end time |
| `only_errors` | string | -- | `1` or `true` to show only failures |

**Response** `200 OK`: Array of ActivityEntry in reverse chronological order.

---

### GET /v1/dashboard/activity/summary

Aggregated activity statistics: totals, per-agent stats, top 10 targets, top 10 services.

**Response** `200 OK`:

```json
{
  "total_actions": 320,
  "total_exec": 250,
  "total_proxy": 65,
  "total_errors": 5,
  "active_agents": 1,
  "agent_stats": {"claude": {"total_actions": 320, "last_active": "...", "last_target": "webserver"}},
  "recent_entries": [],
  "top_targets": [{"name": "webserver", "count": 180}],
  "top_services": [{"name": "grafana", "count": 40}]
}
```

---

### GET /v1/dashboard/activity/agent/{name}

Per-agent activity detail with stats and the 200 most recent entries.

**Response** `200 OK`:

```json
{"agent": "claude", "stats": {...}, "entries": [...]}
```

---

### GET /v1/dashboard/config/hosts

List all host configurations with passwords redacted (`"***"`).

---

### GET /v1/dashboard/config/hosts/{name}

Get a single host configuration (password redacted).

---

### PUT /v1/dashboard/config/hosts/{name}

Create or update a host configuration. Existing configs receive a merge update --
only non-zero fields are applied. New configs are created with all provided fields.

**Request body:**

```json
{
  "host": "TARGET_HOST",
  "port": 22,
  "vlan": 100,
  "ssh_user": "root",
  "ssh_password": "secret",
  "allowed_roles": ["read", "operator"],
  "max_ttl": "10m",
  "default_ttl": "5m",
  "auto_approve": true,
  "description": "Production Docker host",
  "os": "Debian 12"
}
```

Validation: host must be valid IP or hostname, port 1-65535, VLAN 1-4094,
TTL values must be valid Go durations.

Persisted atomically to `/var/lib/clauth/hosts.json` (0600).

---

### DELETE /v1/dashboard/config/hosts/{name}

Delete a host configuration.

**Response** `200 OK`:

```json
{"status": "deleted", "host": "webserver"}
```

---

### GET /v1/dashboard/config/roles

List all roles from the active policy.

**Response** `200 OK`:

```json
[
  {"name": "read", "principal": "agent-read", "description": "Read-only access"},
  {"name": "operator", "principal": "agent-op", "description": "Operational commands"},
  {"name": "admin", "principal": "agent-admin", "description": "Administrative access"}
]
```

---

### GET /v1/dashboard/terminal

WebSocket endpoint for the web terminal (xterm.js). Proxies an interactive SSH
session between the browser and a target host. Authenticated via dashboard token.

---

### GET /v1/dashboard/services

List configured HTTP proxy services (credentials redacted as `"***"`).

---

### GET /v1/dashboard/services/{name}

Get a single proxy service config (credential redacted).

---

### PUT /v1/dashboard/services/{name}

Create or update an HTTP proxy service configuration.

**Request body:**

```json
{
  "url_prefix": "http://GITEA_HOST:3000",
  "auth_type": "bearer",
  "credential": "gitea-api-token",
  "description": "Gitea API",
  "allowed_methods": ["GET", "POST"],
  "allowed_paths": ["/api/*"],
  "max_response_kb": 1024,
  "timeout": 30,
  "headers": {"Accept": "application/json"}
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url_prefix` | string | Yes | URL prefix for matching requests (longest prefix wins) |
| `auth_type` | string | No | `bearer`, `basic`, `header`, `query`, or `none` (default: `none`) |
| `token_header` | string | No | Custom header name for `header` auth type |
| `token_prefix` | string | No | Prefix before credential value (e.g., `"token "`) |
| `username` | string | No | Username for `basic` auth type |
| `credential` | string | No | Token or password (stored encrypted, redacted in responses) |
| `allowed_paths` | array | No | Glob patterns for path restrictions (empty = all paths) |
| `allowed_methods` | array | No | Allowed HTTP methods (empty = all methods) |
| `max_response_kb` | int | No | Max response body in KB (default: 1024 = 1MB) |
| `timeout` | int | No | Timeout in seconds (default: 30, max: 120) |
| `description` | string | No | Human-readable description |
| `headers` | object | No | Extra headers injected into every request |

Persisted atomically to `/var/lib/clauth/services.json`.

---

### DELETE /v1/dashboard/services/{name}

Delete a proxy service configuration.

---

## WebSocket Event Stream

### GET /v1/events

Real-time event stream via WebSocket on the Dashboard TCP listener (:8553).

**Authentication:** `?token={dashboard-token}` query parameter.

**Connection example:**

```javascript
const ws = new WebSocket("ws://BROKER_HOST:8553/v1/events?token=YOUR_TOKEN");
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data.type, data.data);
};
```

**Event envelope:**

```json
{
  "type": "cert_issued",
  "timestamp": "2026-03-10T12:00:00Z",
  "data": { ... }
}
```

**Event types:**

| Type | Trigger | Key data fields |
|------|---------|-----------------|
| `cert_issued` | Certificate granted | serial, agent, target, role, principal, expires |
| `cert_denied` | Request denied | agent, target, role, reason |
| `cert_revoked` | Certificate revoked | serial, agent, target, role |
| `session_start` | Agent session created | agent, uid |
| `host_toggle` | Host access toggled | host, state (enabled/disabled) |
| `policy_reload` | Policy reloaded via SIGHUP | path |
| `mcp_session_create` | Persistent SSH session opened | session_id, agent, target, role |
| `mcp_session_close` | Persistent SSH session closed | session_id, agent, target |
| `mcp_exec` | Command executed via MCP | agent, target, role, exit_code |
| `http_proxy` | HTTP proxy request completed | agent, url, method, service, status_code, duration_ms |
| `config_updated` | Host config changed | host |
| `config_deleted` | Host config removed | host |
| `startup` | Broker started | listen, policy, signer, dashboard |
| `shutdown` | Broker stopping | signal |

**Connection behavior:**

- Ping interval: 30 seconds
- Pong timeout: 60 seconds (disconnected if no pong received)
- Send buffer: 64 events per client
- Backpressure: events dropped silently for slow clients whose buffer is full
- Max inbound message size: 512 bytes (client messages are read and discarded)

---

## MCP API

Default listen address: TCP `:8554`

All requests require an API key via `Authorization: Bearer {api-key}` header.
The key is validated against bcrypt hashes in the policy file's agent
`api_key_hash` fields.

### POST /mcp

Single endpoint handling all MCP JSON-RPC 2.0 methods.

**Supported methods:**

| Method | Description |
|--------|-------------|
| `initialize` | Protocol handshake -- returns server capabilities (tools, resources) |
| `notifications/initialized` | Client acknowledgment (no response) |
| `tools/list` | List all 14 available tools with JSON Schema parameters |
| `tools/call` | Execute a tool by name with arguments |
| `resources/list` | List all 7 available resources with URIs and descriptions |
| `resources/read` | Read a specific resource by URI, returns Markdown content |

**Initialize example:**

```bash
curl -s -X POST http://BROKER:8554/mcp \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "clientInfo": {"name": "test", "version": "1.0"}
    }
  }'
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-03-26",
    "serverInfo": {"name": "clauth", "version": "1.0.0"},
    "capabilities": {
      "tools": {"listChanged": false},
      "resources": {"listChanged": false}
    }
  }
}
```

**Resources list example:**

```bash
curl -s -X POST http://BROKER:8554/mcp \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 2, "method": "resources/list"}'
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "resources": [
      {"uri": "clauth://overview", "name": "System Overview", "description": "High-level summary of Clauth broker capabilities, available targets, services, and your agent permissions", "mimeType": "text/markdown"},
      {"uri": "clauth://targets", "name": "SSH Targets", "description": "Available SSH targets with hosts, ports, allowed roles, TTLs, and auto-approve status", "mimeType": "text/markdown"},
      {"uri": "clauth://services", "name": "HTTP Proxy Services", "description": "Configured web services accessible through the authenticated HTTP proxy with credential injection", "mimeType": "text/markdown"},
      {"uri": "clauth://roles", "name": "Roles & Permissions", "description": "Available roles, their SSH principals, and what each role can do on targets", "mimeType": "text/markdown"},
      {"uri": "clauth://status", "name": "Agent Status", "description": "Your current active certificates, sessions, and recent activity", "mimeType": "text/markdown"},
      {"uri": "clauth://tools", "name": "Tools Reference", "description": "Quick reference for all available MCP tools with parameters and usage examples", "mimeType": "text/markdown"}
    ]
  }
}
```

**Resources read example:**

```bash
curl -s -X POST http://BROKER:8554/mcp \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "resources/read",
    "params": {"uri": "clauth://overview"}
  }'
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "contents": [
      {
        "uri": "clauth://overview",
        "mimeType": "text/markdown",
        "text": "# Clauth Agent Access Broker\n\nZero-trust infrastructure access for AI agents..."
      }
    ]
  }
}
```

**Tools call example:**

```bash
curl -s -X POST http://BROKER:8554/mcp \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {"name": "list_targets", "arguments": {}}
  }'
```

**Available resources:**

| URI | Name | Content |
|-----|------|---------|
| `clauth://overview` | System Overview | Broker summary, target table, service table, tools table, quick start guide |
| `clauth://targets` | SSH Targets | Per-target details: host, port, VLAN, roles, TTL, approval mode, usage examples |
| `clauth://services` | HTTP Proxy Services | Per-service details: URL prefix, auth type, allowed methods/paths, usage examples |
| `clauth://roles` | Roles & Permissions | Role-to-principal mappings, per-role capabilities, role selection guide |
| `clauth://status` | Agent Status | Agent's active certs (count), active sessions (list), last 10 activity entries |
| `clauth://tools` | Tools Reference | All 14 tools with parameters, return types, and usage hints |
| `clauth://remotes` | Federated Servers | Configured MCP federation servers, status, and available tools |

Resources return dynamically generated Markdown content reflecting the current policy
configuration and live broker state. The `status` resource is personalized to the
requesting agent.

**Errors:**

| Code | Meaning |
|------|---------|
| -32600 | Invalid JSON-RPC request |
| -32601 | Unknown method |
| -32602 | Invalid parameters (e.g., missing required field, unknown resource URI) |
| -32603 | Internal error (signer down, SSH failure) |

---

### GET /v1/metrics

Returns Prometheus-format metrics for monitoring. Includes latency histograms for token operations, counters for tasks/tokens/revocations, and gauges for active state.

No authentication required (intended for Prometheus scraping).
