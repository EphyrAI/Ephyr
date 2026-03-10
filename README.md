<p align="center">
  <h1 align="center">Clauth</h1>
  <p align="center"><i>pronounced "klawth"</i></p>
  <p align="center">
    <strong>Zero-trust infrastructure access for AI agents.<br>Every connection authenticated, authorized, audited.</strong>
  </p>
</p>

<p align="center">
  <a href="#quick-start"><img alt="Go 1.24+" src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" /></a>
  <a href="#license"><img alt="License" src="https://img.shields.io/badge/License-Apache_2.0-blue" /></a>
  <img alt="Zero Trust" src="https://img.shields.io/badge/Zero_Trust-Agent_Auth-8B5CF6" />
  <img alt="MCP" src="https://img.shields.io/badge/MCP-2025--03--26-10B981" />
</p>

---

Clauth is an SSH certificate broker purpose-built for autonomous AI agents. Instead of scattering SSH keys and API tokens across your infrastructure, Clauth issues short-lived certificates through a policy engine -- so every agent action is scoped, time-limited, and logged.

It also provides an MCP (Model Context Protocol) server, letting AI agents like Claude request infrastructure access through the same interface they use for everything else. No custom integrations. No credential leakage. Just declare policy, point your agent at the broker, and go.

## Why Clauth?

Static SSH keys for AI agents are a liability. They don't expire, they can't be scoped per-task, and when an agent session ends the keys remain. Clauth replaces that model entirely:

- **Ephemeral certificates** -- 5-minute default TTL. When the task is done, access disappears.
- **Declarative policy** -- YAML defines who can access what, with what role, for how long. Hot-reload with SIGHUP.
- **MCP-native** -- Agents don't shell out to SSH. They call tools through the Model Context Protocol and get structured results.
- **Credential-free agents** -- The HTTP proxy injects API tokens at the broker level. Agents never see passwords or keys.
- **Full audit trail** -- Every certificate, every command, every denied request. Structured JSON, ready for your SIEM.

## Architecture

Clauth runs as three isolated processes with strict privilege separation:

```
                                    +------------------------------+
                                    |         Dashboard            |
                                    |  React SPA - WebSocket - TCP |
                                    +-------------+----------------+
                                                  | :8553
                                                  |
+------------------+  Unix socket  +--------------+----------------+  Unix socket  +------------------+
|                  |  /run/clauth/ |                               |  /run/clauth/ |                  |
|   Agent          |  broker.sock  |         clauth-broker         |  signer.sock  |  clauth-signer   |
|   (CLI or MCP)   +-------------->|                               +-------------->|                  |
|                  |               |  Policy engine - Sessions     |               |  CA key holder   |
+--------+---------+               |  MCP server - HTTP proxy      |               |  Signs certs     |
         |                         |  Activity monitor - Audit     |               |  Never on network|
         |                         +--------------+----------------+               +------------------+
         |                                        |
         |  SSH with ephemeral cert               |  HTTP proxy with
         |                                        |  credential injection
         v                                        v
+------------------+               +-------------------------------+
|  Target Host     |               |  Internal Service             |
|  (SSH server)    |               |  (Gitea, Grafana, n8n, ...)   |
+------------------+               +-------------------------------+
```

**clauth-signer** holds the Ed25519 CA private key and does nothing else. It listens on a Unix socket, signs certificate requests, and runs in a systemd sandbox with `ProtectSystem=strict`, `MemoryDenyWriteExecute`, and zero capabilities. The CA key never leaves this process.

**clauth-broker** is the brain. It loads policy from YAML, evaluates certificate requests through an 8-step pipeline, manages sessions and certificate lifecycle, serves the dashboard and MCP endpoint, proxies HTTP requests with credential injection, and writes structured audit logs. It communicates with the signer exclusively through Unix socket IPC.

**clauth** (CLI) is the agent-side tool. It creates sessions, requests certificates, opens SSH connections, and executes remote commands -- all through the broker's Unix socket API.

## Features

### SSH Certificate Authority

Ed25519 CA issuing ephemeral, per-request certificates. Default TTL is 5 minutes, configurable up to 30 minutes per-target. Each certificate is scoped to a specific agent, target, and role. Duplicate certificates for the same agent+target+role combination are automatically revoked when a new one is issued.

Auto-approve workflows let trusted agents get certificates instantly. For sensitive targets, requests enter a pending state until an admin approves them from the dashboard or CLI.

### MCP Server

JSON-RPC 2.0 over Streamable HTTP, implementing the [Model Context Protocol](https://modelcontextprotocol.io/) (2025-03-26). Eight tools and six resources give agents complete infrastructure access with built-in self-discovery.

**Tools:**

| Tool | Description |
|------|-------------|
| `list_targets` | Discover available hosts and permitted roles |
| `exec` | Run a command on a target via SSH certificate auth |
| `session_create` | Open a persistent SSH session (60x faster for sequential commands) |
| `session_close` | Close a persistent session |
| `list_sessions` | List active persistent SSH sessions |
| `list_certs` | List active certificates for this agent |
| `http_request` | Make an HTTP request through the authenticated proxy |
| `list_services` | List services with automatic credential injection |

**Resources** (agent self-discovery):

| URI | Description |
|-----|-------------|
| `clauth://overview` | System summary, available targets, services, and agent permissions |
| `clauth://targets` | SSH targets with hosts, ports, roles, and auto-approve status |
| `clauth://services` | HTTP proxy services with credential injection details |
| `clauth://roles` | Role definitions and SSH principal mappings |
| `clauth://status` | Agent's active certificates, sessions, and recent activity |
| `clauth://tools` | Quick reference for all MCP tools with parameters |

Resources let agents understand the system without external documentation. An agent can read `clauth://overview` on first connection to discover what infrastructure is available.

API key authentication with bcrypt hashing. Drop-in integration with Claude Code, Claude Desktop, or any MCP-compatible client.

Persistent SSH sessions reduce per-command latency from ~850ms (new cert + connection) to ~14ms (reuse existing connection) -- critical for agents that run dozens of commands in sequence.

### HTTP Proxy with Credential Injection

A generic authenticated proxy for internal web services. Configure a service once with its URL prefix and credentials, and agents can make requests without ever seeing the token. The broker injects authentication headers transparently.

Supported auth types: Bearer token, HTTP Basic, custom header, query parameter. Network policy enforces RFC 1918 by default with configurable CIDR allow/deny lists. URL path and HTTP method restrictions available per-service.

### Real-time Dashboard

React 18 single-page application with a cyberpunk dark theme. Nine views cover every aspect of the system:

- **Overview** -- system health, active certs, agent count, signer status
- **Hosts** -- target list with enable/disable toggles and config panel
- **Agents** -- per-agent activity stats and timeline
- **Activity** -- filterable log of all exec, proxy, and session actions
- **Sessions** -- active certificates with TTL countdown and revocation
- **Audit** -- structured event log from disk
- **Terminal** -- web-based SSH via xterm.js (multi-tab, up to 5 concurrent)
- **Services** -- HTTP proxy service configuration (CRUD)
- **Settings** -- broker configuration and token management

WebSocket live event streaming pushes state changes to all connected clients. Anti-screen-capture privacy mode blurs sensitive fields on tab switch and renders tokens to canvas elements that resist screenshots.

### Policy Engine

Declarative YAML configuration with hot-reload via `SIGHUP` -- no restart required. The evaluation pipeline runs 8 steps for every certificate request:

1. **Agent exists** -- verify the requesting UID is registered
2. **Target exists** -- verify the requested target is in policy
3. **Role allowed** -- check the role against the target's allowed list
4. **Duration clamped** -- enforce min(requested, target max, global max)
5. **Concurrent limit** -- per-agent active certificate cap
6. **Duplicate check** -- auto-revoke stale cert for same agent+target+role
7. **Global limit** -- cluster-wide active certificate cap
8. **Approval mode** -- auto-approve or hold for manual approval

Every denial includes a specific reason. Rate limiting is enforced per-agent with configurable windows.

### Activity Monitoring

A 10,000-entry ring buffer tracks all agent actions in real time. Seven activity types: `exec`, `http_proxy`, `session_open`, `session_close`, `cert_issued`, `cert_denied`, `mcp_call`. Per-agent statistics track total actions, errors, last active time, and most recent target.

Queryable by agent, type, target, service, time range, or errors-only. The dashboard surfaces top targets, top services, and a live activity feed.

### Audit Trail

Append-only structured JSON-line logging. Every certificate operation is recorded: issued, denied, revoked, approved, expired. Rate limit events, policy reloads, host toggles, and session lifecycle are all captured. Logrotate integration with 30-day retention out of the box.

### Security Hardening

- **Unix socket authentication** -- `SO_PEERCRED` extracts the caller's UID from the kernel. No passwords over the wire.
- **Constant-time token comparison** -- `crypto/subtle` prevents timing attacks on dashboard and API tokens.
- **Systemd sandboxing** -- `ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, `PrivateDevices`, `CapabilityBoundingSet=` (empty). Full system call filtering.
- **CA key isolation** -- the private key exists only in the signer process. The broker never reads it.
- **Socket permissions** -- broker socket is `0660` with group restriction.
- **Token masking** -- dashboard tokens are logged as `first4...last4`, never in full.
- **Session binding** -- certificate request tokens are bound to the originating UID. Stolen tokens cannot be replayed from a different process.

## Quick Start

### 1. Build

```bash
git clone https://github.com/sprawl/clauth.git
cd clauth
make build
# Output: bin/clauth-broker  bin/clauth-signer  bin/clauth
```

Requires Go 1.24+.

### 2. Generate CA key

```bash
mkdir -p /etc/clauth
ssh-keygen -t ed25519 -f /etc/clauth/ca_key -N ""
```

Add the CA public key to your target hosts' `sshd_config`:

```
TrustedUserCAKeys /etc/ssh/ca.pub
```

Copy the public key to each target:

```bash
scp /etc/clauth/ca_key.pub target:/etc/ssh/ca.pub
```

### 3. Configure policy

Create `/etc/clauth/policy.yaml`:

```yaml
global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"
  rate_limit:
    requests_per_window: 10
    window_seconds: 60

agents:
  claude:
    uid: 1000
    max_concurrent_certs: 3
    description: "Claude agent"
    # api_key_hash: "$2a$10$..."  # bcrypt hash for MCP API key auth

roles:
  read:
    principal: "agent-read"
    description: "Read-only access"
  operator:
    principal: "agent-op"
    description: "Operator access - restart services, deploy updates"

targets:
  webserver:
    host: "192.168.1.10"
    port: 22
    allowed_roles: [read, operator]
    max_ttl: "10m"
    auto_approve: true
    description: "Production web server"
```

### 4. Start services

```bash
# Create system user and directories
sudo make install-user

# Install systemd units
sudo make install-systemd

# Start signer first, then broker
sudo systemctl enable --now clauth-signer
sudo systemctl enable --now clauth-broker
```

Or run directly for development:

```bash
clauth-signer --ca-key /etc/clauth/ca_key --socket /run/clauth/signer.sock &
clauth-broker --policy /etc/clauth/policy.yaml --admin-uid 0
```

### 5. Use it

```bash
# Create a session (as the agent user, UID 1000)
clauth session create

# Request a certificate and SSH in
clauth ssh webserver --role read

# Or just run a command
clauth exec webserver --role operator -- systemctl status nginx
```

## MCP Integration

### Claude Code

Add to your `.claude/settings.json`:

```json
{
  "mcpServers": {
    "clauth": {
      "type": "url",
      "url": "http://your-broker:8554/mcp",
      "headers": {
        "Authorization": "Bearer your-api-key"
      }
    }
  }
}
```

Then ask Claude to manage your infrastructure naturally:

```
You: Check if nginx is running on the webserver

Claude: I'll check the nginx status on the webserver.

[Calling tool: exec]
  target: "webserver"
  role: "read"
  command: "systemctl status nginx"

nginx.service - A high performance web server
     Active: active (running) since Mon 2026-03-10 08:15:32 UTC
   Main PID: 1234 (nginx)
      Tasks: 5 (limit: 4096)
     Memory: 12.3M
        CPU: 1.234s

Nginx is running and healthy on the webserver. It has been up
since this morning with no recent restarts.
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "clauth": {
      "type": "url",
      "url": "http://your-broker:8554/mcp",
      "headers": {
        "Authorization": "Bearer your-api-key"
      }
    }
  }
}
```

The same 8 tools are available in any MCP-compatible client.

## Configuration

### Policy Reference

```yaml
global:
  max_active_certs: 10          # Cluster-wide cert cap
  default_ttl: "5m"             # Default certificate lifetime
  max_ttl: "30m"                # Absolute maximum lifetime
  rate_limit:
    requests_per_window: 10     # Requests per agent per window
    window_seconds: 60          # Rate limit window

agents:
  <name>:
    uid: <int>                  # Linux UID (matched via SO_PEERCRED)
    max_concurrent_certs: 3     # Per-agent active cert limit
    api_key_hash: "<bcrypt>"    # For MCP API key auth (optional)
    description: "..."

roles:
  <name>:
    principal: "<ssh-principal>" # Maps to SSH authorized principal
    description: "..."

targets:
  <name>:
    host: "<ip-or-hostname>"
    port: 22
    vlan: <int>                 # Informational, shown in dashboard
    allowed_roles: [role1, role2]
    max_ttl: "10m"              # Per-target TTL cap
    auto_approve: true          # Skip manual approval
    force_command: "..."        # SSH forced command (optional)
    description: "..."
```

### Environment Variables

All broker flags can be set via environment:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAUTH_POLICY` | `/etc/clauth/policy.yaml` | Policy file path |
| `CLAUTH_SIGNER_SOCKET` | `/run/clauth/signer.sock` | Signer IPC socket |
| `CLAUTH_LISTEN` | `/run/clauth/broker.sock` | Broker Unix socket |
| `CLAUTH_AUDIT_LOG` | `/var/log/clauth/audit.json` | Audit log path |
| `CLAUTH_DASHBOARD_LISTEN` | `:8553` | Dashboard TCP address |
| `CLAUTH_DASHBOARD_TOKEN` | *(auto-generated)* | Dashboard API token |
| `CLAUTH_DASHBOARD_DIR` | `/opt/clauth/dashboard` | Static files directory |
| `CLAUTH_MCP_LISTEN` | `:8554` | MCP server TCP address |
| `CLAUTH_ADMIN_UIDS` | `0` | Comma-separated admin UIDs |
| `CLAUTH_SOCKET_GROUP` | `clauth-agents` | Unix socket group |

## API Reference

### Unix Socket API (`/run/clauth/broker.sock`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Broker health and signer connectivity |
| `POST` | `/v1/session` | Create agent session (UID-authenticated) |
| `GET` | `/v1/session` | Get current session info (whoami) |
| `POST` | `/v1/request` | Request an SSH certificate |
| `GET` | `/v1/certs` | List active certificates |
| `DELETE` | `/v1/certs/{serial}` | Revoke a certificate |
| `GET` | `/v1/targets` | List available targets and roles |
| `POST` | `/v1/approve/{request_id}` | Approve a pending request (admin) |
| `POST` | `/v1/deny/{request_id}` | Deny a pending request (admin) |
| `POST` | `/v1/admin/hosts/{name}/toggle` | Enable/disable host access (admin) |

### Dashboard TCP API (`:8553`)

All Unix socket endpoints above, plus:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/dashboard/summary` | System overview (uptime, certs, agents) |
| `GET` | `/v1/dashboard/hosts` | Host list with status and session counts |
| `GET` | `/v1/dashboard/sessions` | Active certs with TTL and expiry |
| `GET` | `/v1/dashboard/audit` | Audit log entries (`?limit=50&type=grant`) |
| `POST` | `/v1/dashboard/hosts/{name}/toggle` | Toggle host access |
| `POST` | `/v1/dashboard/sessions/{serial}/revoke` | Revoke a certificate |
| `GET` | `/v1/dashboard/config/hosts` | List host configurations |
| `GET` | `/v1/dashboard/config/hosts/{name}` | Get host config |
| `PUT` | `/v1/dashboard/config/hosts/{name}` | Update host config |
| `DELETE` | `/v1/dashboard/config/hosts/{name}` | Delete host config |
| `GET` | `/v1/dashboard/config/roles` | List role definitions |
| `GET` | `/v1/dashboard/terminal` | WebSocket SSH terminal proxy |
| `GET` | `/v1/dashboard/activity` | Query activity log |
| `GET` | `/v1/dashboard/activity/summary` | Activity statistics |
| `GET` | `/v1/dashboard/activity/agent/{name}` | Per-agent activity |
| `GET` | `/v1/dashboard/services` | List proxy services |
| `GET` | `/v1/dashboard/services/{name}` | Get service config |
| `PUT` | `/v1/dashboard/services/{name}` | Create/update service |
| `DELETE` | `/v1/dashboard/services/{name}` | Delete service |
| `GET` | `/v1/events` | WebSocket live event stream |

### MCP Endpoint (`:8554`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/mcp` | JSON-RPC 2.0 (initialize, tools/list, tools/call, resources/list, resources/read) |

## Project Structure

```
clauth/
├── cmd/
│   ├── broker/         # clauth-broker entry point, flag parsing, signal handling
│   ├── clauth/         # CLI tool: session, ssh, exec, key management
│   └── signer/         # clauth-signer entry point, CA key loading
├── internal/
│   ├── audit/          # Structured JSON-line audit logger, anomaly detection
│   ├── auth/           # Session manager, SO_PEERCRED extraction
│   ├── broker/         # Core broker: server, handlers, dashboard, MCP,
│   │                   #   proxy engine, activity store, config manager,
│   │                   #   terminal proxy, WebSocket hub, rate limiter
│   ├── policy/         # Policy types, YAML loader, evaluation engine
│   └── signer/         # Certificate signing, CA key management, IPC protocol
├── configs/
│   └── policy.yaml     # Default policy configuration
├── dashboard/
│   └── index.html      # React 18 SPA (~2,900 lines, CDN dependencies)
├── deploy/
│   └── systemd/        # clauth-broker.service, clauth-signer.service
├── Makefile            # build, test, install, install-systemd, install-user
├── go.mod              # 3 direct dependencies
└── go.sum
```

## Requirements

- **Go 1.24+** -- uses enhanced `net/http` routing patterns (Go 1.22+) and recent stdlib features
- **Linux** -- `SO_PEERCRED` for Unix socket peer authentication is Linux-specific
- **systemd** -- optional but recommended for production (sandboxing, restart, journal logging)
- **OpenSSH** -- target hosts need `TrustedUserCAKeys` configured

## Dependencies

Clauth is deliberately minimal. Three direct dependencies, all well-established:

| Module | Purpose |
|--------|---------|
| `github.com/gorilla/websocket` | WebSocket for dashboard events and terminal proxy |
| `golang.org/x/crypto` | SSH certificate operations, bcrypt for API key hashing |
| `gopkg.in/yaml.v3` | Policy YAML parsing |

No external databases. No message queues. No container runtime. State lives in memory and on disk as JSON files.

## Contributing

Clauth started as a homelab project to solve a real problem: giving Claude Code safe, auditable access to infrastructure without scattering SSH keys everywhere. It turns out this is a problem a lot of people have.

Contributions welcome. The codebase is ~10,000 lines of Go with no code generation and no frameworks -- just the standard library plus three dependencies. If you can read Go, you can contribute.

To run the tests:

```bash
make test
```

Please open an issue before starting work on large changes so we can discuss the approach.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <code>~10,000 lines of Go | 3 external dependencies | Zero external databases | Production-ready</code>
</p>
