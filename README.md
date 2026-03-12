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

Clauth is an access broker for AI agents, accessed entirely through MCP (Model Context Protocol). A single MCP connection replaces N different authentication mechanisms -- SSH keys, API tokens, service credentials -- with one unified, policy-governed interface.

Instead of scattering credentials across your infrastructure and hoping agents handle them responsibly, Clauth sits between agents and backends as a proxy, authenticator, and broker. The agent connects to one MCP endpoint. Clauth handles the rest: issuing ephemeral SSH certificates, injecting API tokens into HTTP requests, and forwarding calls to federated MCP servers -- all governed by declarative policy, scoped by role, time-limited by grants, and fully audited.

## Why Clauth?

Static credentials for AI agents are a liability. SSH keys don't expire, API tokens can't be scoped per-task, and when an agent session ends the access remains. Clauth replaces that model entirely:

- **One connection, all access** -- Agents connect to a single MCP endpoint. SSH targets, HTTP APIs, and remote MCP servers are all reachable through the broker. No direct backend access required.
- **Ephemeral credentials** -- SSH certificates default to 5-minute TTL. Service and MCP grants auto-expire. When the task is done, access disappears.
- **Network isolation** -- nftables blocks the agent user from reaching backends directly. All traffic flows through the broker, which enforces policy before proxying.
- **Credential-free agents** -- The broker injects API tokens, SSH certificates, and auth headers. Agents never see passwords or keys.
- **Declarative policy** -- YAML defines who can access what, with what role, for how long. Hot-reload with SIGHUP.
- **TTL-based grants** -- Beyond SSH certificates, the broker issues time-limited access grants for HTTP services and federated MCP servers, with a configurable passthrough mode for fire-and-forget access.
- **Full audit trail** -- Every certificate, every command, every HTTP proxy request, every denied action. Structured JSON, ready for your SIEM.

## Architecture

Clauth runs as three isolated processes with strict privilege separation. The broker is the sole point of contact for agents, proxying three distinct backend types:

```
                                    +------------------------------+
                                    |         Dashboard            |
                                    |  React SPA - WebSocket - TCP |
                                    +-------------+----------------+
                                                  | :8553
                                                  |
+------------------+  Unix socket  +--------------+----------------+  Unix socket  +------------------+
|                  |  /run/clauth/ |                               |  /run/clauth/ |                  |
|   Agent (CLI)    |  broker.sock  |         clauth-broker         |  signer.sock  |  clauth-signer   |
|                  +-------------->|                               +-------------->|                  |
+------------------+               |  Policy engine - Sessions     |               |  CA key holder   |
                                   |  MCP server - HTTP proxy      |               |  Signs certs     |
+------------------+  HTTP :8554   |  Grant store - Activity       |               |  Never on network|
|   Agent (MCP)    |  Bearer auth  |  MCP federation - Audit       |               +------------------+
|  Claude, etc.    +-------------->|                               |
+--------+---------+               +-+------------+----------+-----+
         |                           |            |          |
     nftables blocks          Three proxy paths:
     direct access            1. SSH exec     2. HTTP proxy   3. MCP federation
                                   |            |          |
                                   v            v          v
                            +------------------+  +------------------+  +------------------+
                            |  Target Hosts    |  |  Web Services    |  |  Remote MCP      |
                            |  (SSH servers)   |  |  (GitHub, etc.)  |  |  Servers         |
                            +------------------+  +------------------+  +------------------+
```

### Three Proxy Paths

**1. SSH Exec** -- The agent calls `exec` with a target and command. The broker generates an ephemeral Ed25519 keypair, has the signer issue a certificate via Unix socket IPC, SSHs to the target, runs the command, and returns stdout/stderr/exit_code. The agent never touches SSH keys or certificates. Persistent sessions reduce per-command latency from ~850ms to ~14ms.

**2. HTTP Proxy** -- The agent calls `http_request` with a URL. The broker matches the URL to a configured service, injects stored credentials (bearer token, basic auth, custom header, or query parameter), and forwards the request. Network policy controls which destinations are reachable: RFC 1918 by default, external hostnames via allowlist.

**3. MCP Federation** -- The agent calls a namespaced tool like `demo-tools.roll_dice`. The broker proxies the JSON-RPC call to the remote MCP server, injecting any configured credentials. Background discovery keeps tool catalogs fresh. From the agent's perspective, local and federated tools are indistinguishable.

### Network Isolation

On the broker host, nftables enforces that the agent user (UID 1000) cannot reach backend hosts directly. All output traffic from the agent to infrastructure IPs is dropped at the kernel level. The only path to backends is through the broker's Unix socket or MCP endpoint, where policy is enforced before every action. This means even a compromised agent process cannot bypass the broker.

### Process Isolation

**clauth-signer** holds the Ed25519 CA private key and does nothing else. It listens on a Unix socket, signs certificate requests, and runs in a systemd sandbox with `ProtectSystem=strict`, `MemoryDenyWriteExecute`, and zero capabilities. The CA key never leaves this process.

**clauth-broker** is the brain. It loads policy from YAML, evaluates certificate requests through an 8-step pipeline, manages sessions, grants, and certificate lifecycle, serves the dashboard and MCP endpoint, proxies HTTP requests with credential injection, federates remote MCP servers, and writes structured audit logs.

**clauth** (CLI) is the agent-side tool for direct SSH operations from the broker host.

## Features

### TTL-Based Access Grants

Clauth extends the ephemeral access model beyond SSH certificates. When an agent accesses an HTTP service or calls a federated MCP tool, the broker issues a time-limited access grant tracking the agent, resource, and expiry. Three grant types:

| Type | Default TTL | Scope |
|------|-------------|-------|
| `ssh_cert` | 5 min | Tracked in CertState (existing SSH CA system) |
| `service` | 5 min | HTTP proxy service access |
| `mcp` | 5 min | Federated MCP server access |

Grants auto-expire and are cleaned up by a background goroutine. Duplicate grants for the same agent+resource pair are deduplicated (existing valid grant is returned). Each service and remote MCP server can be configured with its own grant mode:

- **TTL mode** (default) -- grants are issued and validated on each request
- **Passthrough mode** -- grant issuance is skipped entirely for fire-and-forget access patterns

Grant lifecycle events (issued, expired, revoked) are recorded in the activity store and visible on the dashboard.

### SSH Certificate Authority

Ed25519 CA issuing ephemeral, per-request certificates. Default TTL is 5 minutes, configurable up to 30 minutes per-target. Each certificate is scoped to a specific agent, target, and role. Duplicate certificates for the same agent+target+role combination are automatically revoked when a new one is issued.

Auto-approve workflows let trusted agents get certificates instantly. For sensitive targets, requests enter a pending state until an admin approves them from the dashboard or CLI.

### MCP Server

JSON-RPC 2.0 over Streamable HTTP, implementing the [Model Context Protocol](https://modelcontextprotocol.io/) (2025-03-26). Ten tools (plus federated tools from remote servers) and seven resources give agents complete infrastructure access with built-in self-discovery.

**Tools (10 local + federated):**

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
| `list_remotes` | List federated remote MCP servers and their tools |
| *`{server}.{tool}`* | *Federated tools from remote MCP servers (dynamic)* |

**Resources** (agent self-discovery):

| URI | Description |
|-----|-------------|
| `clauth://overview` | System summary, available targets, services, and agent permissions |
| `clauth://targets` | SSH targets with hosts, ports, roles, and auto-approve status |
| `clauth://services` | HTTP proxy services with credential injection details |
| `clauth://roles` | Role definitions and SSH principal mappings |
| `clauth://status` | Agent's active certificates, sessions, and recent activity |
| `clauth://tools` | Quick reference for all MCP tools with parameters |
| `clauth://remotes` | Federated MCP servers with connection status and available tools |

Resources let agents understand the system without external documentation. An agent can read `clauth://overview` on first connection to discover what infrastructure is available.

API key authentication with bcrypt hashing. Drop-in integration with Claude Code, Claude Desktop, or any MCP-compatible client.

### HTTP Proxy with Credential Injection

A generic authenticated proxy for any web service -- internal or external. Configure a service once with its URL prefix and credentials, and agents can make requests without ever seeing the token. The broker injects authentication headers transparently.

Works with internal services (Gitea, Grafana, Portainer) and external APIs (GitHub, cloud providers) alike. Network policy controls which destinations agents can reach: RFC 1918 private ranges are allowed by default, external access uses a configurable hostname allowlist. Supported auth types: Bearer token, HTTP Basic, custom header, query parameter. URL path and HTTP method restrictions available per-service. Services can be individually enabled/disabled via the dashboard.

### MCP Federation

Clauth can aggregate tools and resources from remote MCP servers, presenting them through a single unified endpoint. Configure a remote server once, and the broker automatically discovers its tools via the MCP handshake (initialize -> tools/list -> resources/list), then exposes them to agents with namespace prefixing.

Remote tools appear as `{server}.{tool}` (e.g., `demo-tools.roll_dice`). When an agent calls a federated tool, the broker proxies the request transparently, injecting any configured credentials. Background refresh keeps the tool catalog up to date, with exponential backoff on failures.

Remote servers can use any auth type (bearer, basic, header, none) and are managed via the dashboard or REST API. Each remote's connection status, tool count, and last refresh time are visible in real time. Remotes can be individually enabled/disabled.

### Real-time Dashboard

React 18 single-page application with a cyberpunk dark theme. Ten views across four groups:

- **OVERVIEW:** Overview -- stat cards, host/service/MCP panels with toggles, active sessions, live event feed
- **INFRASTRUCTURE:** Hosts, Services, MCP Servers (with enable/disable toggles and config panels)
- **MONITOR:** Agents, Activity, Sessions, Audit Log
- **TOOLS:** Terminal, Settings

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
- **Network isolation** -- nftables drops direct agent-to-backend traffic. All access is brokered.
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

# Discover available infrastructure
clauth targets     # SSH targets
clauth services    # HTTP proxy services
clauth remotes     # Federated MCP servers
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

The same tools are available in any MCP-compatible client.

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
| `GET` | `/v1/services` | List HTTP proxy services (credentials redacted) |
| `GET` | `/v1/remotes` | List federated MCP servers with status |

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
| `POST` | `/v1/dashboard/services/{name}/toggle` | Toggle service on/off |
| `GET` | `/v1/dashboard/remotes` | List remote MCP servers |
| `GET` | `/v1/dashboard/remotes/{name}` | Get remote config and status |
| `PUT` | `/v1/dashboard/remotes/{name}` | Create/update remote |
| `DELETE` | `/v1/dashboard/remotes/{name}` | Delete remote |
| `POST` | `/v1/dashboard/remotes/{name}/refresh` | Force tool re-discovery |
| `POST` | `/v1/dashboard/remotes/{name}/toggle` | Toggle remote on/off |
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
│   ├── clauth/         # CLI tool: session, ssh, exec, service/remote discovery
│   └── signer/         # clauth-signer entry point, CA key loading
├── internal/
│   ├── audit/          # Structured JSON-line audit logger, anomaly detection
│   ├── auth/           # Session manager, SO_PEERCRED extraction
│   ├── broker/         # Core broker: server, handlers, dashboard, MCP,
│   │                   #   proxy engine, activity store, config manager,
│   │                   #   terminal proxy, WebSocket hub, rate limiter,
│   │                   #   MCP federation engine, grant store
│   ├── policy/         # Policy types, YAML loader, evaluation engine
│   └── signer/         # Certificate signing, CA key management, IPC protocol
├── configs/
│   └── policy.yaml     # Default policy configuration
├── dashboard/
│   └── index.html      # React 18 SPA (~3,300 lines, CDN dependencies)
├── deploy/
│   └── systemd/        # clauth-broker.service, clauth-signer.service
├── docs/               # Architecture, security, configuration, deployment,
│                       #   API reference, MCP integration docs
├── CLAUDE.md           # Project instructions for Claude Code
├── CONTRIBUTING.md     # Contributor guidelines
├── Makefile            # build, test, install, install-systemd, install-user
├── go.mod              # 3 direct dependencies
└── go.sum
```

## Requirements
## Requirements

- **Go 1.24+** -- uses enhanced `net/http` routing patterns (Go 1.22+) and recent stdlib features
- **Linux** -- `SO_PEERCRED` for Unix socket peer authentication is Linux-specific
- **systemd** -- optional but recommended for production (sandboxing, restart, journal logging)
- **OpenSSH** -- target hosts need `TrustedUserCAKeys` configured
- **nftables** -- recommended for network isolation (blocking agent direct access to backends)

## Dependencies

Clauth is deliberately minimal. Three direct dependencies, all well-established:

| Module | Purpose |
|--------|---------|
| `github.com/gorilla/websocket` | WebSocket for dashboard events and terminal proxy |
| `golang.org/x/crypto` | SSH certificate operations, bcrypt for API key hashing |
| `gopkg.in/yaml.v3` | Policy YAML parsing |

No external databases. No message queues. No container runtime. State lives in memory and on disk as JSON files.

## RBAC -- Per-Agent Permissions

Clauth implements fine-grained, per-agent access control across all three proxy paths (SSH, HTTP, MCP federation) and the dashboard. Permissions are defined declaratively in `policy.yaml` using a template inheritance model.

### Overview

Every agent can have explicit permissions for:

- **SSH targets** -- Which targets the agent can access and with which roles (intersection with the target's `allowed_roles`)
- **HTTP proxy services** -- Which services the agent can use and which HTTP methods are permitted
- **MCP federation** -- Which remote MCP servers the agent can call and optionally which tools
- **Dashboard** -- Access level: `none`, `viewer`, `operator`, or `admin`

### Backwards Compatibility

Agents that do not define any RBAC fields (`ssh`, `services`, `remotes`, `dashboard`) operate in **legacy mode** with full access -- the same behavior as before RBAC was added. This means existing deployments continue to work without any policy changes.

### Templates

Templates define reusable permission sets. An agent inherits permissions from one or more templates via the `inherits` field, then applies agent-level overrides.

```yaml
templates:
  monitoring:
    description: "Read-only monitoring"
    ssh:
      "*":                    # wildcard: applies to all targets
        roles: [read]
        auto_approve: true
    services:
      grafana:
        methods: [GET]
      uptime-kuma:
        methods: [GET]
    remotes: {}               # empty = no federation access
    dashboard: "viewer"

  full-ops:
    description: "Operator-level access to everything"
    ssh:
      "*":
        roles: [read, operator]
        auto_approve: true
    services:
      "*":                    # wildcard: all services
        methods: [GET, POST, PUT, PATCH, DELETE]
    remotes:
      "*": {}                 # wildcard: all remotes, all tools
    dashboard: "operator"
```

### Per-Agent Configuration

Agents reference templates and add overrides:

```yaml
agents:
  claude:
    uid: 1000
    max_concurrent_certs: 20
    api_key_hash: "$2a$10$..."
    inherits: [full-ops]          # inherit from template(s)
    ssh:
      docker-host:                # override: admin on docker-host
        roles: [read, operator, admin]
        auto_approve: true
      mandrake-rack:
        roles: [read, operator]
        auto_approve: true
    services:
      github:
        methods: [GET, POST, PUT, PATCH, DELETE]
      grafana:
        methods: [GET]            # restrict to read-only
    remotes:
      demo-tools: {}              # allow this remote, all tools
    dashboard: "admin"            # override template's "operator"

  monitoring-bot:
    uid: 1001
    inherits: [monitoring]        # read-only everywhere
    # No overrides needed -- template is sufficient
```

### Permission Resolution Rules

When an agent inherits from a template and also defines its own permissions, the resolution follows these rules:

1. **SSH roles** -- Per-target, the agent's effective roles are the **intersection** of:
   - The roles listed in the agent's `ssh` block for that target (or inherited from template)
   - The `allowed_roles` defined on the target itself in the `targets` section
   - If neither the agent nor its templates define SSH permissions for a target, the agent cannot access it (unless in legacy mode)

2. **Services** -- The agent can only access services explicitly listed in its `services` block or inherited via templates. The `methods` list restricts which HTTP methods are allowed. A wildcard `"*"` key means all services are accessible.

3. **Remotes** -- The agent can only call federated tools on remotes explicitly listed in its `remotes` block or inherited via templates. A wildcard `"*"` key means all remotes are accessible. Per-remote tool restrictions are optional.

4. **Dashboard** -- Agent-level `dashboard` value overrides the inherited template value. Levels: `none` (no dashboard access), `viewer` (read-only), `operator` (toggles and basic management), `admin` (full access including settings).

5. **Agent overrides win** -- When an agent defines a field that also exists in an inherited template, the agent's value takes precedence for that specific key. Unspecified keys fall through to the template.

6. **Multiple templates** -- When inheriting from multiple templates, they are merged left-to-right. Later templates override earlier ones for the same keys.

### Discovery Filtering

The `list_targets`, `list_services`, and `list_remotes` MCP tools automatically filter their results based on the calling agent's permissions. An agent only sees infrastructure it is allowed to access:

- `list_targets` returns only targets where the agent has at least one permitted role
- `list_services` returns only services the agent is allowed to use
- `list_remotes` returns only remotes the agent is allowed to call

This means agents self-discover their available infrastructure without seeing resources they cannot access.

### Enforcement Points

RBAC permissions are enforced at three levels:

| Layer | File | What it checks |
|-------|------|----------------|
| SSH exec | `mcp_tools.go` | Agent's roles for the target, intersection with target's `allowed_roles` |
| HTTP proxy | `proxy.go` | Agent's allowed services and permitted HTTP methods |
| MCP federation | `mcp.go` | Agent's allowed remotes and optional tool restrictions |
| Discovery | `mcp_tools.go` | Filters `list_targets`, `list_services`, `list_remotes` results |
| Dashboard | `dashboard.go` | Agent's dashboard access level |

### Example: Restricting a New Agent

To add a monitoring-only agent that can read from all hosts but only view Grafana dashboards:

```yaml
agents:
  prometheus-scraper:
    uid: 1002
    max_concurrent_certs: 3
    inherits: [monitoring]
    services:
      grafana:
        methods: [GET]
    remotes: {}
    dashboard: "none"
```

This agent gets SSH `read` on all targets (from the `monitoring` template), can only make GET requests to Grafana, has no access to federated MCP servers, and cannot use the dashboard.

## Roadmap

### Implemented

- **RBAC** -- Per-agent permissions for SSH targets, HTTP proxy services, and MCP federation. Template inheritance, wildcard support, method restrictions, dashboard access levels. See the [RBAC](#rbac--per-agent-permissions) section below.

### Planned

Roughly prioritized:

- **Prometheus metrics + ntfy alerts** -- Export cert counts, request rates, error rates. Push alerts on denied requests or anomalous activity.
- **Sub-agent tracking** -- Accept an optional context/session ID from MCP clients to distinguish parallel sub-agents (e.g. Claude Code's Agent tool). Track and display as a tree: parent agent -> sub-agents -> their actions. Requires a custom MCP extension since the protocol has no sub-session concept.
- **OIDC / JWT agent auth** -- Alternative to API key auth for multi-tenant deployments.
- **Certificate pinning to source IP** -- Bind certs to the requesting agent's IP for defense-in-depth.
- **Target health checks** -- Periodic SSH connectivity probes with dashboard status.
- **Audit log export** -- Ship structured logs to external SIEM (syslog, webhook, S3).
- **Broker-level command policy** -- Command filtering at the broker before cert signing, adding a second enforcement layer above the host OS boundary. Two planned modes:
  - *Allowlist mode* -- Only pre-approved command patterns pass (e.g., `cat *`, `docker ps *`, `systemctl status *`). Strictest security but most restrictive.
  - *Denylist mode* -- Block known-dangerous patterns (e.g., `rm -rf /*`, `dd if=*`, `mkfs.*`, `shutdown*`). More flexible but requires careful pattern maintenance.
  - Long-term goal: capability-based roles that map to curated command templates rather than raw shell pattern matching, avoiding the inherent complexity of bash command parsing (escapes, subshells, globs, quoting).
  - Current architecture already supports this -- all agent commands flow through the broker via nftables isolation, so the broker is already a chokepoint. Today RBAC controls *which role* an agent gets; command policy would control *what they can do with it*.

## Contributing

Clauth started as a homelab project to solve a real problem: giving Claude Code safe, auditable access to infrastructure without scattering SSH keys everywhere. It turns out this is a problem a lot of people have.

Contributions welcome. The codebase is ~16,000 lines of Go + HTML with no code generation and no frameworks -- just the standard library plus three dependencies. If you can read Go, you can contribute.

To run the tests:

```bash
make test
```

Please open an issue before starting work on large changes so we can discuss the approach.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <code>~16,000 lines of Go + HTML | 3 external dependencies | Zero external databases | Production-ready</code>
</p>
