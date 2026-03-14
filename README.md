<p align="center">
  <h1 align="center">Ephyr</h1>
  <p align="center"><i>pronounced "klawth"</i></p>
  <p align="center">
    <strong>A broker that gives AI agents ephemeral, auditable, policy-controlled access<br>to infrastructure -- without standing credentials.</strong>
  </p>
</p>

<p align="center">
  <a href="https://github.com/ben-spanswick/Ephyr/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ben-spanswick/Ephyr/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="#quick-start"><img alt="Go 1.24+" src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" /></a>
  <a href="#license"><img alt="License" src="https://img.shields.io/badge/License-Apache_2.0-blue" /></a>
  <img alt="Brokered Access" src="https://img.shields.io/badge/Brokered-Least_Privilege-8B5CF6" />
  <img alt="MCP" src="https://img.shields.io/badge/MCP-2025--03--26-10B981" />
</p>

---

## What is Ephyr?

Ephyr is an access broker that gives AI agents ephemeral, policy-controlled access to infrastructure through a single MCP endpoint. It replaces scattered SSH keys, API tokens, and service credentials with one unified, auditable control plane -- agents connect to the broker, and the broker handles authentication, authorization, and credential injection on their behalf.

With v0.2, Ephyr adds task-scoped portable identity: agents create tasks, receive signed tokens that scope all actions to a task ID with capability envelopes, and every command is correlated back to its originating task for full traceability.

## Architecture

```
                                    +------------------------------+
                                    |         Dashboard            |
                                    |       (admin UI, :8553)      |
                                    +-------------+----------------+
                                                  |
                                                  |
+------------------+  Unix socket  +--------------+----------------+  Unix socket  +------------------+
|                  |  /run/ephyr/ |                               |  /run/ephyr/ |                  |
|   Agent (CLI)    |  broker.sock  |         ephyr-broker         |  signer.sock  |  ephyr-signer   |
|                  +-------------->|                               +-------------->|                  |
+------------------+               |  Policy engine   Sessions     |               |  CA key custody  |
                                   |  MCP server      Grant store  |               |  SSH cert signing|
+------------------+  HTTP :8554   |  Task identity   Metrics      |               |  Delegation certs|
|   Agent (MCP)    |  Bearer auth  |  Activity store  Audit        |               |  Never on network|
|  Claude, etc.    +-------------->|                               |               +------------------+
+--------+---------+               +-+------------+----------+-----+
         |                           |            |          |
     nftables blocks          Three proxy paths:
     direct access            1. SSH exec     2. HTTP proxy   3. MCP federation
     (when configured)             |            |          |
                                   v            v          v
                            +------------------+  +------------------+  +------------------+
                            |  Target Hosts    |  |  Web Services    |  |  Remote MCP      |
                            |  (SSH servers)   |  |  (APIs, etc.)    |  |  Servers         |
                            +------------------+  +------------------+  +------------------+
```

Three isolated processes with strict privilege separation:

- **ephyr-signer** -- Holds the Ed25519 CA private key. Signs SSH certificates and delegation certificates via Unix socket IPC. Runs in a systemd sandbox with `ProtectSystem=strict`, `MemoryDenyWriteExecute`, and zero capabilities. The CA key never leaves this process.

- **ephyr-broker** -- The control plane. Loads policy from YAML, evaluates requests, manages sessions/grants/certificates, serves the MCP endpoint (15 tools), proxies HTTP requests with credential injection, federates remote MCP servers, issues and validates task identity tokens, exports Prometheus metrics, and writes structured audit logs.

- **ephyr** (CLI) -- Agent-side tool for direct SSH operations from the broker host.

## Intended Deployment Model

Ephyr is designed for:

- **Homelabs and power users** who give AI agents (Claude Code, etc.) access to their infrastructure
- **Internal engineering teams** managing dev/staging/prod environments with AI-assisted operations
- **Single-tenant environments** where a small number of trusted operators control the broker

Ephyr is **not** designed for multi-tenant SaaS, public-facing agent platforms, or environments where the broker operator is untrusted. It assumes a trusted administrator who defines policy and manages the broker.

## Why Ephyr?

Static credentials for AI agents are a liability. SSH keys don't expire, API tokens can't be scoped per-task, and when an agent session ends the access remains. Ephyr replaces that model:

- **One connection, all access** -- Agents connect to a single MCP endpoint. SSH targets, HTTP APIs, and remote MCP servers are all reachable through the broker. No direct backend access required.
- **Ephemeral credentials** -- SSH certificates default to 5-minute TTL. Service and MCP grants auto-expire. When the task is done, access disappears.
- **Task-scoped identity** -- Agents create tasks and receive signed tokens that correlate every action to a task ID. Capability envelopes bound what a token can do. Epoch watermark revocation invalidates all tokens for a task instantly.
- **No standing backend credentials** -- The broker injects API tokens, SSH certificates, and auth headers. Agents never handle long-lived backend secrets directly.
- **Declarative policy** -- YAML defines who can access what, with what role, for how long. Hot-reload with SIGHUP.
- **Full audit trail** -- Every certificate, every command, every HTTP proxy request, every denied action. Structured JSON, ready for your SIEM. Task correlation ties actions to their originating task.
- **Network isolation** -- Optional nftables rules block the agent user from reaching backends directly. All traffic flows through the broker, which enforces policy before proxying.

## Features

### MCP Server (14 Tools)

JSON-RPC 2.0 over Streamable HTTP, implementing [MCP 2025-03-26](https://modelcontextprotocol.io/). Fourteen tools (10 core + 4 task identity) plus federated tools from remote servers.

**Core Tools:**

| Tool | Description |
|------|-------------|
| `list_targets` | Discover available SSH hosts and permitted roles |
| `exec` | Run a command on a target via ephemeral SSH certificate |
| `session_create` | Open a persistent SSH session (60x faster for sequential commands) |
| `session_close` | Close a persistent SSH session |
| `list_sessions` | List active persistent SSH sessions |
| `list_certs` | List active certificates for this agent |
| `http_request` | Make an HTTP request through the credential-injecting proxy |
| `list_services` | List available HTTP proxy services |
| `list_remotes` | List federated remote MCP servers and their tools |

**Task Identity Tools (v0.2):**

| Tool | Description |
|------|-------------|
| `task_create` | Create a task and receive a signed CTT-E token with capability envelope |
| `task_delegate` | Delegate a child task with attenuated capabilities (returns CTT-D token) |
| `task_info` | Get task details, status, and lineage |
| `task_list` | List active tasks for this agent |
| `task_revoke` | Revoke a task and all its tokens via epoch watermark (cascading to children) |

**Federated Tools:**

| Tool | Description |
|------|-------------|
| *`{server}.{tool}`* | Dynamically discovered tools from remote MCP servers (e.g., `devtools.list_repos`) |

**Resources** (agent self-discovery):

| URI | Description |
|-----|-------------|
| `ephyr://overview` | System summary, available targets, services, and agent permissions |
| `ephyr://targets` | SSH targets with hosts, ports, roles, and auto-approve status |
| `ephyr://services` | HTTP proxy services with credential injection details |
| `ephyr://roles` | Role definitions and SSH principal mappings |
| `ephyr://status` | Agent's active certificates, sessions, and recent activity |
| `ephyr://tools` | Quick reference for all MCP tools with parameters |
| `ephyr://remotes` | Federated MCP servers with connection status and available tools |

### SSH Certificate Authority

Ed25519 CA issuing ephemeral, per-request certificates. Default TTL is 5 minutes, configurable up to 30 minutes per-target. Each certificate is scoped to a specific agent, target, and role. Duplicate certificates for the same agent+target+role are automatically revoked when a new one is issued.

Persistent sessions reduce per-command latency from ~850ms to ~14ms for sequential operations.

### Task-Scoped Identity (v0.2) and Delegation (v0.3)

Agents create tasks via `task_create` and receive a signed CTT-E (Ephyr Task Token - Execution) JWT. The token carries:

- **Task ID** -- ULID (lexicographically sortable, encodes creation time)
- **Capability envelope** -- Upper-bound permissions (targets, roles, services, remotes, methods) resolved from RBAC policy at creation time
- **Lineage** -- Parent task reference for sub-task delegation

**Delegation with attenuation (v0.3):** Parent tasks created with `can_delegate: true` can spawn child tasks via `task_delegate`. Children receive CTT-D (delegation) tokens with capability envelopes that are equal to or a strict subset of the parent's. Maximum chain depth is 5. Child TTL cannot exceed parent's remaining TTL.

**Tiered trust model:** The signer issues delegation certificates to the broker. The broker signs task tokens locally using its delegation key -- no IPC round-trip per token. Delegation keys auto-rotate before expiry.

**Epoch watermark revocation:** `task_revoke` invalidates all tokens for a task by setting an epoch timestamp. Validation checks the watermark in O(depth) with no per-token blocklists. Cascading revocation propagates to all child tasks in the lineage.

**Full backward compatibility:** Agents without task tokens continue to work in legacy mode with unchanged behavior.

### HTTP Proxy with Credential Injection

A generic authenticated proxy for web services. Configure a service once with its URL prefix and credentials, and agents make requests without ever seeing the token. Supports bearer, basic auth, custom header, and query parameter injection. Network policy controls reachable destinations.

Works with internal services (Gitea, Grafana, Portainer) and external APIs (GitHub, cloud providers). Services can be individually enabled/disabled via the dashboard.

### MCP Federation

Aggregate tools from remote MCP servers through a single unified endpoint. The broker discovers tools automatically via MCP handshake, exposes them namespaced (e.g., `devtools.list_repos`), and proxies calls transparently with credential injection. Background refresh keeps catalogs current.

### Policy Engine

Declarative YAML with hot-reload via SIGHUP. Eight-step evaluation pipeline for every certificate request: agent exists, target exists, role allowed, duration clamped, concurrent limits, duplicate handling, global limits, approval mode. Every denial includes a specific reason.

### RBAC -- Per-Agent Permissions

Fine-grained, per-agent access control across all three proxy paths (SSH, HTTP, MCP federation) and the dashboard. Template inheritance, wildcard support, and agent-level overrides. Backwards-compatible legacy mode for agents without RBAC fields.

| Layer | What it checks |
|-------|----------------|
| SSH exec | Agent's roles for the target, intersection with target's `allowed_roles` |
| HTTP proxy | Agent's allowed services and permitted HTTP methods |
| MCP federation | Agent's allowed remotes and optional tool restrictions |
| Discovery | Filters `list_targets`, `list_services`, `list_remotes` results |
| Dashboard | Agent's dashboard access level (none/viewer/operator/admin) |

### Prometheus Metrics

`GET /v1/metrics` endpoint in Prometheus exposition format. Lock-free atomic counters and latency histograms.

**Latency histograms** (7 buckets: <100us, <500us, <1ms, <5ms, <10ms, <50ms, >50ms):

| Metric | Description |
|--------|-------------|
| `ephyr_token_sign_seconds` | Token signing latency |
| `ephyr_token_validate_seconds` | Token validation latency |
| `ephyr_watermark_check_seconds` | Watermark revocation check latency |
| `ephyr_envelope_check_seconds` | Capability envelope check latency |
| `ephyr_policy_eval_seconds` | Policy evaluation latency |
| `ephyr_ssh_cert_seconds` | SSH certificate signing latency |
| `ephyr_delegation_ipc_seconds` | Delegation IPC latency |
| `ephyr_exec_e2e_seconds` | End-to-end exec latency |

**Counters and gauges:**

| Metric | Type | Description |
|--------|------|-------------|
| `ephyr_tasks_created_total` | counter | Total tasks created |
| `ephyr_tasks_active` | gauge | Currently active tasks |
| `ephyr_tokens_signed_total` | counter | Total CTT-E tokens signed |
| `ephyr_tokens_validated_total` | counter | Total tokens validated |
| `ephyr_tokens_rejected_total` | counter | Total tokens rejected |
| `ephyr_watermark_revocations_total` | counter | Total watermark revocations |
| `ephyr_delegation_rotations_total` | counter | Total delegation cert rotations |
| `ephyr_legacy_requests_total` | counter | Requests without CTT (legacy mode) |
| `ephyr_auth_cache_hits_total` | counter | Auth cache hits (bcrypt bypassed) |
| `ephyr_auth_cache_misses_total` | counter | Auth cache misses (bcrypt required) |

### Auth Cache

SHA-256 keyed bcrypt result cache with configurable TTL. Eliminates redundant bcrypt verification on repeated MCP requests from the same agent.

| Metric | Value |
|--------|-------|
| Cold auth (bcrypt) | ~216ms |
| Warm auth (cache hit) | <1ms |
| Speedup | 187x |
| Default TTL | 60 seconds |
| Configuration | `EPHYR_AUTH_CACHE_TTL` env var |
| Disable | `EPHYR_AUTH_CACHE_TTL=0` or `off` or `false` |

### Dashboard

Single-page admin UI with ten views across four groups:

- **OVERVIEW:** System summary, stat cards, host/service/MCP panels with toggles, active sessions, live event feed
- **INFRASTRUCTURE:** Hosts, Services, MCP Servers -- enable/disable toggles, configuration panels
- **MONITOR:** Agents, Activity, Sessions, Audit Log -- searchable, filterable
- **TOOLS:** Terminal (WebSocket SSH proxy), Settings

Key operational controls: policy inspection, emergency certificate revocation, remote enable/disable without restart, audit log search. WebSocket live event streaming.

### Security Hardening

- **Unix socket authentication** -- `SO_PEERCRED` extracts the caller's UID from the kernel
- **Constant-time token comparison** -- `crypto/subtle` prevents timing attacks
- **Systemd sandboxing** -- `ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, zero capabilities
- **CA key isolation** -- Private key exists only in the signer process; broker never reads it
- **Network isolation** -- nftables drops direct agent-to-backend traffic
- **Delegation separation** -- Broker signs task tokens with a delegated key, not the CA key
- **Epoch revocation** -- No per-token blocklists; watermark-based invalidation in O(depth)

## Performance

Benchmarked on a Debian 12 LXC (1 vCPU, 512MB RAM):

| Operation | Latency | Notes |
|-----------|---------|-------|
| Auth (cold, bcrypt) | ~216ms | First request per API key |
| Auth (warm, cached) | <1ms | Subsequent requests within TTL (187x speedup) |
| Token signing | <1ms | Ed25519 local signing via delegation key |
| Token validation | <1ms | Signature + envelope + watermark check |
| SSH exec (new cert) | ~850ms | Full cert issuance + SSH connection |
| SSH exec (session) | ~14ms | Persistent session reuse (60x faster) |

## Security Boundaries

### What Ephyr enforces

- **Access issuance policy** -- Which agents can reach which targets, with which roles, for how long
- **Task-scoped identity** -- Capability envelopes bound what a token can do; watermark revocation invalidates instantly
- **Request-level audit** -- Every action logged with agent identity, target, timestamp, outcome, and task correlation
- **Credential isolation** -- Backend credentials live in the broker/signer processes; agents never receive long-lived secrets
- **Grant expiry** -- All access is time-limited with automatic cleanup

### What target hosts enforce

- **Command-level permissions** -- SSH principals map to Linux users with shell restrictions, sudoers rules, and filesystem permissions
- **OS-level isolation** -- SELinux/AppArmor, filesystem permissions, and host network policy are the final enforcement layer

### Threat model

- Broker compromise does not expose the CA key (signer is a separate process)
- Host compromise can abuse active grants within TTL only (default 5 minutes)
- Network isolation is defense-in-depth, not a substitute for host hardening
- See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for 12 enumerated threats with mitigations

## Quick Start

### 1. Build

```bash
git clone https://github.com/ben-spanswick/ephyr.git
cd ephyr
make build
# Output: bin/ephyr-broker  bin/ephyr-signer  bin/ephyr
```

Requires Go 1.24+.

### 2. Generate CA key

```bash
mkdir -p /etc/ephyr
ssh-keygen -t ed25519 -f /etc/ephyr/ca_key -N ""
```

### 3. Configure policy

Create `/etc/ephyr/policy.yaml` (see `configs/policy.yaml` for a complete example):

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
    description: "Operator access"

targets:
  webserver:
    host: "10.0.1.10"
    port: 22
    allowed_roles: [read, operator]
    max_ttl: "10m"
    auto_approve: true
    description: "Production web server"
```

### 4. Configure target hosts

Deploy the CA public key and create role accounts on each target:

```bash
# On each target host:
scp /etc/ephyr/ca_key.pub target:/etc/ssh/ephyr_ca.pub

# Add to sshd_config:
#   TrustedUserCAKeys /etc/ssh/ephyr_ca.pub
#   AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u

# Create role accounts:
useradd -m -s /usr/bin/rbash agent-read
useradd -m -s /bin/bash agent-op
echo "agent-read" > /etc/ssh/auth_principals/agent-read
echo "agent-op" > /etc/ssh/auth_principals/agent-op
```

Or use the provisioning script: `deploy/scripts/provision-target.sh`

### 5. Start services

```bash
sudo make install-user      # Create system user and directories
sudo make install-systemd   # Install systemd units
sudo systemctl enable --now ephyr-signer ephyr-broker
```

Or run directly:

```bash
ephyr-signer --ca-key /etc/ephyr/ca_key --socket /run/ephyr/signer.sock &
ephyr-broker --policy /etc/ephyr/policy.yaml --admin-uid 0
```

### 6. Connect an agent

Add to your `.claude/settings.json` (Claude Code), `claude_desktop_config.json` (Claude Desktop), or any MCP client:

```json
{
  "mcpServers": {
    "ephyr": {
      "type": "url",
      "url": "http://your-broker:8554/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

Generate an API key and add its bcrypt hash to `policy.yaml`:

```bash
# Generate key
openssl rand -base64 32

# Hash it
htpasswd -nbBC 10 "" "YOUR_KEY" | cut -d: -f2
```

### 7. Use it

```bash
# Via CLI (on broker host)
ephyr exec webserver --role read -- systemctl status nginx
ephyr session create   # persistent session for faster sequential commands

# Via MCP (from any connected agent)
# Agent calls: exec { target: "webserver", role: "read", command: "systemctl status nginx" }

# With task identity (v0.2)
# Agent calls: task_create { description: "Deploy update" }
# Agent calls: exec { target: "webserver", role: "operator", command: "..." }
# All actions correlated to the task ID
```

## Deployment

### Local (Same Machine)

Broker and agent on the same Linux host. Agent connects via Unix socket or MCP on localhost.

1. `make build && sudo make install`
2. `sudo make install-user && sudo make install-systemd`
3. Generate CA key, configure policy, deploy to target hosts
4. `sudo systemctl enable --now ephyr-signer ephyr-broker`

### Dedicated Host (VM / LXC / Bare Metal)

Recommended for production. Broker on its own host, agents connect over the network.

1. Provision a Debian/Ubuntu host
2. Build, install, configure (same as local)
3. Set `EPHYR_MCP_LISTEN=:8554` and `EPHYR_DASHBOARD_LISTEN=:8553`
4. Generate MCP API key, add bcrypt hash to policy
5. Configure firewall: allow 8554 (MCP) and 8553 (dashboard) from trusted networks
6. Provision target hosts with `deploy/scripts/provision-target.sh`

See [docs/deployment.md](docs/deployment.md) for detailed instructions.

## Configuration

### Environment Variables

All broker configuration can be set via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `EPHYR_POLICY` | `/etc/ephyr/policy.yaml` | Policy file path |
| `EPHYR_SIGNER_SOCKET` | `/run/ephyr/signer.sock` | Signer IPC socket path |
| `EPHYR_LISTEN` | `/run/ephyr/broker.sock` | Broker Unix socket path |
| `EPHYR_AUDIT_LOG` | `/var/log/ephyr/audit.json` | Audit log path |
| `EPHYR_DASHBOARD_LISTEN` | `:8553` | Dashboard TCP listen address |
| `EPHYR_DASHBOARD_TOKEN` | *(auto-generated)* | Dashboard API/login token |
| `EPHYR_DASHBOARD_DIR` | `/opt/ephyr/dashboard` | Dashboard static files directory |
| `EPHYR_MCP_LISTEN` | `:8554` | MCP server TCP listen address |
| `EPHYR_ADMIN_UIDS` | `0` | Comma-separated admin UIDs |
| `EPHYR_SOCKET_GROUP` | `ephyr-agents` | Unix socket group ownership |
| `EPHYR_AUTH_CACHE_TTL` | `60s` | Auth cache TTL (duration string, or `0`/`off`/`false` to disable) |

### Policy Reference

See [docs/configuration.md](docs/configuration.md) for the full policy schema. Key sections:

```yaml
global:         # Cluster-wide limits, rate limiting, default TTL
agents:         # Agent definitions with UID, API key hash, RBAC permissions
roles:          # SSH principal mappings
targets:        # SSH host definitions with allowed roles and TTL caps
templates:      # Reusable RBAC permission sets for template inheritance
```

## What Survives a Broker Restart

| Persists across restarts | Lost on restart |
|--------------------------|-----------------|
| Policy config (`policy.yaml`) | Active SSH sessions |
| Host/service/remote configs (JSON) | In-memory certificate state |
| Audit logs (append-only JSON) | WebSocket connections |
| CA key (in signer process) | Activity ring buffer |
| | Task state and tokens |

The signer process is independent -- a broker restart does not affect it. Active SSH certificates remain valid on target hosts until TTL expires, since validation is performed by the target's `sshd` against the CA public key.

## API Reference

### MCP Endpoint (`:8554`)

```
POST /mcp -- JSON-RPC 2.0 (initialize, tools/list, tools/call, resources/list, resources/read)
GET  /v1/metrics -- Prometheus metrics
```

### Unix Socket API (`/run/ephyr/broker.sock`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Broker health and signer connectivity |
| `POST` | `/v1/session` | Create agent session (UID-authenticated) |
| `GET` | `/v1/session` | Get current session info |
| `POST` | `/v1/request` | Request an SSH certificate |
| `GET` | `/v1/certs` | List active certificates |
| `DELETE` | `/v1/certs/{serial}` | Revoke a certificate |
| `GET` | `/v1/targets` | List available targets and roles |
| `POST` | `/v1/approve/{request_id}` | Approve a pending request (admin) |
| `POST` | `/v1/deny/{request_id}` | Deny a pending request (admin) |
| `POST` | `/v1/admin/hosts/{name}/toggle` | Enable/disable host access (admin) |
| `GET` | `/v1/services` | List HTTP proxy services |
| `GET` | `/v1/remotes` | List federated MCP servers |

### Dashboard TCP API (`:8553`)

All Unix socket endpoints above, plus dashboard-specific routes for summary, hosts, sessions, audit, activity, services, remotes, permissions, terminal, and configuration management. See [docs/api-reference.md](docs/api-reference.md) for the complete reference.

## Project Structure

```
ephyr/
├── cmd/
│   ├── broker/            # ephyr-broker entry point, flag parsing, signal handling
│   ├── ephyr/            # CLI tool: session, ssh, exec, service/remote discovery
│   └── signer/            # ephyr-signer entry point, CA key loading
├── internal/
│   ├── audit/             # Structured JSON-line audit logger, anomaly detection
│   ├── auth/              # Session manager, SO_PEERCRED extraction
│   ├── broker/            # Core broker: server, MCP, dashboard, proxy, federation,
│   │                      #   task identity, delegation, metrics, grants, activity,
│   │                      #   config manager, terminal proxy, WebSocket, rate limiter
│   ├── policy/            # Policy types, YAML loader, evaluation engine, RBAC resolver
│   │   └── testdata/      # Policy test fixtures
│   ├── signer/            # Certificate signing, CA key management, delegation, IPC
│   └── token/             # CTT-E token types, signing, validation, ULID generation
├── test/
│   └── integration/       # Integration smoke tests (8 tests against live instance)
├── configs/
│   └── policy.yaml        # Default policy configuration
├── dashboard/
│   └── index.html         # Single-page admin UI (~4,100 lines)
├── deploy/
│   ├── systemd/           # ephyr-broker.service, ephyr-signer.service
│   └── scripts/           # Target provisioning, sudoers, audit helpers
├── docs/                  # Detailed documentation
│   ├── architecture.md    # Trust model, delegation chain, validation
│   ├── security.md        # Security boundaries, hardening guide
│   ├── configuration.md   # Full policy reference
│   ├── deployment.md      # Deployment scenarios
│   ├── api-reference.md   # Complete API documentation
│   ├── mcp-integration.md # MCP client setup guides
│   └── THREAT_MODEL.md    # 12 enumerated threats with mitigations
├── .github/
│   └── workflows/         # CI: build, test, lint (GitHub Actions)
├── EPHYR.md              # Agent-facing reference document
├── CONTRIBUTING.md        # Contributor guidelines
├── Makefile               # build, test, lint, install targets
├── go.mod                 # 3 direct dependencies
└── go.sum
```

## Testing

253 tests across 13 test files:

- **Unit tests** -- Policy engine, RBAC resolution, delegation, revocation, grants, rate limiting, metrics, token signing/validation, activity store
- **Integration tests** -- 8 end-to-end tests (`test/integration/smoke_test.go`) that run against a live Ephyr instance: MCP handshake, tool listing, legacy compatibility, task lifecycle, task validation, metrics endpoint, and performance benchmarks

```bash
make test                    # Unit tests
make lint                    # golangci-lint
go test ./test/integration/  # Integration tests (requires running instance)
```

## Requirements

- **Go 1.24+** -- uses enhanced routing patterns and recent stdlib features
- **Linux** -- `SO_PEERCRED` for Unix socket peer authentication is Linux-specific
- **systemd** -- optional but recommended for production
- **OpenSSH** -- target hosts need `TrustedUserCAKeys` configured
- **nftables** -- recommended for network isolation

## Dependencies

Three direct dependencies, all well-established:

| Module | Purpose |
|--------|---------|
| `github.com/gorilla/websocket` | WebSocket for dashboard events and terminal proxy |
| `golang.org/x/crypto` | SSH certificate operations, bcrypt for API key hashing |
| `gopkg.in/yaml.v3` | Policy YAML parsing |

No external databases. No message queues. No container runtime.

## Roadmap

- **Sub-agent tracking** -- Accept optional context/session ID from MCP clients to distinguish parallel sub-agents. Track and display as a tree.
- **OIDC / JWT agent auth** -- Alternative to API key auth for stronger authentication.
- **mTLS for MCP** -- Mutual TLS as an alternative to API key authentication.
- **Certificate pinning to source IP** -- Bind certs to the requesting agent's IP.
- **Target health checks** -- Periodic SSH connectivity probes with dashboard status.
- **Audit log export** -- Ship to external SIEM (syslog, webhook, S3).
- **Broker-level command policy** -- Command filtering at the broker before cert signing. Allowlist and denylist modes.
- **ntfy alerting** -- Push alerts on denied requests or anomalous activity.

## Contributing

Contributions welcome. The codebase is ~23,000 lines of Go across ~60 files with no code generation and no frameworks -- just the standard library plus three dependencies.

```bash
make test    # Run tests
make lint    # Run linter
```

Please open an issue before starting work on large changes.

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Trust model, delegation chain, validation flow |
| [Security](docs/security.md) | Security boundaries, hardening guide |
| [Configuration](docs/configuration.md) | Full policy reference and RBAC setup |
| [Deployment](docs/deployment.md) | Local, dedicated host, and production scenarios |
| [API Reference](docs/api-reference.md) | Complete REST and MCP API documentation |
| [MCP Integration](docs/mcp-integration.md) | Client setup for Claude Code, Desktop, Cursor, Cline |
| [Threat Model](docs/THREAT_MODEL.md) | 12 enumerated threats with mitigations |

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <code>~23,000 lines of Go | 64 source files | 253 tests | 3 dependencies | Zero external databases</code>
</p>
