<p align="center">
  <h1 align="center">Clauth</h1>
  <p align="center"><i>pronounced "klawth"</i></p>
  <p align="center">
    <strong>A broker that gives AI agents ephemeral, auditable, policy-controlled access<br>to infrastructure -- without standing credentials.</strong>
  </p>
</p>

<p align="center">
  <a href="https://github.com/ben-spanswick/Clauth/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ben-spanswick/Clauth/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="#quick-start"><img alt="Go 1.24+" src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" /></a>
  <a href="#license"><img alt="License" src="https://img.shields.io/badge/License-Apache_2.0-blue" /></a>
  <img alt="Brokered Access" src="https://img.shields.io/badge/Brokered-Least_Privilege-8B5CF6" />
  <img alt="MCP" src="https://img.shields.io/badge/MCP-2025--03--26-10B981" />
</p>

---

## What is Clauth?

Clauth is an access broker for AI agents. It sits between agents and your infrastructure, issuing ephemeral credentials, enforcing policy, and auditing every action. Agents never hold long-lived infrastructure secrets -- credentials stay in the broker, not the agent runtime.

A single MCP connection replaces N different authentication mechanisms -- SSH keys, API tokens, service credentials -- with one unified, policy-governed interface.

Instead of scattering credentials across your infrastructure and hoping agents handle them responsibly, Clauth centralizes access control in a single broker process. The agent connects to one MCP endpoint. Clauth handles the rest.

### Hierarchy

- **Core:** Brokered, least-privilege access for AI agents
- **Access types:** SSH (ephemeral certificates), HTTP (credential-injecting proxy), federated MCP
- **Control plane:** Declarative policy, time-limited grants, structured audit
- **Admin UI:** Optional operational dashboard for policy inspection, emergency revocation, and audit search

## Intended Deployment Model

Clauth is designed for:

- **Homelabs and power users** who give AI agents (Claude Code, etc.) access to their infrastructure
- **Internal engineering teams** managing dev/staging/prod environments with AI-assisted operations
- **Single-tenant environments** where a small number of trusted operators control the broker

Clauth is **not** designed for multi-tenant SaaS, public-facing agent platforms, or environments where the broker operator is untrusted. It assumes a trusted administrator who defines policy and manages the broker.

## Why Clauth?

Static credentials for AI agents are a liability. SSH keys don't expire, API tokens can't be scoped per-task, and when an agent session ends the access remains. Clauth replaces that model:

- **One connection, all access** -- Agents connect to a single MCP endpoint. SSH targets, HTTP APIs, and remote MCP servers are all reachable through the broker. No direct backend access required.
- **Ephemeral credentials** -- SSH certificates default to 5-minute TTL. Service and MCP grants auto-expire. When the task is done, access disappears.
- **No standing backend credentials** -- The broker injects API tokens, SSH certificates, and auth headers. Agents never handle long-lived backend secrets directly.
- **Declarative policy** -- YAML defines who can access what, with what role, for how long. Hot-reload with SIGHUP.
- **Full audit trail** -- Every certificate, every command, every HTTP proxy request, every denied action. Structured JSON, ready for your SIEM.
- **Network isolation** -- Optional nftables rules block the agent user from reaching backends directly. All traffic flows through the broker, which enforces policy before proxying.

## Architecture

Clauth runs as three isolated processes with strict privilege separation. The broker is the sole point of contact for agents, proxying three distinct backend types:

```
                                    +------------------------------+
                                    |         Dashboard            |
                                    |  (optional admin UI)         |
                                    +-------------+----------------+
                                                  | :8553
                                                  |
+------------------+  Unix socket  +--------------+----------------+  Unix socket  +------------------+
|                  |  /run/clauth/ |                               |  /run/clauth/ |                  |
|   Agent (CLI)    |  broker.sock  |         clauth-broker         |  signer.sock  |  clauth-signer   |
|                  +-------------->|                               +-------------->|                  |
+------------------+               |  Policy engine - Sessions     |               |  CA key holder   |
                                   |  MCP server - Grant store     |               |  Signs certs     |
+------------------+  HTTP :8554   |  Activity store - Audit       |               |  Never on network|
|   Agent (MCP)    |  Bearer auth  |                               |               +------------------+
|  Claude, etc.    +-------------->|                               |
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

### Core

**SSH Broker** -- The agent calls `exec` with a target and command. The broker generates an ephemeral Ed25519 keypair, has the signer issue a certificate via Unix socket IPC, SSHs to the target, runs the command, and returns stdout/stderr/exit_code. The agent never touches SSH keys or certificates. Persistent sessions reduce per-command latency from ~850ms to ~14ms.

**Policy Engine** -- Declarative YAML configuration with hot-reload. An 8-step evaluation pipeline checks every certificate request: agent exists, target exists, role allowed, duration clamped, concurrent limits, duplicate handling, global limits, approval mode. Every denial includes a specific reason.

**Grant Store** -- Time-limited access grants track agent permissions across all proxy paths. Three types: `ssh_cert` (5 min default), `service` (5 min), and `mcp` (5 min). Grants auto-expire and are cleaned up by a background goroutine.

**Audit** -- Append-only structured JSON-line logging. Every certificate operation, command execution, HTTP proxy request, and policy decision is recorded. Logrotate integration with 30-day retention out of the box.

**Network Isolation** -- When deployed on the same host as the agent, nftables rules block the agent user (by UID) from reaching backend hosts directly. The only path to backends is through the broker's Unix socket or MCP endpoint. This isolation applies specifically when the agent process runs on the broker host -- remote MCP agents connecting over the network are constrained by the broker's policy enforcement rather than kernel-level traffic filtering.

### Extensions

**HTTP Proxy** -- A credential-injecting proxy for web services. Configure a service once with its URL prefix and credentials, and agents make requests without ever seeing the token. Supports bearer, basic auth, custom header, and query parameter injection. Network policy controls reachable destinations.

**MCP Federation** -- Aggregate tools from remote MCP servers through a single unified endpoint. Remote tools appear namespaced (e.g., `devtools.list_repos`). The broker discovers tools automatically via MCP handshake and keeps catalogs fresh with background refresh.

**Dashboard** -- A single-page admin UI for operational control: policy inspection, host/service/remote management with enable/disable toggles, emergency certificate revocation, session monitoring, activity feed, and audit log search. WebSocket streaming pushes state changes to connected clients in real time.

### Process Isolation

**clauth-signer** holds the Ed25519 CA private key and does nothing else. It listens on a Unix socket, signs certificate requests, and runs in a systemd sandbox with `ProtectSystem=strict`, `MemoryDenyWriteExecute`, and zero capabilities. The CA key never leaves this process. Broker compromise does not expose the CA key.

**clauth-broker** is the brain. It loads policy from YAML, evaluates certificate requests, manages sessions/grants/certificate lifecycle, serves the MCP endpoint and optional dashboard, proxies HTTP requests with credential injection, federates remote MCP servers, and writes structured audit logs.

**clauth** (CLI) is the agent-side tool for direct SSH operations from the broker host.

## Security Boundaries

Clauth provides brokered, ephemeral, policy-governed infrastructure access. Understanding what it enforces -- and what it relies on other layers to enforce -- is important for secure deployment.

### What Clauth enforces

- **Access issuance policy** -- Which agents can reach which targets, with which roles, for how long. Every request is evaluated against declarative policy before credentials are issued.
- **Request-level audit** -- Every action (cert issued, command executed, HTTP request proxied, access denied) is logged with agent identity, target, timestamp, and outcome.
- **Credential isolation** -- Backend credentials (API tokens, SSH CA key) live in the broker/signer processes. Agents interact through MCP tools and never receive long-lived secrets.
- **Grant expiry** -- All access is time-limited. SSH certificates, service grants, and MCP grants auto-expire.

### What target hosts enforce

- **Command-level permissions** -- Clauth issues certificates with SSH principals (e.g., `agent-read`, `agent-op`). The target host maps these principals to Linux users with appropriate shell restrictions (rbash for read-only, bash for operators), sudoers rules, and filesystem permissions.
- **OS-level isolation** -- The target host's own security controls (SELinux/AppArmor, filesystem permissions, network policy) are the final enforcement layer. Clauth gets the agent to the host with the right principal; the host decides what that principal can do.

### What to understand about the threat model

- **Broker compromise does not expose the CA key.** The signer runs as a separate process with its own systemd sandbox. An attacker who compromises the broker can request certificates (subject to policy) but cannot extract the CA private key.
- **Host compromise can abuse active grants within TTL.** If a target host is compromised, an attacker could abuse any currently-valid SSH certificate until it expires (default 5 minutes). Short TTLs limit the blast radius.
- **Network isolation reduces bypass risk but does not replace host hardening.** nftables rules prevent the agent user from reaching backends directly, but this is defense-in-depth, not a substitute for properly configured target hosts.
- **Strong deployments should use:** dedicated principals per agent, least-privilege sudoers, forced commands where appropriate, and `no-pty`/`no-port-forwarding` defaults in `authorized_principals` or `sshd_config`.

### Why API keys for MCP instead of mTLS?

The current MCP authentication model uses API keys (bcrypt-hashed, stored in policy) for simplicity. This is appropriate for single-tenant deployments where the broker and agents share a trusted network. Stronger authentication (mTLS, OIDC/JWT) is on the roadmap for environments that need it.

## Features

### SSH Certificate Authority

Ed25519 CA issuing ephemeral, per-request certificates. Default TTL is 5 minutes, configurable up to 30 minutes per-target. Each certificate is scoped to a specific agent, target, and role. Duplicate certificates for the same agent+target+role combination are automatically revoked when a new one is issued.

Auto-approve workflows let trusted agents get certificates instantly. For sensitive targets, requests enter a pending state until an admin approves them from the dashboard or CLI.

### TTL-Based Access Grants

Clauth extends the ephemeral access model beyond SSH certificates. When an agent accesses an HTTP service or calls a federated MCP tool, the broker issues a time-limited access grant tracking the agent, resource, and expiry. Three grant types:

| Type | Default TTL | Scope |
|------|-------------|-------|
| `ssh_cert` | 5 min | Tracked in CertState (existing SSH CA system) |
| `service` | 5 min | HTTP proxy service access |
| `mcp` | 5 min | Federated MCP server access |

Grants auto-expire and are cleaned up by a background goroutine. Duplicate grants for the same agent+resource pair are deduplicated (existing valid grant is returned). Each service and remote MCP server can be configured with its own grant mode:

- **TTL mode** (default) -- grants are issued and validated on each request
- **Stateless mode** -- request-scoped policy evaluation without persisted grant state, for lightweight access patterns where tracking individual grants adds no value

Grant lifecycle events (issued, expired, revoked) are recorded in the activity store and visible on the dashboard.

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

Remote tools appear as `{server}.{tool}` (e.g., `devtools.list_repos`). When an agent calls a federated tool, the broker proxies the request transparently, injecting any configured credentials. Background refresh keeps the tool catalog up to date, with exponential backoff on failures.

Remote servers can use any auth type (bearer, basic, header, none) and are managed via the dashboard or REST API. Each remote's connection status, tool count, and last refresh time are visible in real time. Remotes can be individually enabled/disabled.

### Dashboard

Optional single-page admin UI with ten views across four groups:

- **OVERVIEW:** System summary -- stat cards, host/service/MCP panels with toggles, active sessions, live event feed
- **INFRASTRUCTURE:** Hosts, Services, MCP Servers -- enable/disable toggles, configuration panels
- **MONITOR:** Agents, Activity, Sessions, Audit Log -- searchable, filterable
- **TOOLS:** Terminal (WebSocket SSH proxy), Settings

Key operational controls:
- **Policy inspection** -- View resolved per-agent permissions, target configs, role mappings
- **Emergency revocation** -- Revoke any active certificate immediately
- **Remote disable** -- Toggle hosts, services, or federated MCP servers on/off without restart
- **Audit search** -- Filter audit logs by agent, type, target, time range

WebSocket live event streaming pushes state changes to all connected clients.

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

### Security Hardening

- **Unix socket authentication** -- `SO_PEERCRED` extracts the caller's UID from the kernel. No passwords over the wire.
- **Constant-time token comparison** -- `crypto/subtle` prevents timing attacks on dashboard and API tokens.
- **Systemd sandboxing** -- `ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, `PrivateDevices`, `CapabilityBoundingSet=` (empty). Full system call filtering.
- **CA key isolation** -- the private key exists only in the signer process. The broker never reads it.
- **Network isolation** -- nftables drops direct agent-to-backend traffic. All access is brokered.
- **Socket permissions** -- broker socket is `0660` with group restriction.
- **Token masking** -- dashboard tokens are logged as `first4...last4`, never in full.
- **Session binding** -- certificate request tokens are bound to the originating UID. Stolen tokens cannot be replayed from a different process.

## What Survives a Broker Restart

| Persists across restarts | Lost on restart |
|--------------------------|-----------------|
| Policy config (`policy.yaml`) | Active SSH sessions |
| Host/service/remote configs (JSON) | In-memory certificate state |
| Audit logs (append-only JSON) | WebSocket connections |
| CA key (in signer process) | Activity ring buffer |

The signer process is independent -- a broker restart does not affect it. Active SSH certificates remain valid on target hosts until their TTL expires, even if the broker restarts, since certificate validation is performed by the target's `sshd` against the CA public key.

## RBAC -- Per-Agent Permissions

Clauth implements fine-grained, per-agent access control across all three proxy paths (SSH, HTTP, MCP federation) and the dashboard. Permissions are defined declaratively in `policy.yaml` using a template inheritance model.

### Capabilities

- **Per-agent SSH target access** -- Which targets the agent can reach and with which roles (intersection with the target's `allowed_roles`)
- **Per-agent HTTP service access** -- Which services the agent can use and which HTTP methods are permitted
- **Per-agent MCP federation access** -- Which remote MCP servers the agent can call, with optional per-tool restrictions
- **Template inheritance** -- Reusable permission sets that agents inherit via the `inherits` field, with agent-level overrides
- **Wildcard support** -- `"*"` matches all targets, services, or remotes for broad permission grants
- **Dashboard permission levels** -- `none`, `viewer`, `operator`, or `admin`

### Backwards Compatibility

Agents that do not define any RBAC fields (`ssh`, `services`, `remotes`, `dashboard`) operate in **legacy mode** with full access -- the same behavior as before RBAC was added. Existing deployments continue to work without any policy changes.

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
      prod-server:                # override: admin on prod-server
        roles: [read, operator, admin]
        auto_approve: true
      staging-server:
        roles: [read, operator]
        auto_approve: true
    services:
      github:
        methods: [GET, POST, PUT, PATCH, DELETE]
      grafana:
        methods: [GET]            # restrict to read-only
    remotes:
      devtools: {}                # allow this remote, all tools
    dashboard: "admin"            # override template's "operator"

  monitoring-bot:
    uid: 1001
    inherits: [monitoring]        # read-only everywhere
    # No overrides needed -- template is sufficient
```

### Permission Resolution Rules

When an agent inherits from a template and also defines its own permissions:

1. **SSH roles** -- Per-target, the agent's effective roles are the **intersection** of the roles listed in the agent's `ssh` block (or inherited) and the `allowed_roles` on the target itself. If neither the agent nor its templates define SSH permissions for a target, the agent cannot access it (unless in legacy mode).

2. **Services** -- Agents can only access services explicitly listed in their `services` block or inherited via templates. The `methods` list restricts which HTTP methods are allowed. A wildcard `"*"` key means all services are accessible.

3. **Remotes** -- Agents can only call federated tools on remotes explicitly listed in their `remotes` block or inherited. A wildcard `"*"` key means all remotes. Per-remote tool restrictions are optional.

4. **Dashboard** -- Agent-level value overrides the inherited template value. Levels: `none`, `viewer`, `operator`, `admin`.

5. **Agent overrides win** -- When an agent defines a field that also exists in an inherited template, the agent's value takes precedence for that specific key. Unspecified keys fall through to the template.

6. **Multiple templates** -- Merged left-to-right. Later templates override earlier ones for the same keys.

### Discovery Filtering

The `list_targets`, `list_services`, and `list_remotes` MCP tools automatically filter results based on the calling agent's permissions. Agents self-discover their available infrastructure without seeing resources they cannot access.

### Enforcement Points

| Layer | What it checks |
|-------|----------------|
| SSH exec | Agent's roles for the target, intersection with target's `allowed_roles` |
| HTTP proxy | Agent's allowed services and permitted HTTP methods |
| MCP federation | Agent's allowed remotes and optional tool restrictions |
| Discovery | Filters `list_targets`, `list_services`, `list_remotes` results |
| Dashboard | Agent's dashboard access level |

## Quick Start

### 1. Build

```bash
git clone https://github.com/your-org/clauth.git
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

### 3. Configure target hosts

For each target host, create Linux users corresponding to your role principals:

```bash
# Read-only agent user (restricted shell)
useradd -m -s /usr/bin/rbash agent-read

# Operator agent user (standard shell, limited sudo)
useradd -m -s /bin/bash agent-op
echo "agent-op ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/docker ps" > /etc/sudoers.d/agent-op

# Map principals to users in sshd_config or authorized_principals
echo "agent-read" > /etc/ssh/auth_principals/agent-read
echo "agent-op" > /etc/ssh/auth_principals/agent-op
```

Configure `sshd_config` to use principals:

```
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

### 4. Configure policy

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
    host: "10.0.1.10"
    port: 22
    allowed_roles: [read, operator]
    max_ttl: "10m"
    auto_approve: true
    description: "Production web server"
```

### 5. Start services

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

### 6. Use it

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

## Deployment

### Local (Same Machine)

The simplest deployment: broker and agent on the same Linux host.

1. Build: `make build`
2. Install: `sudo make install` (copies binaries to `/usr/local/bin/`)
3. Create user: `sudo make install-user` (creates `clauth-broker` system user)
4. Generate CA: `ssh-keygen -t ed25519 -f /etc/clauth/ca_key -N ""`
5. Copy `configs/policy.yaml` to `/etc/clauth/policy.yaml` and edit
6. Install systemd units: `sudo make install-systemd`
7. Start: `sudo systemctl enable --now clauth-signer clauth-broker`
8. Agent connects via Unix socket (`/run/clauth/broker.sock`) or MCP (`localhost:8554`)

For network isolation, add nftables rules blocking agent UID from backend IPs:
```bash
nft add rule inet filter output meta skuid 1000 ip daddr { 10.0.1.0/24 } drop
```

### Dedicated Host (VM / LXC / Bare Metal)

Recommended for production. Broker runs on its own host, agents connect over the network.

1. Provision a Debian/Ubuntu host (VM, LXC, or bare metal)
2. Build and install Clauth (same as local)
3. Configure `CLAUTH_MCP_LISTEN=:8554` and `CLAUTH_DASHBOARD_LISTEN=:8553`
4. Set `CLAUTH_DASHBOARD_TOKEN` in systemd override
5. Generate MCP API key: `openssl rand -base64 32`
6. Hash it: `htpasswd -nbBC 10 "" "YOUR_KEY" | cut -d: -f2`
7. Add hash to policy.yaml under agent's `api_key_hash` field
8. Configure firewall: allow 8554 (MCP) and 8553 (dashboard) from trusted networks only
9. Provision target hosts: run `deploy/scripts/provision-target.sh` on each target with the CA public key
10. Agents connect via MCP: `http://broker-ip:8554/mcp` with Bearer token

Network isolation: nftables on the broker host is useful only if agents also run on that host. For remote agents, the broker's policy engine is the enforcement boundary.

### Target Host Setup

For each host that agents will SSH into:

1. Run the provisioning script: `scp deploy/scripts/provision-target.sh target: && ssh target 'sudo bash provision-target.sh /path/to/ca.pub'`
2. This creates: role accounts (agent-read, agent-op, agent-admin), principals files, sudoers rules, sshd config
3. Verify: `ssh -i /tmp/test -o CertificateFile=/tmp/test-cert agent-read@target whoami`

Or do it manually:
- Copy CA public key to `/etc/ssh/clauth_ca.pub`
- Add `TrustedUserCAKeys /etc/ssh/clauth_ca.pub` and `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u` to sshd_config
- Create users: `useradd -m -s /usr/bin/rbash agent-read` etc.
- Create principal files: `echo "agent-read" > /etc/ssh/auth_principals/agent-read`
- Install sudoers from `deploy/scripts/sudoers.d/clauth`
- Restart sshd

### Environment Configuration

See the [Environment Variables](#environment-variables) table for a full list of configurable options.

Key overrides for systemd:
```bash
# Set dashboard token
sudo mkdir -p /etc/systemd/system/clauth-broker.service.d
echo -e '[Service]\nEnvironment=CLAUTH_DASHBOARD_TOKEN=your-secure-token' | sudo tee /etc/systemd/system/clauth-broker.service.d/token.conf

# Enable MCP server on network
echo -e '[Service]\nEnvironment=CLAUTH_MCP_LISTEN=:8554' | sudo tee /etc/systemd/system/clauth-broker.service.d/mcp.conf

sudo systemctl daemon-reload
sudo systemctl restart clauth-broker
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
        "Authorization": "Bearer YOUR_API_KEY"
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
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` (or Cursor settings > MCP):

```json
{
  "mcpServers": {
    "clauth": {
      "url": "http://your-broker:8554/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

### Cline

Add to Cline's MCP settings (VS Code: Cline > MCP Servers > Add):

```json
{
  "mcpServers": {
    "clauth": {
      "type": "streamableHttp",
      "url": "http://your-broker:8554/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

### Any MCP-Compatible Client

Clauth implements standard MCP 2025-03-26 over Streamable HTTP. Any client that supports the `url` transport type can connect. Point it at `http://your-broker:8554/mcp` with a Bearer token header. See [CLAUTH.md](CLAUTH.md) for the agent-facing reference document.

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
    inherits: [template1]       # RBAC template inheritance (optional)
    ssh: { ... }                # Per-target role overrides (optional)
    services: { ... }           # Per-service method restrictions (optional)
    remotes: { ... }            # Per-remote tool restrictions (optional)
    dashboard: "viewer"         # Dashboard access level (optional)
    description: "..."

roles:
  <name>:
    principal: "<ssh-principal>" # Maps to SSH authorized principal
    description: "..."

targets:
  <name>:
    host: "<ip-or-hostname>"
    port: 22
    allowed_roles: [role1, role2]
    max_ttl: "10m"              # Per-target TTL cap
    auto_approve: true          # Skip manual approval
    force_command: "..."        # SSH forced command (optional)
    description: "..."

templates:                      # Reusable RBAC permission sets
  <name>:
    description: "..."
    ssh: { ... }
    services: { ... }
    remotes: { ... }
    dashboard: "viewer"
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
| `GET` | `/v1/dashboard/permissions` | Resolved RBAC permissions for all agents |
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
├── CLAUTH.md           # Agent reference (framework-agnostic)
├── CONTRIBUTING.md     # Contributor guidelines
├── Makefile            # build, test, install, install-systemd, install-user
├── go.mod              # 3 direct dependencies
└── go.sum
```

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

## Roadmap

- **Prometheus metrics + ntfy alerts** -- Export cert counts, request rates, error rates. Push alerts on denied requests or anomalous activity.
- **Sub-agent tracking** -- Accept an optional context/session ID from MCP clients to distinguish parallel sub-agents (e.g. Claude Code's Agent tool). Track and display as a tree: parent agent -> sub-agents -> their actions.
- **OIDC / JWT agent auth** -- Alternative to API key auth for environments that need stronger authentication or multi-agent deployments.
- **mTLS for MCP** -- Mutual TLS as an alternative to API key authentication for the MCP endpoint.
- **Certificate pinning to source IP** -- Bind certs to the requesting agent's IP for defense-in-depth.
- **Target health checks** -- Periodic SSH connectivity probes with dashboard status.
- **Audit log export** -- Ship structured logs to external SIEM (syslog, webhook, S3).
- **Broker-level command policy** -- Command filtering at the broker before cert signing, adding a second enforcement layer above the host OS boundary. Two planned modes:
  - *Allowlist mode* -- Only pre-approved command patterns pass. Strictest security but most restrictive.
  - *Denylist mode* -- Block known-dangerous patterns. More flexible but requires careful pattern maintenance.
  - Long-term goal: capability-based roles that map to curated command templates rather than raw shell pattern matching.
  - Current architecture already supports this -- all agent commands flow through the broker, so it is already a chokepoint. Today RBAC controls *which role* an agent gets; command policy would control *what they can do with it*.

## Contributing

Clauth started as a project to solve a real problem: giving AI agents safe, auditable access to infrastructure without scattering SSH keys everywhere. It turns out this is a problem a lot of people have.

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
  <code>~16,000 lines of Go + HTML | 3 external dependencies | Zero external databases | Production-focused</code>
</p>
