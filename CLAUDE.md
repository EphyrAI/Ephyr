# Clauth -- Developer Reference

> **For agent-facing docs, see [`CLAUTH.md`](CLAUTH.md).** That file is framework-agnostic and designed to be referenced by any AI agent system (Claude Code, Cline, Cursor, etc.). This file (`CLAUDE.md`) contains development internals for contributors working on the Clauth codebase.

## Architecture Overview

Three isolated processes:
- **clauth-signer** -- holds Ed25519 CA key, signs certs via Unix socket IPC only
- **clauth-broker** -- policy engine, MCP server, HTTP proxy, grant store, federation engine, dashboard, audit
- **clauth** (CLI) -- agent-side tool for SSH operations from the broker host

### Network Isolation (nftables)

The agent user (UID 1000) is blocked by nftables from reaching any backend host directly. All output traffic from UID 1000 to infrastructure IPs is dropped at the kernel level. The agent can only reach:
- `localhost` (broker Unix socket and MCP endpoint)
- The broker then proxies to backends after enforcing policy

This means even if agent code tries to SSH or curl a backend directly, the connection is refused by the firewall. All access must go through the broker.

### Three Proxy Paths

1. **SSH Exec** -- `exec` tool -> broker generates ephemeral keypair -> signer issues cert -> SSH to target -> return stdout/stderr/exit_code
2. **HTTP Proxy** -- `http_request` tool -> broker matches URL to service config -> injects credentials -> forwards request -> returns response
3. **MCP Federation** -- `{server}.{tool}` call -> broker proxies JSON-RPC to remote MCP server -> injects credentials -> returns result

### Grant System

Beyond SSH certificates (tracked in CertState), the broker issues TTL-based access grants for services and MCP servers. See `internal/broker/grants.go` for the implementation.

- **GrantStore** -- in-memory store with background cleanup (30s interval)
- **Three grant types:** `ssh_cert`, `service`, `mcp`
- **Two modes:** `ttl` (default, grants issued and validated) and `passthrough` (skips grant issuance)
- **Per-service/remote override** -- each service or remote can set `grant_mode` in its config
- **Deduplication** -- existing valid grant for same agent+type+target is returned instead of creating a new one
- Grants auto-expire (default 5 min), cleaned up 10 min after expiry

The proxy path (`proxy.go` line ~208) checks/issues grants before proxying HTTP requests. Federation checks are in `federation.go`.

## Connecting

MCP endpoint: configured in your MCP client settings (type: url, with Authorization Bearer header).

## Discovering Available Infrastructure

Do NOT assume what hosts, services, or MCP servers are available. Always query the broker to discover them dynamically.

### SSH Targets

Call the `list_targets` tool to discover available SSH hosts:

```
Tool: list_targets
Arguments: {}
```

Returns for each target: `name`, `host`, `port`, `vlan`, `roles[]`, `description`, `enabled`.

Use the `name` value as the `target` parameter in `exec` and `session_create` calls. The `roles` array shows what access levels you have (e.g., "read", "operator", "admin").

### HTTP Proxy Services

Call the `list_services` tool to discover web services you can access through the authenticated proxy:

```
Tool: list_services
Arguments: {}
```

Returns for each service: `name`, `url_prefix`, `description`, `auth_type`, optionally `allowed_methods`.

Credentials are injected automatically by the broker -- you never see tokens or passwords. Use the `http_request` tool with the service URL to make requests.

### Federated MCP Servers

Call the `list_remotes` tool to discover remote MCP servers federated through Clauth:

```
Tool: list_remotes
Arguments: {}
```

Returns for each remote: `name`, `url`, `description`, `enabled`, `status`, `protocol_version`, `server_name`, `server_version`, `tool_count`, `resource_count`, `auth_type`.

Federated tools are namespaced as `{server_name}.{tool_name}`. For example, if a remote named "demo-tools" has a tool called "roll_dice", call it as `demo-tools.roll_dice`. Federated resources use `remote:{server}://{path}` URIs.

### MCP Resources (Deep Discovery)

For richer information, read these MCP resources:

| Resource URI | What it provides |
|---|---|
| `clauth://overview` | System summary: targets, services, agent permissions |
| `clauth://targets` | SSH targets with hosts, ports, roles, TTLs, auto-approve |
| `clauth://services` | Proxy services with auth types and URL prefixes |
| `clauth://roles` | Role definitions and SSH principal mappings |
| `clauth://status` | Your active certificates, sessions, recent activity |
| `clauth://tools` | Tool reference with parameters and usage examples |
| `clauth://remotes` | Federated MCP servers with tools and status |

Reading `clauth://overview` on first connection gives you a complete picture of what is available.

## Running Commands on Targets

**One-shot** (new SSH cert per command, ~850ms):
```
Tool: exec
Arguments: { "target": "<name>", "role": "<role>", "command": "<shell command>" }
```

**Persistent session** (reuses connection, ~14ms per command):
```
Tool: session_create
Arguments: { "target": "<name>", "role": "<role>" }
# Returns session_id

Tool: exec
Arguments: { "target": "<name>", "role": "<role>", "command": "<cmd>", "session_id": "<id>" }

Tool: session_close
Arguments: { "session_id": "<id>" }
```

Use sessions when running multiple commands on the same target. Always close sessions when done.

## Making HTTP Requests Through the Proxy

```
Tool: http_request
Arguments: { "url": "<full URL matching a service url_prefix>", "method": "GET" }
```

The broker matches the URL to a configured service and injects credentials. You do not need to provide authentication. Optional arguments: `method`, `headers` (object), `body` (string).

## Key Behaviors

- Certificates are ephemeral (5-minute default TTL) -- access disappears when the task is done
- Service and MCP grants also have TTLs (default 5 min), unless passthrough mode is set
- All actions are audited (exec commands, proxy requests, cert operations)
- Hosts, services, and MCP servers can be toggled on/off by admins -- if something returns an error about being disabled, it has been intentionally turned off
- Role escalation is not possible -- you can only use roles listed in `list_targets` for each target
- Network policy restricts proxy destinations -- not all URLs are reachable

### RBAC -- Per-Agent Permissions (Implemented)

RBAC is defined in `policy.yaml` using templates and per-agent blocks. The YAML schema supports three permission domains plus dashboard access levels.

#### How permissions are defined in policy.yaml

```yaml
templates:
  <name>:
    description: "..."
    ssh:
      "<target-or-*>":
        roles: [read, operator]
        auto_approve: true
    services:
      "<service-or-*>":
        methods: [GET, POST]
    remotes:
      "<remote-or-*>": {}
    dashboard: "viewer"    # none | viewer | operator | admin

agents:
  <name>:
    uid: 1000
    inherits: [<template>, ...]    # inherit + override
    ssh:
      <target>:
        roles: [read, operator, admin]
        auto_approve: true
    services:
      <service>:
        methods: [GET]
    remotes:
      <remote>: {}
    dashboard: "admin"
```

**Key rules:**
- `"*"` is a wildcard key (all targets/services/remotes)
- Agent-level keys override inherited template keys for the same target/service/remote
- Multiple templates merge left-to-right; later templates override earlier ones
- SSH roles are **intersected** with the target's `allowed_roles` (agent cannot escalate beyond what the target allows)
- Services use an **allow-list** model: agent can only use listed services (or `"*"`)
- Remotes use an **allow-list** model: agent can only call listed remotes (or `"*"`)
- Agents without RBAC fields (`ssh`, `services`, `remotes`, `dashboard`) get **legacy mode** (full access, same as pre-RBAC behavior)

#### Where enforcement happens in code

| File | What it enforces |
|------|-----------------|
| `internal/broker/mcp_tools.go` | SSH role validation in `toolExec` and `toolSessionCreate`; filters `toolListTargets` to only show targets with permitted roles; filters `toolListServices` to allowed services; filters `toolListRemotes` to allowed remotes |
| `internal/broker/proxy.go` | HTTP method restrictions per-service for the calling agent |
| `internal/broker/mcp.go` | Federation tool call routing checks agent's remote permissions before proxying |
| `internal/broker/dashboard.go` | Dashboard access level enforcement |

The `MCPAgent` struct in `mcp.go` carries the agent's resolved `Roles` list. For SSH, `toolListTargets` computes the intersection of agent roles and each target's `allowed_roles`, hiding targets where the intersection is empty.

#### How to add a new agent with restricted permissions

1. Create a Linux user on the broker host (for Unix socket auth via SO_PEERCRED):
   ```bash
   useradd -r -s /bin/bash -M newagent
   ```

2. Add to `policy.yaml`:
   ```yaml
   agents:
     newagent:
       uid: 1003
       max_concurrent_certs: 3
       inherits: [monitoring]     # or any template
       services:
         grafana:
           methods: [GET]
       dashboard: "viewer"
   ```

3. Reload: `systemctl reload clauth-broker`

#### How to add a new template

Add under the `templates:` key in `policy.yaml`:

```yaml
templates:
  deploy-only:
    description: "Can deploy but not read"
    ssh:
      docker-host:
        roles: [operator]
        auto_approve: true
    services:
      gitea:
        methods: [GET, POST]
    remotes: {}
    dashboard: "none"
```

Templates are purely a YAML convenience -- the broker resolves them into flat per-agent permission sets at policy load time.

#### Permission resolution

Resolution happens in the policy loader (`internal/policy/loader.go`) during `load()`:

1. Parse all templates into permission structures
2. For each agent, merge inherited templates left-to-right
3. Apply agent-level overrides on top (agent keys win for same target/service/remote)
4. Intersect SSH roles with each target's `allowed_roles`
5. Store resolved permissions on the agent's runtime representation

The `MCPAgent.Roles` field in `mcp.go` holds the resolved role list. Discovery tools (`list_targets`, `list_services`, `list_remotes`) filter results based on these resolved permissions so agents only see what they can access.

## Project Layout

Key files for working on the codebase:

| Path | Lines | Purpose |
|------|-------|---------|
| `internal/broker/dashboard.go` | ~970 | Dashboard API handlers, toggle endpoints |
| `internal/broker/handler.go` | ~990 | Core Unix socket API handlers |
| `internal/broker/proxy.go` | ~700 | HTTP proxy engine with credential injection |
| `internal/broker/mcp_exec.go` | ~680 | SSH exec engine (ephemeral keypair -> signer -> SSH) |
| `internal/broker/mcp_tools.go` | ~670 | MCP tool definitions and dispatch |
| `internal/broker/mcp_resources.go` | ~590 | MCP resource definitions |
| `internal/broker/mcp.go` | ~570 | MCP protocol (JSON-RPC, initialize, routing) |
| `internal/broker/federation.go` | ~530 | MCP federation engine |
| `internal/broker/server.go` | ~480 | Broker server setup, route registration |
| `internal/broker/config.go` | ~460 | Host config CRUD, persistent JSON |
| `internal/broker/terminal.go` | ~460 | WebSocket SSH terminal proxy |
| `internal/broker/activity.go` | ~420 | Activity ring buffer and queries |
| `internal/broker/federation_client.go` | ~400 | MCP client for remote server discovery |
| `internal/broker/grants.go` | ~250 | TTL-based access grant store |
| `internal/broker/state.go` | ~210 | Certificate state management |
| `internal/broker/federation_tools.go` | ~210 | Federated tool dispatch |
| `dashboard/index.html` | ~3,300 | React 18 SPA (single file, CDN deps) |
| `internal/policy/` | | Policy types, YAML loader, evaluation |
| `internal/signer/` | | CA key management, cert signing, IPC |
| `internal/audit/` | | JSON-line audit logger |
| `cmd/broker/` | | Broker entry point |
| `cmd/signer/` | | Signer entry point |
| `cmd/clauth/` | | CLI tool |

## Systemd

Always restart signer before broker. Both share `/run/clauth/` managed by tmpfiles.d:

```bash
sudo systemctl restart clauth-signer clauth-broker
sudo systemctl reload clauth-broker   # hot-reload policy.yaml
journalctl -u clauth-broker -f
```
