# CLAUTH.md -- Agent Reference

This file tells AI agents how to interact with Clauth. Point your agent framework's context file here (Claude Code's `CLAUDE.md`, Cline's `RULES.md`, OpenClaw's `SOUL.md`, Cursor's `.cursorrules`, etc.).

## What is Clauth?

Clauth is an access broker for AI agents. You connect to one MCP endpoint and get access to SSH targets, HTTP APIs, and federated MCP servers -- all through the broker. You never handle credentials directly.

## Connecting

Configure your MCP client with:
- **Type:** `url`
- **URL:** `http://<broker-host>:8554/mcp`
- **Auth:** `Authorization: Bearer <your-api-key>`

Your API key and the broker URL are provided by your administrator.

## First Steps

After connecting, discover what's available:

1. **Read `clauth://overview`** -- returns a summary of all targets, services, and your permissions
2. **Call `list_targets`** -- SSH hosts you can access
3. **Call `list_services`** -- HTTP APIs available through the proxy
4. **Call `list_remotes`** -- federated MCP servers and their tools

Do NOT assume what infrastructure exists. Always discover dynamically.

## Available Tools

### SSH Execution

| Tool | Description |
|------|-------------|
| `list_targets` | List SSH targets and your allowed roles |
| `exec` | Run a command on a target host |
| `session_create` | Open a persistent SSH session (faster for multiple commands) |
| `session_close` | Close a persistent session |
| `list_sessions` | List your active sessions |
| `list_certs` | List your active SSH certificates |

**One-shot command** (~850ms):
```json
{"name": "exec", "arguments": {"target": "<name>", "role": "<role>", "command": "<shell command>"}}
```

**Persistent session** (~14ms per command after setup):
```json
{"name": "session_create", "arguments": {"target": "<name>", "role": "<role>"}}
// Returns session_id
{"name": "exec", "arguments": {"target": "<name>", "role": "<role>", "command": "<cmd>", "session_id": "<id>"}}
// When done:
{"name": "session_close", "arguments": {"session_id": "<id>"}}
```

Use sessions when running multiple commands on the same target. Always close sessions when done.

### HTTP Proxy

| Tool | Description |
|------|-------------|
| `http_request` | Make an HTTP request through the authenticated proxy |
| `list_services` | List available proxy services |

```json
{"name": "http_request", "arguments": {"url": "<full URL>", "method": "GET"}}
```

Credentials are injected automatically. You do not provide authentication. Optional: `method`, `headers` (object), `body` (string), `timeout` (seconds).

### MCP Federation

| Tool | Description |
|------|-------------|
| `list_remotes` | List federated MCP servers |

Federated tools are namespaced as `{server}.{tool}`. Example: a remote named "utils" with tool "convert" is called as `utils.convert`.

### MCP Resources

| Resource URI | Contents |
|---|---|
| `clauth://overview` | System summary with all targets, services, permissions |
| `clauth://targets` | SSH targets with roles, TTLs, auto-approve settings |
| `clauth://services` | Proxy services with auth types and URL prefixes |
| `clauth://roles` | Role definitions and SSH principal mappings |
| `clauth://status` | Your active certificates, sessions, recent activity |
| `clauth://tools` | Tool reference with parameters and usage examples |
| `clauth://remotes` | Federated MCP servers with tools and status |

## Key Behaviors

- **Ephemeral access** -- SSH certificates have short TTLs (default 5 min). Service and MCP grants auto-expire. Access disappears when the task is done.
- **Credential-free** -- The broker injects all authentication. You never see passwords, tokens, or keys.
- **Audited** -- Every command, request, and action is logged.
- **Role-scoped** -- You can only use roles listed in `list_targets` for each target. Role escalation is not possible.
- **Toggleable** -- Hosts, services, and remotes can be disabled by admins. If something returns a "disabled" error, it was intentionally turned off.
- **Network-isolated** -- Direct connections to backends are blocked. All access goes through the broker.

## RBAC

Your permissions are controlled by your administrator via policy. You may have:
- **Per-target SSH roles** -- different roles on different hosts (e.g., read-only on production, full access on staging)
- **Per-service HTTP methods** -- some services may be GET-only
- **Per-remote tool access** -- some federated servers or specific tools may be restricted

The discovery tools (`list_targets`, `list_services`, `list_remotes`) automatically filter results to only show what you can access. If something doesn't appear in the list, you don't have permission to use it.

## Error Handling

| Error | Meaning |
|-------|---------|
| `unknown target: X` | Target doesn't exist in policy |
| `role "X" is not permitted on target "Y"` | RBAC denies this role on this target |
| `access denied to service "X"` | RBAC denies access to this service |
| `access denied to remote "X" tool "Y"` | RBAC denies this federated tool |
| `target "X" is currently disabled` | Admin has toggled this host off |
| `remote X is disabled` | Admin has toggled this MCP server off |
| `service disabled` | Admin has toggled this service off |
| `proxy: url not allowed by network policy` | URL is outside allowed network ranges |
