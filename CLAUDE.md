# Clauth -- Agent Access Broker

Clauth is an SSH certificate broker and MCP server for AI agents. It provides scoped, auditable access to infrastructure without exposing credentials.

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
- All actions are audited (exec commands, proxy requests, cert operations)
- Hosts, services, and MCP servers can be toggled on/off by admins -- if something returns an error about being disabled, it has been intentionally turned off
- Role escalation is not possible -- you can only use roles listed in `list_targets` for each target
- Network policy restricts proxy destinations -- not all URLs are reachable
