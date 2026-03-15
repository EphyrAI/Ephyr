# Target Host Setup

This guide explains how to configure a Linux host to accept Ephyr-brokered SSH connections.

## How roles work

Roles are arbitrary names you define in your broker's `policy.yaml`. Each role maps to a **Linux user account** on the target host via the `principal` field. When Ephyr issues an SSH certificate for a role, the certificate's principal matches the Linux user, and sshd grants access.

```
policy.yaml (broker)              target host
─────────────────────              ───────────
roles:                             Linux users:
  read:                              agent-read  (rbash, no sudo)
    principal: "agent-read"   →
  operator:                          agent-op    (bash, limited sudo)
    principal: "agent-op"     →
  admin:                             agent-admin (bash, broader sudo)
    principal: "agent-admin"  →
```

**You can name roles anything.** `read`/`operator`/`admin` are conventions, not requirements. The only constraint is that the `principal` value must match a Linux user on the target.

## What the target host needs

1. **Linux user accounts** for each role (with appropriate shells)
2. **The broker's CA public key** in `/etc/ssh/` so sshd trusts Ephyr certificates
3. **sshd configured** with `TrustedUserCAKeys` and `AuthorizedPrincipalsFile`
4. **Principal files** mapping certificate principals to user accounts
5. **Sudoers rules** (optional) controlling what each role can do with `sudo`

## Quick setup (one command)

From the broker host, copy the CA public key to the target and run the provisioning script:

```bash
# Copy the script and CA key to the target
scp /etc/ephyr/ca_key.pub deploy/scripts/provision-target.sh root@TARGET_HOST:/tmp/

# Run it on the target
ssh root@TARGET_HOST "bash /tmp/provision-target.sh /tmp/ca_key.pub"
```

This creates three default role accounts (`agent-read`, `agent-op`, `agent-admin`), configures sshd, and installs sudoers rules. The script is idempotent.

Or from the target host directly:

```bash
# If you have the CA public key content
sudo ./deploy/scripts/provision-target.sh /path/to/ca_key.pub
```

## Manual setup

If you prefer to set up roles manually or need custom configurations:

### 1. Create role accounts

```bash
# Read-only role: restricted shell
useradd -m -s /bin/rbash -c "Ephyr read role" agent-read

# Operator role: full shell, limited sudo
useradd -m -s /bin/bash -c "Ephyr operator role" agent-op

# Admin role: full shell, broader sudo
useradd -m -s /bin/bash -c "Ephyr admin role" agent-admin
```

**Shell choice matters:**
- `/bin/rbash` (restricted bash) prevents `cd`, setting `PATH`, running commands with `/`, and redirecting output. Good for read-only inspection.
- `/bin/bash` gives full shell access. Control what the user can do via sudoers.

### 2. Install the CA public key

```bash
# Copy from the broker (or paste the key content)
echo "ssh-ed25519 AAAA... ephyr-ca" > /etc/ssh/ephyr_ca.pub
chmod 644 /etc/ssh/ephyr_ca.pub
```

### 3. Configure sshd

Add to `/etc/ssh/sshd_config`:

```
# Ephyr SSH Certificate Authentication
TrustedUserCAKeys /etc/ssh/ephyr_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

`TrustedUserCAKeys` tells sshd to trust certificates signed by this CA.
`AuthorizedPrincipalsFile` maps certificate principals to local users.

### 4. Create principal files

```bash
mkdir -p /etc/ssh/auth_principals

# Each file contains the principal name(s) the user accepts
echo "agent-read" > /etc/ssh/auth_principals/agent-read
echo "agent-op" > /etc/ssh/auth_principals/agent-op
echo "agent-admin" > /etc/ssh/auth_principals/agent-admin

chmod 644 /etc/ssh/auth_principals/*
```

### 5. Reload sshd

```bash
# Validate config first
sshd -t && systemctl reload sshd
```

### 6. Configure sudoers (optional)

```bash
cat > /etc/sudoers.d/ephyr << 'EOF'
# agent-read: no sudo at all (omitted = denied)

# agent-op: monitoring and service management
agent-op ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, \
    /usr/bin/systemctl restart *, /usr/bin/journalctl *, \
    /usr/bin/docker ps *, /usr/bin/docker logs *

# agent-admin: broader operational access
agent-admin ALL=(ALL) NOPASSWD: /usr/bin/systemctl *, \
    /usr/bin/docker *, /usr/bin/journalctl *
EOF

chmod 440 /etc/sudoers.d/ephyr
visudo -c -f /etc/sudoers.d/ephyr  # validate
```

**Tailor sudoers to your environment.** The defaults above are examples. Add or remove commands based on what you want each role to do.

## Using Ansible

For multiple targets, the Ansible playbook automates everything:

```bash
cd deploy/ansible

# Edit inventory with your targets
cp inventory.example.yml inventory.yml
# Add your hosts under ephyr_targets

# Provision all targets
ansible-playbook -i inventory.yml site.yml --limit ephyr_targets
```

See [deploy/ansible/README.md](../deploy/ansible/README.md) for details.

## Command restriction via force_command

For maximum lockdown, you can restrict a target to a single command at the certificate level. Set `force_command` in `policy.yaml`:

```yaml
targets:
  monitoring-host:
    host: "10.0.1.30"
    port: 22
    allowed_roles: [read]
    force_command: "/usr/local/bin/health-check.sh"
    auto_approve: true
```

When `force_command` is set, the SSH certificate includes it as a critical option. The target's sshd enforces it — the agent can only run that exact command, regardless of what it requests. This is enforced by OpenSSH at the protocol level, not by shell or sudoers.

This is useful for single-purpose targets (monitoring probes, backup triggers, deploy hooks) where you want to eliminate all ambiguity about what the agent can do.

## Custom roles

You can define any roles you need. Examples:

```yaml
# policy.yaml
roles:
  readonly:
    principal: "app-viewer"
  deploy:
    principal: "app-deploy"
  dba:
    principal: "db-admin"
  backup:
    principal: "backup-agent"
```

Then on each target, create the corresponding Linux users:

```bash
useradd -m -s /bin/rbash app-viewer    # read-only
useradd -m -s /bin/bash app-deploy     # deployment
useradd -m -s /bin/bash db-admin       # database admin
useradd -m -s /bin/bash backup-agent   # backup operations
```

And create principal files:

```bash
echo "app-viewer" > /etc/ssh/auth_principals/app-viewer
echo "app-deploy" > /etc/ssh/auth_principals/app-deploy
# etc.
```

## Verifying the setup

After provisioning, test from the broker:

```bash
# This should work if Ephyr is running and the target is configured
ephyr exec your-target --role read -- whoami
# Expected output: agent-read

ephyr exec your-target --role operator -- sudo systemctl status sshd
# Expected: sshd status output (via sudo, no password)
```

## Request filtering

Request filtering is an optional defense-in-depth layer that checks inputs against deny/allow patterns before they reach the backend. It covers all three proxy paths: SSH commands, HTTP proxy requests, and MCP federation tool calls. Filtering is **disabled by default** on all paths -- there is zero overhead unless you explicitly enable it.

Prometheus metrics for all filtering paths: `ephyr_commands_filtered_total`, `ephyr_commands_denied_total`, `ephyr_auto_revocations_total`.

### SSH command filtering

Enable with `command_filter: true` on a target in `policy.yaml`.

#### Deny-list mode

Block commands matching specific patterns. All other commands are allowed.

```yaml
targets:
  production-db:
    host: "10.0.1.20"
    allowed_roles: [operator]
    command_filter: true
    command_deny:
      - "rm "
      - "rm -"
      - "rmdir"
      - "dd if="
      - "mkfs"
      - "drop database"
      - "drop table"
      - "truncate "
      - "> /dev/"
    auto_revoke_on_deny: true
```

When `auto_revoke_on_deny: true` is set, the target is automatically disabled for all agents when a prohibited command is attempted. An admin must re-enable the target from the dashboard or API before any agent can connect again.

#### Allow-list mode

Only permit commands matching specific patterns. Everything else is denied. When both `command_deny` and `command_allow` are set, the allow-list takes precedence (it is more restrictive).

```yaml
targets:
  monitoring-host:
    host: "10.0.1.30"
    allowed_roles: [read]
    command_filter: true
    command_allow:
      - "systemctl status*"
      - "journalctl*"
      - "df *"
      - "free *"
      - "uptime"
      - "cat /proc/loadavg"
```

#### How it works

- Filtering runs **before** the SSH connection is established -- no certificate is issued for blocked commands
- Denied commands are logged in the audit trail with the matched pattern, mode, and reason
- The agent receives an informative error message explaining why the command was blocked

### HTTP proxy filtering

Enable with `request_filter: true` on a service in `services.json`. Checks the URL path against `request_deny` / `request_allow` patterns, and optionally checks the request body against `body_deny` patterns.

```json
{
  "name": "gitea",
  "url_prefix": "http://10.0.1.54:3000",
  "auth_type": "bearer",
  "credential": "your-token",
  "request_filter": true,
  "request_deny": ["/api/v1/admin/*", "*/delete"],
  "body_deny": ["drop database", "drop table"],
  "auto_revoke_on_deny": false
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `request_filter` | bool | false | Enable URL/body filtering for this service |
| `request_deny` | list of strings | [] | Deny URL path patterns (block if matched) |
| `request_allow` | list of strings | [] | Allow URL path patterns (only permit if matched; takes precedence over deny) |
| `body_deny` | list of strings | [] | Deny patterns matched against the request body |
| `auto_revoke_on_deny` | bool | false | Disable the service for all agents when a request is denied |

**How it works:**

- The URL path is extracted from the request URL and checked against `request_deny` / `request_allow`
- If the request has a body and `body_deny` patterns are configured, the body is checked separately
- Denied requests are logged in the audit trail (event types: `request_denied`, `request_body_denied`)
- When `auto_revoke_on_deny` is true, the service is disabled (set `enabled: false`)

### MCP federation filtering

Enable with `arg_filter: true` on a remote in `remotes.json`. The tool call arguments are serialized to JSON and checked against `arg_deny` patterns before the call is forwarded to the remote server.

```json
{
  "name": "deploy-tools",
  "url": "http://10.0.1.74:8560/mcp",
  "enabled": true,
  "arg_filter": true,
  "arg_deny": ["rm ", "format", "destroy"],
  "auto_revoke_on_deny": true
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `arg_filter` | bool | false | Enable argument filtering for this remote |
| `arg_deny` | list of strings | [] | Deny patterns matched against the serialized JSON arguments |
| `auto_revoke_on_deny` | bool | false | Disable the remote for all agents when arguments are denied |

**How it works:**

- The tool arguments (`map[string]interface{}`) are serialized to a JSON string
- The JSON string is checked against `arg_deny` patterns using the same matching logic as command filtering
- Denied calls are logged in the audit trail (event type: `federation_arg_denied`)
- When `auto_revoke_on_deny` is true, the remote is disabled (`enabled: false`)

### Pattern syntax

All filtering paths use the same pattern matching. Patterns support simple glob-style matching:

| Pattern | Matches |
|---------|---------|
| `rm ` | Any input containing "rm " (substring) |
| `systemctl status*` | Input starting with "systemctl status" |
| `*.conf` | Input ending with ".conf" |
| `*passwd*` | Input containing "passwd" |

Matching is case-insensitive (`RM -RF` matches `rm -rf`).

### Important: this is defense-in-depth

Request filtering is **not** a security boundary. Shell commands can be obfuscated (e.g., `r''m`, `$(echo rm)`, base64 encoding), URL paths can be encoded, and JSON arguments can be structured to avoid pattern matches. The real enforcement is at the backend:

- **rbash** (restricted shell) for read-only SSH roles
- **sudoers allow-lists** for what each role can run with elevated privileges
- **force_command** at the SSH certificate level for single-purpose targets
- **allowed_paths** and **allowed_methods** on HTTP proxy services
- **RBAC tool restrictions** on federated remotes

Request filtering catches the obvious cases and provides an audit trail. It does not replace proper backend controls.

## Security notes

- **Ephyr controls access (who, when, how long).** The target host controls capability (what they can do once connected).
- **Certificate TTL is your blast radius.** Default 5 minutes. A compromised certificate is useless after expiry.
- **rbash is defense-in-depth**, not a security boundary. A determined attacker can escape restricted shells. The real protection is short TTLs and audit trails.
- **Sudoers deny lists are fragile.** New binaries or symlinks can bypass command restrictions. Consider using allow-lists for high-security targets.
- **Lock sudoers with `chattr +i`** to prevent modification by compromised agent accounts. The provisioning script does this automatically.
