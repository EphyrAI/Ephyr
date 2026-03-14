# Deployment Guide

Step-by-step instructions for deploying Ephyr from scratch, including
building from source, system setup, CA key generation, target provisioning,
MCP configuration, and operational verification.

---

## Prerequisites

**Broker host requirements:**
- Linux (kernel 2.6.14+ for SO_PEERCRED Unix socket peer credentials)
- Go 1.24+ (for building from source)
- systemd (recommended for service management; not strictly required)
- Ed25519 support in OpenSSH (OpenSSH 6.5+)

**Target host requirements:**
- OpenSSH server with TrustedUserCAKeys support (OpenSSH 5.4+)
- AuthorizedPrincipalsFile support (OpenSSH 6.2+)

**Network requirements:**
- Unix socket communication between signer and broker (same host)
- TCP port 8553 for dashboard (configurable)
- TCP port 8554 for MCP endpoint (configurable)
- SSH (port 22) from broker host to all target hosts

---

## Building from Source

Clone the repository and build all three binaries:

```bash
git clone https://github.com/ben-spanswick/ephyr.git
cd ephyr

# Build all binaries
go build -o bin/ephyr-broker ./cmd/broker
go build -o bin/ephyr-signer ./cmd/signer
go build -o bin/ephyr         ./cmd/ephyr

# Optional: set version at build time
go build -ldflags "-X main.version=1.0.0" -o bin/ephyr-broker ./cmd/broker
```

The project has minimal dependencies (see go.mod):
- gorilla/websocket (WebSocket support for dashboard and terminal)
- golang.org/x/crypto (SSH certificate operations, bcrypt)
- gopkg.in/yaml.v3 (policy file parsing)

Verify the build:

```bash
./bin/ephyr-broker -version
./bin/ephyr help
```

---

## System Setup

### 1. Create Service User and Group

The broker runs as a dedicated unprivileged user. An agents group controls
who can connect to the broker socket.

```bash
# Create the service user (no login shell, no home directory)
groupadd --system ephyr-broker
useradd --system --gid ephyr-broker --shell /usr/sbin/nologin \
        --no-create-home --comment "Ephyr broker service" ephyr-broker

# Create the agents group (members can connect to the broker socket)
groupadd --system ephyr-agents

# Add the agent user(s) to the agents group
# Example: add the "claude" user (UID 1000)
usermod -aG ephyr-agents claude
```

### 2. Create Directory Structure

```bash
# Configuration directory (CA key, policy file)
mkdir -p /etc/ephyr
chown root:ephyr-broker /etc/ephyr
chmod 750 /etc/ephyr

# Runtime directory (sockets) -- managed by tmpfiles.d, see below
mkdir -p /run/ephyr
chown ephyr-broker:ephyr-broker /run/ephyr
chmod 755 /run/ephyr

# Audit log directory
mkdir -p /var/log/ephyr
chown ephyr-broker:ephyr-broker /var/log/ephyr
chmod 750 /var/log/ephyr

# Persistent data directory (hosts.json, services.json)
mkdir -p /var/lib/ephyr
chown ephyr-broker:ephyr-broker /var/lib/ephyr
chmod 700 /var/lib/ephyr

# Dashboard static files
mkdir -p /opt/ephyr/dashboard
```

### 3. Install Binaries

```bash
install -m 755 bin/ephyr-broker /usr/local/bin/
install -m 755 bin/ephyr-signer /usr/local/bin/
install -m 755 bin/ephyr        /usr/local/bin/
```

---

## CA Key Generation

The CA key is an Ed25519 private key used to sign all SSH certificates.
Protect this key carefully -- compromise of the CA key means any certificate
can be forged.

```bash
# Generate the CA keypair
ssh-keygen -t ed25519 -f /etc/ephyr/ca_key -N "" -C "ephyr-ca"

# Set strict permissions
chmod 0600 /etc/ephyr/ca_key
chmod 0644 /etc/ephyr/ca_key.pub
chown ephyr-broker:ephyr-broker /etc/ephyr/ca_key
chown ephyr-broker:ephyr-broker /etc/ephyr/ca_key.pub
```

Verify the key:

```bash
ssh-keygen -l -f /etc/ephyr/ca_key.pub
# Should show: 256 SHA256:... ephyr-ca (ED25519)
```

**Backup:** Copy ca_key and ca_key.pub to a secure offline location.
If the CA key is lost, all target hosts must be reprovisioned with a new
CA public key and all existing certificates become invalid.

---

## Policy Configuration

Create a minimal policy.yaml to get started:

```yaml
# /etc/ephyr/policy.yaml -- minimal working configuration

global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"
  rate_limit:
    requests_per_window: 10
    window_seconds: 60

agents:
  myagent:
    uid: 1000        # Must match the UID of the agent process
    max_concurrent_certs: 3
    description: "Primary agent"

roles:
  read:
    principal: "agent-read"
    description: "Read-only access"
  operator:
    principal: "agent-op"
    description: "Operational commands"

targets:
  my-server:
    host: "192.168.1.10"
    port: 22
    allowed_roles: [read, operator]
    auto_approve: true
    description: "My first target"
```

Set ownership and permissions:

```bash
chown root:ephyr-broker /etc/ephyr/policy.yaml
chmod 640 /etc/ephyr/policy.yaml
```

See the Configuration Reference (docs/configuration.md) for full field
documentation.

---

## Systemd Installation

### Signer Service

Create /etc/systemd/system/ephyr-signer.service:

```ini
[Unit]
Description=Ephyr SSH Certificate Signer
Documentation=https://github.com/ben-spanswick/ephyr
After=network.target
Before=ephyr-broker.service
StartLimitBurst=3
StartLimitIntervalSec=60

[Service]
Type=simple
User=ephyr-broker
Group=ephyr-broker
ExecStart=/usr/local/bin/ephyr-signer \
    --ca-key /etc/ephyr/ca_key \
    --socket /run/ephyr/signer.sock
Restart=on-failure
RestartSec=5
Environment=EPHYR_BROKER_UID=999

# Security hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
ReadOnlyPaths=/etc/ephyr
ReadWritePaths=/run/ephyr
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

Note: Set EPHYR_BROKER_UID to the actual UID of the ephyr-broker user.
Find it with: `id -u ephyr-broker`

### Broker Service

Create /etc/systemd/system/ephyr-broker.service:

```ini
[Unit]
Description=Ephyr SSH Certificate Broker
Documentation=https://github.com/ben-spanswick/ephyr
After=network.target ephyr-signer.service
Requires=ephyr-signer.service
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=simple
User=ephyr-broker
Group=ephyr-broker
ExecStart=/usr/local/bin/ephyr-broker \
    --policy /etc/ephyr/policy.yaml \
    --signer-socket /run/ephyr/signer.sock \
    --listen /run/ephyr/broker.sock \
    --audit-log /var/log/ephyr/audit.json
Restart=on-failure
RestartSec=5
ExecReload=/bin/kill -HUP $MAINPID
Environment=EPHYR_ADMIN_UIDS=0,1000
Environment=EPHYR_AUTH_CACHE_TTL=60s

# Security hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ReadOnlyPaths=/etc/ephyr
ReadWritePaths=/run/ephyr /var/log/ephyr /var/lib/ephyr
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

### Runtime Directory (tmpfiles.d)

Both services share `/run/ephyr/` for their Unix sockets. Using systemd's
`RuntimeDirectory` on either unit would cause it to delete the directory
(and the other service's socket) on restart. Instead, use tmpfiles.d for
persistent ownership:

```bash
cat > /etc/tmpfiles.d/ephyr.conf << 'EOF'
d /run/ephyr 0755 ephyr-broker ephyr-agents -
EOF

systemd-tmpfiles --create
```

**Important:** Always restart the signer before the broker, since the broker
connects to the signer's socket on startup.

### Dashboard Token Override

To set a fixed dashboard token (rather than the auto-generated one), create
a systemd override:

```bash
mkdir -p /etc/systemd/system/ephyr-broker.service.d
cat > /etc/systemd/system/ephyr-broker.service.d/token.conf << 'EOF'
[Service]
Environment=EPHYR_DASHBOARD_TOKEN=your-secure-token-here
EOF
```

### Enable and Start

```bash
systemctl daemon-reload
systemctl enable ephyr-signer ephyr-broker
systemctl start ephyr-signer
systemctl start ephyr-broker
```

Check status:

```bash
systemctl status ephyr-signer
systemctl status ephyr-broker
journalctl -u ephyr-broker -f
```

The broker logs its dashboard token (masked) at startup. Look for:
```
[broker] dashboard token: abcd...wxyz
```

---

## Target Host Provisioning

Repeat these steps for each target host that agents should be able to access.

### Step 1: Copy CA Public Key

```bash
scp /etc/ephyr/ca_key.pub root@TARGET_HOST:/etc/ssh/ephyr_ca.pub
```

### Step 2: Configure sshd

Add to /etc/ssh/sshd_config on the target:

```
# Ephyr SSH certificate authentication
TrustedUserCAKeys /etc/ssh/ephyr_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

### Step 3: Create Role Accounts

```bash
# On the target host:

# Read-only role (restricted shell)
useradd -r -s /bin/rbash -M agent-read

# Operator role (standard shell)
useradd -r -s /bin/bash -M agent-op

# Admin role (standard shell)
useradd -r -s /bin/bash -M agent-admin
```

Only create accounts for roles that are listed in allowed_roles for this
target in the policy file.

### Step 4: Create Principal Files

```bash
mkdir -p /etc/ssh/auth_principals

echo "agent-read"  > /etc/ssh/auth_principals/agent-read
echo "agent-op"    > /etc/ssh/auth_principals/agent-op
echo "agent-admin" > /etc/ssh/auth_principals/agent-admin

chmod 644 /etc/ssh/auth_principals/*
```

### Step 5: Configure Sudoers

```bash
# Operator: limited sudo for service management
cat > /etc/sudoers.d/ephyr-agent-op << 'EOF'
agent-op ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, \
                             /usr/bin/systemctl restart *, \
                             /usr/bin/systemctl stop *, \
                             /usr/bin/docker ps, \
                             /usr/bin/docker logs *, \
                             /usr/bin/docker compose ps
EOF

# Admin: full sudo access
cat > /etc/sudoers.d/ephyr-agent-admin << 'EOF'
agent-admin ALL=(ALL) NOPASSWD: ALL
EOF

# Set permissions and lock
chmod 440 /etc/sudoers.d/ephyr-agent-*
chattr +i /etc/sudoers.d/ephyr-agent-*
```

### Step 6: Restart sshd

```bash
systemctl restart sshd
```

### Step 7: Test with ephyr CLI

On the broker host, as the agent user:

```bash
# Initialize agent keypair (first time only)
ephyr init

# Request a certificate
ephyr request -t my-server -r read

# Open an interactive SSH session
ephyr ssh -t my-server -r operator

# Execute a remote command
ephyr exec -t my-server -r operator -- systemctl status nginx
```

---

## MCP Setup

The MCP (Model Context Protocol) endpoint allows LLM agents like Claude Code
to request certificates and execute commands over a TCP JSON-RPC 2.0 API,
authenticated via API keys rather than Unix socket peer credentials.

### Step 1: Generate an API Key

Choose a strong random key:

```bash
openssl rand -hex 32
# Example output: a1b2c3d4e5f6...
```

Save this key securely -- you will need it for the MCP client configuration.

### Step 2: Hash the Key

Create a bcrypt hash for the policy file. Use one of these methods:

```bash
# Option A: Python with bcrypt
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_KEY_HERE', bcrypt.gensalt()).decode())"

# Option B: htpasswd (if available)
htpasswd -nbBC 10 "" "YOUR_KEY_HERE" | cut -d: -f2
```

The output will look like: $2a$10$... or $2b$12$...

### Step 3: Add Hash to Policy

Edit /etc/ephyr/policy.yaml and add the api_key_hash field to the
agent's entry:

```yaml
agents:
  claude:
    uid: 1000
    max_concurrent_certs: 5
    api_key_hash: "$2a$10$..."  # bcrypt hash of your MCP API key
    description: "Claude Code agent"
```

### Step 4: Configure the MCP Client

For Claude Code, add to your MCP settings (typically in
~/.claude/settings.json or the project's .mcp.json):

```json
{
  "mcpServers": {
    "ephyr": {
      "type": "url",
      "url": "http://BROKER_HOST:8554/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_PLAINTEXT_KEY_HERE"
      }
    }
  }
}
```

### Step 5: Restart the Broker

Reload the policy to pick up the new API key hash:

```bash
systemctl reload ephyr-broker
# Or, for a full restart:
systemctl restart ephyr-broker
```

### Step 6: Test with curl

```bash
# Initialize handshake
curl -s -X POST http://BROKER_HOST:8554/mcp \
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
  }' | python3 -m json.tool

# List available tools
curl -s -X POST http://BROKER_HOST:8554/mcp \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list"
  }' | python3 -m json.tool

# List targets
curl -s -X POST http://BROKER_HOST:8554/mcp \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {"name": "list_targets", "arguments": {}}
  }' | python3 -m json.tool
```

---

## HTTP Proxy Setup

The HTTP proxy allows MCP agents to make authenticated requests to internal
services without exposing raw credentials.

### Step 1: Add a Service

Via the dashboard API:

```bash
curl -s -X PUT http://BROKER_HOST:8553/v1/dashboard/services/gitea \
  -H "Authorization: Bearer YOUR_DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Gitea",
    "url_prefix": "http://GITEA_HOST:3000",
    "auth_type": "bearer",
    "credential": "your-gitea-api-token",
    "description": "Gitea API",
    "allowed_paths": ["/api/v1/*"],
    "allowed_methods": ["GET", "POST", "PUT", "DELETE"]
  }'
```

Or edit /var/lib/ephyr/services.json directly (restart not required; file
is read on each request).

### Step 2: Configure Network Policy

The default policy allows all RFC 1918 ranges and blocks external access.
To customize, create `/var/lib/ephyr/network_policy.json`:

```bash
cat > /var/lib/ephyr/network_policy.json << 'EOF'
{
  "allow_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "deny_cidrs": [],
  "external": "restricted",
  "external_allow": ["api.github.com", "*.github.com"]
}
EOF

chown ephyr-broker:ephyr-broker /var/lib/ephyr/network_policy.json
chmod 600 /var/lib/ephyr/network_policy.json
```

The broker loads this file at startup. See the Configuration Reference
(`docs/configuration.md`) for full field documentation. No restart is
required when adding or updating services in `services.json`, but changes
to `network_policy.json` require a broker restart.

### Step 3: Test via MCP

```bash
curl -s -X POST http://BROKER_HOST:8554/mcp \
  -H "Authorization: Bearer YOUR_MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "http_request",
      "arguments": {
        "url": "http://GITEA_HOST:3000/api/v1/repos/search?limit=5",
        "method": "GET"
      }
    }
  }' | python3 -m json.tool
```

The broker automatically injects the Gitea bearer token because the URL
matches the service's url_prefix.

---

## Dashboard Access

### Step 1: Note the Token

The dashboard token is either:
- Set explicitly via EPHYR_DASHBOARD_TOKEN environment variable or
  systemd override
- Auto-generated at startup and logged (masked, first 4 and last 4 chars)

To set a fixed token via systemd:

```bash
mkdir -p /etc/systemd/system/ephyr-broker.service.d
cat > /etc/systemd/system/ephyr-broker.service.d/token.conf << 'EOF'
[Service]
Environment=EPHYR_DASHBOARD_TOKEN=your-token-here
EOF
systemctl daemon-reload
systemctl restart ephyr-broker
```

### Step 2: Open the Dashboard

Navigate to http://BROKER_HOST:8553 in a browser.

Static files (the React dashboard) are served without authentication from
the directory configured by EPHYR_DASHBOARD_DIR.

### Step 3: Authenticate

All /v1/* API calls require the token as either:
- Authorization: Bearer <token> header
- ?token=<token> query parameter

The dashboard UI will prompt for the token on first load.

---

## Firewall Configuration

Recommended nftables rules for the broker host. Only SSH and the dashboard/MCP
ports need to be accessible, and only from the local network:

```nft
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # Allow established connections
        ct state established,related accept

        # Allow loopback
        iif "lo" accept

        # Allow ICMP/ICMPv6
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept

        # Allow SSH from anywhere
        tcp dport 22 accept

        # Allow dashboard from local network only
        ip saddr 192.168.0.0/16 tcp dport 8553 accept

        # Allow MCP from local network only
        ip saddr 192.168.0.0/16 tcp dport 8554 accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```

Apply:

```bash
# Save to /etc/nftables.conf
nft -f /etc/nftables.conf

# Enable on boot
systemctl enable nftables
```

For tighter security, replace 192.168.0.0/16 with specific VLAN subnets:

```nft
# Only specific VLANs (replace X and Y with your VLAN subnets)
ip saddr { 192.168.X.0/24, 192.168.Y.0/24 } tcp dport 8553 accept
ip saddr { 192.168.X.0/24, 192.168.Y.0/24 } tcp dport 8554 accept
```

---

## Logrotate Configuration

Create /etc/logrotate.d/ephyr:

```
/var/log/ephyr/audit.json {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ephyr-broker ephyr-broker
    postrotate
        systemctl reload ephyr-broker 2>/dev/null || true
    endscript
}
```

The postrotate script sends SIGHUP to the broker, which causes it to
reopen the audit log file handle via the policy reload path.

---

## Agent User Hardening

On the broker host, the agent user (e.g., "claude") should be restricted:

```bash
# Deny cron and at
echo "claude" >> /etc/cron.deny
echo "claude" >> /etc/at.deny

# No sudo access for the agent user
# (agents use certificates for target access, not local sudo)

# Set process limits in /etc/security/limits.d/ephyr-agent.conf
cat > /etc/security/limits.d/ephyr-agent.conf << 'EOF'
claude  hard  nproc   256
claude  hard  nofile  1024
EOF
```

---

## Running Integration Tests

After the broker is running, verify the full MCP stack with the integration
test suite in `test/integration/`. These tests exercise the live MCP endpoint
including protocol handshake, all tool categories, task identity lifecycle,
validation, metrics, and performance benchmarking.

### Prerequisites

- Go 1.24+ installed on the test runner machine
- Network access to the broker's MCP port (8554) and dashboard port (8553)
- A valid MCP API key for an agent configured in `policy.yaml`

### Running the Tests

From the Ephyr source directory:

```bash
cd /opt/ephyr
go test ./test/integration/ -v -count=1
```

Override connection parameters with environment variables:

```bash
EPHYR_MCP_ENDPOINT=http://192.168.100.75:8554/mcp \
EPHYR_MCP_KEY=your-api-key \
EPHYR_DASH_ENDPOINT=http://192.168.100.75:8553 \
EPHYR_DASH_TOKEN=your-dashboard-token \
go test ./test/integration/ -v -count=1
```

### What the Tests Verify

| Test | Description |
|------|-------------|
| TestMCPInitialize | MCP protocol handshake and version negotiation |
| TestToolsList | Confirms all 14 tools are registered (including 4 task identity tools) |
| TestLegacyToolsStillWork | Verifies pre-v0.2 tools (`list_targets`) are unaffected |
| TestTaskLifecycle | Full create -> info -> list -> revoke -> verify-revoked cycle |
| TestTaskValidation | Rejects invalid TTLs, empty descriptions, nonexistent task IDs |
| TestMetricsEndpoint | Prometheus metrics include task and token counters |
| TestPerformanceBench | Latency benchmarks for task_create, task_info, task_list, task_revoke |

A JSON report with per-test latencies is written to
`/tmp/ephyr-smoke-report.json` after each run.

### Expected Output

All tests should pass. A summary is printed at the end:

```
  EPHYR v0.2 PHASE 2a -- INTEGRATION TEST REPORT
  ========================================================================
  TEST                            LATENCY   STATUS  DETAIL
  ----------------------------------------------------------------------
  mcp_initialize                    5.20ms  [  OK  ]  server=ephyr protocol=2025-03-26
  tools_list                        3.15ms  [  OK  ]  14 tools, all 4 task tools present
  ...
  TOTAL: N passed, 0 failed, XXms total latency
  ========================================================================
```

---

## Verification Checklist

After completing all setup steps, verify each component:

- [ ] **Signer starts and logs "listening"**
  ```bash
  systemctl status ephyr-signer
  journalctl -u ephyr-signer --no-pager -n 5
  # Should show: "listening on /run/ephyr/signer.sock"
  ```

- [ ] **Broker connects to signer**
  ```bash
  systemctl status ephyr-broker
  journalctl -u ephyr-broker --no-pager -n 10
  # Should show: "listening on /run/ephyr/broker.sock"
  # No signer connection errors
  ```

- [ ] **Signer health check passes**
  ```bash
  # As root or ephyr-broker user:
  curl --unix-socket /run/ephyr/broker.sock http://localhost/v1/health
  # Should return: {"status":"ok","signer":"ok",...}
  ```

- [ ] **Dashboard accessible**
  ```bash
  curl -s http://BROKER_HOST:8553/v1/dashboard/summary \
    -H "Authorization: Bearer YOUR_TOKEN" | python3 -m json.tool
  # Should return JSON with broker_status: "healthy"
  ```

- [ ] **MCP endpoint responds to initialize**
  ```bash
  curl -s -X POST http://BROKER_HOST:8554/mcp \
    -H "Authorization: Bearer YOUR_MCP_KEY" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}' \
    | python3 -m json.tool
  # Should return protocolVersion and serverInfo
  ```

- [ ] **Agent can request and receive cert**
  ```bash
  # As the agent user:
  ephyr init
  ephyr request -t my-server -r read
  # Should print certificate details (serial, principal, expiry)
  ```

- [ ] **SSH works with issued cert**
  ```bash
  ephyr ssh -t my-server -r operator
  # Should open an interactive SSH session as agent-op
  ephyr exec -t my-server -r read -- whoami
  # Should print: agent-read
  ```

- [ ] **Audit log captures events**
  ```bash
  tail -3 /var/log/ephyr/audit.json | python3 -m json.tool
  # Should show recent events (startup, cert_granted, etc.)
  ```

- [ ] **Activity monitoring shows entries**
  ```bash
  curl -s http://BROKER_HOST:8553/v1/dashboard/activity \
    -H "Authorization: Bearer YOUR_TOKEN" | python3 -m json.tool
  # Should list recent activity entries
  ```

- [ ] **Socket permissions correct**
  ```bash
  ls -la /run/ephyr/
  # broker.sock: srw-rw---- ephyr-broker ephyr-agents
  # signer.sock: srw-rw---- ephyr-broker ephyr-broker
  ```

- [ ] **Firewall rules active**
  ```bash
  nft list ruleset
  # Should show the inet filter table with SSH + 8553 + 8554 rules
  ```

- [ ] **Task identity tools available**
  ```bash
  curl -s -X POST http://BROKER_HOST:8554/mcp \
    -H "Authorization: Bearer YOUR_MCP_KEY" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
    | python3 -c "import sys,json; tools=[t['name'] for t in json.load(sys.stdin)['result']['tools']]; assert 'task_create' in tools, 'missing task_create'; print(f'{len(tools)} tools registered, task identity available')"
  ```

- [ ] **Task create/revoke cycle works**
  ```bash
  # Create a test task
  RESULT=$(curl -s -X POST http://BROKER_HOST:8554/mcp \
    -H "Authorization: Bearer YOUR_MCP_KEY" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"task_create","arguments":{"description":"verification test","ttl":"1m"}}}')
  TASK_ID=$(echo "$RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(json.loads(r['result']['content'][0]['text'])['task_id'])")
  echo "Created task: $TASK_ID"

  # Revoke it
  curl -s -X POST http://BROKER_HOST:8554/mcp \
    -H "Authorization: Bearer YOUR_MCP_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"task_revoke\",\"arguments\":{\"task_id\":\"$TASK_ID\"}}}" \
    | python3 -m json.tool
  # Should return: {"revoked": "...", "status": "all tokens invalidated"}
  ```

- [ ] **Integration tests pass**
  ```bash
  cd /opt/ephyr && go test ./test/integration/ -v -count=1
  # All tests should pass with 0 failures
  ```

---

## Troubleshooting

**"unknown agent UID" errors:**
The agent's Linux UID does not match any uid entry in the policy file.
Check with `id -u <agent-user>` and update policy.yaml accordingly.

**"signer ipc: dial" errors:**
The broker cannot connect to the signer socket. Verify ephyr-signer is
running and the socket exists at the expected path. Check that both
services use the same socket path.

**Agent gets "unauthorized" on broker socket:**
The agent user is not a member of the ephyr-agents group. Add them with
`usermod -aG ephyr-agents <user>` and have them re-login.

**"permission denied" on SSH to target:**
The target's sshd_config may be missing TrustedUserCAKeys or
AuthorizedPrincipalsFile. Verify the CA public key is present and the
principal file for the target user exists and contains the correct
principal name.

**Dashboard returns 401:**
The token does not match. Check the broker logs for the auto-generated
token, or verify the EPHYR_DASHBOARD_TOKEN environment variable.

**MCP returns "invalid API key":**
The plaintext key does not match any bcrypt hash in the policy file.
Regenerate the hash and update policy.yaml, then reload.

**Policy reload fails on SIGHUP:**
The new policy file has a syntax error or validation failure. The broker
keeps the old policy and logs the error. Check journalctl for details.
Common causes: duplicate UIDs, target max_ttl exceeding global max_ttl,
references to undefined roles.
