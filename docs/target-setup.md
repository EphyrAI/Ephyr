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

## Security notes

- **Ephyr controls access (who, when, how long).** The target host controls capability (what they can do once connected).
- **Certificate TTL is your blast radius.** Default 5 minutes. A compromised certificate is useless after expiry.
- **rbash is defense-in-depth**, not a security boundary. A determined attacker can escape restricted shells. The real protection is short TTLs and audit trails.
- **Sudoers deny lists are fragile.** New binaries or symlinks can bypass command restrictions. Consider using allow-lists for high-security targets.
- **Lock sudoers with `chattr +i`** to prevent modification by compromised agent accounts. The provisioning script does this automatically.
