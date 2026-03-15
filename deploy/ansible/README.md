# Ephyr Ansible Deployment

Ansible roles for deploying an Ephyr broker and provisioning SSH target hosts.

## Roles

- **ephyr-broker** -- Installs Go, clones the repo, builds binaries, generates a CA key, templates `policy.yaml` and systemd units, starts services.
- **ephyr-target** -- Creates role accounts (`agent-read`, `agent-op`, `agent-admin`), deploys the CA public key, configures `sshd` for certificate auth, installs sudoers rules.

## Quick Start

```bash
# 1. Copy and edit inventory
cp inventory.example.yml inventory.yml
# Edit inventory.yml: set hosts, agents, targets, dashboard token

# 2. Deploy broker
ansible-playbook -i inventory.yml site.yml --limit ephyr_broker

# 3. Provision targets (uses CA key from broker automatically)
ansible-playbook -i inventory.yml site.yml --limit ephyr_targets

# 4. Deploy everything at once
ansible-playbook -i inventory.yml site.yml
```

## Inventory Example

```yaml
all:
  children:
    ephyr_broker:
      hosts:
        broker.example.com:
          ansible_user: root
          ephyr_dashboard_token: "my-secret-token"
          ephyr_agents:
            my-agent:
              uid: 1000
              max_concurrent_certs: 3
              description: "Primary automation agent"
          ephyr_targets:
            webserver:
              host: "10.0.1.10"
              port: 22
              allowed_roles: [read, operator]
              max_ttl: "10m"
              auto_approve: true
              description: "Production web server"
    ephyr_targets:
      hosts:
        webserver:
          ansible_host: 10.0.1.10
          ansible_user: root
          ephyr_roles: [read, operator]
```

## Key Variables (ephyr-broker)

| Variable | Default | Description |
|----------|---------|-------------|
| `ephyr_version` | `latest` | Git tag/branch to deploy |
| `ephyr_go_version` | `1.24.1` | Go version to install |
| `ephyr_git_repo` | GitHub URL | Source repository |
| `ephyr_dashboard_token` | `changeme` | Dashboard auth token |
| `ephyr_mcp_port` | `8554` | MCP listener port |
| `ephyr_dashboard_port` | `8553` | Dashboard listener port |
| `ephyr_agents` | `{}` | Agent definitions (uid, certs, description) |
| `ephyr_roles` | 3 defaults | Role-to-principal mappings |
| `ephyr_targets` | `{}` | SSH target definitions |
| `ephyr_generate_ca_key` | `true` | Auto-generate CA key if missing |

## Key Variables (ephyr-target)

| Variable | Default | Description |
|----------|---------|-------------|
| `ephyr_roles` | `[]` | Roles to provision (read, operator, admin) |
| `ephyr_ca_public_key` | `""` | CA public key (auto-fetched from broker if empty) |
| `ephyr_sudoers_immutable` | `true` | Lock sudoers with `chattr +i` |

## Notes

- The broker role runs the signer before the broker (required ordering).
- The CA public key is automatically shared from broker to targets when both plays run in the same `ansible-playbook` invocation.
- To provide the CA key manually, set `ephyr_ca_public_key` in inventory or pass it with `-e`.
- Policy changes trigger a broker reload (SIGHUP), not a full restart.
- Binary rebuilds only happen when the git checkout changes.

## Requirements

- Ansible 2.12+
- Target hosts: Debian/Ubuntu with `systemd` and `openssh-server`
- Broker host: internet access to download Go and clone the repo
