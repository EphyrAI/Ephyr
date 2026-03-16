#!/usr/bin/env bash
#
# provision-target.sh — Configure a Debian/Ubuntu host to accept Ephyr SSH certificates.
#
# Usage:
#   ./provision-target.sh /path/to/ca.pub
#   CA_PUB_KEY="ssh-ed25519 AAAA..." ./provision-target.sh
#   cat ca.pub | ./provision-target.sh -
#
# Idempotent: safe to run multiple times.

set -euo pipefail

readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly CA_PUB_DEST="/etc/ssh/ephyr_ca.pub"
readonly PRINCIPALS_DIR="/etc/ssh/auth_principals"
readonly SUDOERS_FILE="/etc/sudoers.d/ephyr"
readonly SCRIPT_NAME="$(basename "$0")"

# Color output helpers.
info()  { printf '\033[1;34m[INFO]\033[0m  %s\n' "$*"; }
ok()    { printf '\033[1;32m[OK]\033[0m    %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*"; }
fail()  { printf '\033[1;31m[FAIL]\033[0m  %s\n' "$*" >&2; exit 1; }

# ─── Check root ────────────────────────────────────────────────────────────────

[[ "$(id -u)" -eq 0 ]] || fail "This script must be run as root."

# ─── Resolve CA public key ─────────────────────────────────────────────────────

CA_PUB_KEY="${CA_PUB_KEY:-}"

if [[ $# -ge 1 ]]; then
    if [[ "$1" == "-" ]]; then
        info "Reading CA public key from stdin..."
        CA_PUB_KEY="$(cat)"
    elif [[ -f "$1" ]]; then
        info "Reading CA public key from $1..."
        CA_PUB_KEY="$(cat "$1")"
    else
        fail "File not found: $1"
    fi
fi

if [[ -z "$CA_PUB_KEY" ]]; then
    fail "No CA public key provided. Pass a file path, set CA_PUB_KEY, or pipe via stdin."
fi

# Validate it looks like an SSH public key.
if ! echo "$CA_PUB_KEY" | grep -qE '^ssh-(ed25519|rsa|ecdsa)'; then
    fail "CA_PUB_KEY does not look like a valid SSH public key."
fi

info "CA public key: ${CA_PUB_KEY:0:50}..."

# ─── Step 1: Install CA public key ────────────────────────────────────────────

info "Installing CA public key to $CA_PUB_DEST..."
echo "$CA_PUB_KEY" > "$CA_PUB_DEST"
chmod 644 "$CA_PUB_DEST"
chown root:root "$CA_PUB_DEST"
ok "CA public key installed."

# ─── Step 2: Configure sshd ───────────────────────────────────────────────────

info "Configuring sshd..."

# Backup sshd_config if not already backed up by us.
if [[ ! -f "${SSHD_CONFIG}.ephyr-backup" ]]; then
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.ephyr-backup"
    info "Backed up sshd_config to ${SSHD_CONFIG}.ephyr-backup"
fi

# Add TrustedUserCAKeys (idempotent).
if grep -q "^TrustedUserCAKeys.*ephyr_ca.pub" "$SSHD_CONFIG" 2>/dev/null; then
    info "TrustedUserCAKeys already configured."
else
    # Remove any commented-out version first.
    sed -i '/^#.*TrustedUserCAKeys.*ephyr_ca.pub/d' "$SSHD_CONFIG"
    echo "" >> "$SSHD_CONFIG"
    echo "# Ephyr SSH Certificate Authentication" >> "$SSHD_CONFIG"
    echo "TrustedUserCAKeys $CA_PUB_DEST" >> "$SSHD_CONFIG"
    ok "Added TrustedUserCAKeys to sshd_config."
fi

# Add AuthorizedPrincipalsFile (idempotent).
if grep -q "^AuthorizedPrincipalsFile.*/etc/ssh/auth_principals/%u" "$SSHD_CONFIG" 2>/dev/null; then
    info "AuthorizedPrincipalsFile already configured."
else
    sed -i '/^#.*AuthorizedPrincipalsFile.*auth_principals/d' "$SSHD_CONFIG"
    echo "AuthorizedPrincipalsFile $PRINCIPALS_DIR/%u" >> "$SSHD_CONFIG"
    ok "Added AuthorizedPrincipalsFile to sshd_config."
fi

# Validate sshd config.
if sshd -t 2>/dev/null; then
    ok "sshd configuration is valid."
else
    warn "sshd -t failed. Restoring backup and aborting."
    cp "${SSHD_CONFIG}.ephyr-backup" "$SSHD_CONFIG"
    fail "sshd configuration validation failed. Original config restored."
fi

# ─── Step 3: Create principals directory ──────────────────────────────────────

info "Creating principals directory at $PRINCIPALS_DIR..."
mkdir -p "$PRINCIPALS_DIR"
chmod 755 "$PRINCIPALS_DIR"
chown root:root "$PRINCIPALS_DIR"

# ─── Step 4: Create role accounts ─────────────────────────────────────────────

create_role_account() {
    local username="$1"
    local shell="$2"
    local principal="$3"

    if id "$username" &>/dev/null; then
        info "User $username already exists."
    else
        info "Creating user $username with shell $shell..."

        # For rbash, check if it exists.
        local actual_shell="$shell"
        if [[ "$shell" == "/usr/bin/rbash" ]] && [[ ! -x "/usr/bin/rbash" ]]; then
            if [[ -x "/bin/rbash" ]]; then
                actual_shell="/bin/rbash"
            else
                # Create rbash symlink if bash exists.
                if [[ -x "/bin/bash" ]]; then
                    ln -sf /bin/bash /usr/bin/rbash
                    actual_shell="/usr/bin/rbash"
                    info "Created /usr/bin/rbash symlink."
                else
                    warn "rbash not available, falling back to /bin/sh"
                    actual_shell="/bin/sh"
                fi
            fi
        fi

        useradd \
            --create-home \
            --shell "$actual_shell" \
            --system \
            --comment "Ephyr $username role" \
            "$username"
        ok "Created user $username."
    fi

    # Create principal file (always overwrite to ensure correctness).
    echo "$principal" > "${PRINCIPALS_DIR}/${username}"
    chmod 644 "${PRINCIPALS_DIR}/${username}"
    chown root:root "${PRINCIPALS_DIR}/${username}"
    ok "Principal file for $username: $principal"

    # Ensure .ssh directory exists with correct permissions.
    local home_dir
    home_dir="$(getent passwd "$username" | cut -d: -f6)"
    mkdir -p "${home_dir}/.ssh"
    chmod 700 "${home_dir}/.ssh"
    chown "$username:$(id -gn "$username")" "${home_dir}/.ssh"
}

info "Creating role accounts..."

create_role_account "agent-read"  "/usr/bin/rbash" "agent-read"
create_role_account "agent-op"    "/bin/bash"      "agent-op"
create_role_account "agent-admin" "/bin/bash"      "agent-admin"

# ─── Step 5: Install sudoers rules ────────────────────────────────────────────

info "Installing sudoers rules..."

# Ensure sudo is installed.
if ! command -v sudo &>/dev/null; then
    warn "sudo is not installed. Installing..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq sudo
    elif command -v yum &>/dev/null; then
        yum install -y -q sudo
    elif command -v apk &>/dev/null; then
        apk add --quiet sudo
    else
        warn "Cannot install sudo automatically. Skipping sudoers rules."
        warn "Install sudo manually and re-run this script."
    fi
fi

# Ensure sudoers.d directory exists.
mkdir -p /etc/sudoers.d

# Remove immutable flag if present from a previous run.
if [[ -f "$SUDOERS_FILE" ]]; then
    chattr -i "$SUDOERS_FILE" 2>/dev/null || true
fi

cat > "$SUDOERS_FILE" << 'SUDOERSEOF'
# Ephyr role-based sudoers rules
# Managed by provision-target.sh — do not edit manually.
# This file is made immutable (chattr +i) after provisioning.

# ─── Explicit DENY list (all roles) ──────────────────────────────────────────
# These commands are NEVER allowed, regardless of role.

Cmnd_Alias EPHYR_DENY_SHELLS = /bin/bash, /bin/sh, /bin/zsh, /usr/bin/zsh, \
    /usr/bin/fish, /bin/fish

Cmnd_Alias EPHYR_DENY_EDITORS = /usr/bin/vi, /usr/bin/vim, /usr/bin/nano, \
    /usr/bin/emacs, /bin/vi, /bin/nano

Cmnd_Alias EPHYR_DENY_INTERPRETERS = /usr/bin/python*, /usr/bin/perl, \
    /usr/bin/ruby, /usr/bin/node, /usr/local/bin/python*, /usr/local/bin/node

Cmnd_Alias EPHYR_DENY_PKGMGR = /usr/bin/apt install *, /usr/bin/apt remove *, \
    /usr/bin/apt purge *, /usr/bin/dpkg -i *, /usr/bin/dpkg --install *, \
    /usr/bin/dpkg -r *, /usr/bin/dpkg --remove *, /usr/bin/dpkg -P *, \
    /usr/bin/dpkg --purge *

Cmnd_Alias EPHYR_DENY_DANGEROUS = /usr/bin/chattr, /usr/sbin/visudo, \
    /bin/su, /usr/bin/su, /usr/bin/passwd, /usr/sbin/usermod, \
    /usr/sbin/userdel, /bin/chmod, /usr/bin/chmod, /bin/chown, /usr/bin/chown

# Apply deny rules to all agent roles.
agent-read  ALL = !EPHYR_DENY_SHELLS, !EPHYR_DENY_EDITORS, !EPHYR_DENY_INTERPRETERS, !EPHYR_DENY_PKGMGR, !EPHYR_DENY_DANGEROUS
agent-op    ALL = !EPHYR_DENY_SHELLS, !EPHYR_DENY_EDITORS, !EPHYR_DENY_INTERPRETERS, !EPHYR_DENY_PKGMGR, !EPHYR_DENY_DANGEROUS
agent-admin ALL = !EPHYR_DENY_SHELLS, !EPHYR_DENY_EDITORS, !EPHYR_DENY_INTERPRETERS, !EPHYR_DENY_PKGMGR, !EPHYR_DENY_DANGEROUS

# ─── agent-read: NO sudo access ──────────────────────────────────────────────
# (no additional rules — agent-read gets no sudo at all)

# ─── agent-op: read-only operations ──────────────────────────────────────────

Cmnd_Alias EPHYR_OP_SYSTEMCTL = /usr/bin/systemctl status *, \
    /usr/bin/systemctl restart *, /usr/bin/systemctl stop *

Cmnd_Alias EPHYR_OP_DOCKER = /usr/bin/docker ps *, /usr/bin/docker ps, \
    /usr/bin/docker logs *, /usr/bin/docker inspect *, \
    /usr/bin/docker stats *, /usr/bin/docker stats, \
    /usr/bin/docker compose ps *, /usr/bin/docker compose ps, \
    /usr/bin/docker compose logs *, /usr/bin/docker compose top *

Cmnd_Alias EPHYR_OP_MONITORING = /usr/bin/journalctl *, /usr/bin/journalctl, \
    /usr/bin/df *, /usr/bin/df, /usr/bin/free *, /usr/bin/free, \
    /usr/sbin/ip *, /usr/bin/ss *, /usr/bin/ss, \
    /usr/bin/cat *, /usr/bin/ls *, /usr/bin/find *

agent-op ALL = NOPASSWD: EPHYR_OP_SYSTEMCTL, EPHYR_OP_DOCKER, EPHYR_OP_MONITORING

# ─── agent-admin: agent-op + management operations ───────────────────────────

Cmnd_Alias EPHYR_ADMIN_SYSTEMCTL = /usr/bin/systemctl start *, \
    /usr/bin/systemctl enable *, /usr/bin/systemctl disable *

Cmnd_Alias EPHYR_ADMIN_DOCKER = /usr/bin/docker run *, \
    /usr/bin/docker exec *, /usr/bin/docker pull *, \
    /usr/bin/docker build *

Cmnd_Alias EPHYR_ADMIN_PKG = /usr/bin/apt list *, /usr/bin/apt list, \
    /usr/bin/apt show *

Cmnd_Alias EPHYR_ADMIN_STORAGE = /usr/bin/mount *, /usr/bin/umount *

agent-admin ALL = NOPASSWD: EPHYR_OP_SYSTEMCTL, EPHYR_OP_DOCKER, EPHYR_OP_MONITORING, \
    EPHYR_ADMIN_SYSTEMCTL, EPHYR_ADMIN_DOCKER, EPHYR_ADMIN_PKG, EPHYR_ADMIN_STORAGE
SUDOERSEOF

# Validate sudoers syntax.
chmod 440 "$SUDOERS_FILE"
chown root:root "$SUDOERS_FILE"

if visudo -c -f "$SUDOERS_FILE" 2>/dev/null; then
    ok "Sudoers rules installed and validated."
else
    warn "Sudoers validation failed. Removing invalid file."
    rm -f "$SUDOERS_FILE"
    fail "Sudoers file failed validation. Check the rules and try again."
fi

# Make sudoers file immutable.
chattr +i "$SUDOERS_FILE" 2>/dev/null && ok "Sudoers file made immutable (chattr +i)." || warn "chattr not available; sudoers file is not immutable."

# ─── Step 6: Restart sshd ─────────────────────────────────────────────────────

info "Restarting sshd..."
if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
    ok "sshd restarted."
else
    warn "Could not restart sshd. You may need to restart it manually."
fi

# ─── Done ──────────────────────────────────────────────────────────────────────

echo ""
ok "Ephyr target provisioning complete!"
echo ""
info "Role accounts created:"
echo "  agent-read  — restricted shell, no sudo"
echo "  agent-op    — bash, read-only sudo (systemctl status, docker ps/logs, etc.)"
echo "  agent-admin — bash, management sudo (start/stop services, docker run/exec, etc.)"
echo ""
info "Test with:"
echo "  ssh -i ~/.ephyr/id_ed25519 -o CertificateFile=<cert> agent-read@$(hostname -f || hostname)"
echo "  ssh -i ~/.ephyr/id_ed25519 -o CertificateFile=<cert> agent-op@$(hostname -f || hostname)"
echo ""
