#!/bin/bash
# Install Ephyr systemd units with correct settings.
# Usage: ./deploy/install-services.sh [DASHBOARD_TOKEN] [MCP_PORT] [DASHBOARD_PORT]
set -e

TOKEN="${1:-changeme}"
MCP_PORT="${2:-8554}"
DASH_PORT="${3:-8553}"

cat > /etc/systemd/system/ephyr-signer.service << 'EOF'
[Unit]
Description=Ephyr SSH Certificate Signer
Documentation=https://github.com/EphyrAI/Ephyr
After=network.target
Before=ephyr-broker.service

[Service]
Type=simple
User=ephyr-broker
Group=ephyr-agents
ExecStart=/usr/local/bin/ephyr-signer --ca-key /etc/ephyr/ca_key --socket /run/ephyr/signer.sock

StandardOutput=journal
StandardError=journal
SyslogIdentifier=ephyr-signer

Restart=on-failure
RestartSec=5s

ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes

ReadOnlyPaths=/etc/ephyr
ReadWritePaths=/run/ephyr

CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ephyr-broker.service << BROKEREOF
[Unit]
Description=Ephyr SSH Certificate Broker
Documentation=https://github.com/EphyrAI/Ephyr
After=network.target ephyr-signer.service
Wants=ephyr-signer.service

[Service]
Type=simple
User=ephyr-broker
Group=ephyr-agents
ExecStart=/usr/local/bin/ephyr-broker --policy /etc/ephyr/policy.yaml
ExecReload=/bin/kill -HUP \$MAINPID

Environment=EPHYR_SIGNER_SOCKET=/run/ephyr/signer.sock
Environment=EPHYR_MCP_LISTEN=:${MCP_PORT}
Environment=EPHYR_DASHBOARD_LISTEN=:${DASH_PORT}
Environment=EPHYR_DASHBOARD_TOKEN=${TOKEN}

StandardOutput=journal
StandardError=journal
SyslogIdentifier=ephyr-broker

Restart=on-failure
RestartSec=5s

ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes

ReadWritePaths=/run/ephyr /var/log/ephyr /var/lib/ephyr

CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
BROKEREOF

echo "d /run/ephyr 0750 ephyr-broker ephyr-agents -" > /etc/tmpfiles.d/ephyr.conf
systemd-tmpfiles --create 2>/dev/null || true
systemctl daemon-reload
echo "Systemd units installed (MCP: :${MCP_PORT}, Dashboard: :${DASH_PORT})"
