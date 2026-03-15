#!/bin/bash
# Ephyr Live Audit Stream
# Shows real-time broker events in a clean, colored format
# Usage: ./ephyr-live.sh

HOST="192.168.100.75"
PASS="ff3fmmmk"

clear
echo "============================================"
echo "  EPHYR LIVE AUDIT STREAM"
echo "  Broker: $HOST"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
echo ""

sshpass -p "$PASS" ssh -o StrictHostKeyChecking=accept-new root@$HOST \
  "tail -f /var/log/ephyr/audit.json" 2>/dev/null | \
python3 -c "
import sys, json
from datetime import datetime

COLORS = {
    'INFO': '\033[36m',   # cyan
    'WARN': '\033[33m',   # yellow
    'CRIT': '\033[31m',   # red
    'ERR':  '\033[31m',   # red
}
RESET = '\033[0m'
DIM = '\033[2m'
BOLD = '\033[1m'

EVENT_ICONS = {
    'mcp_exec':          'EXEC',
    'http_proxy':        'HTTP',
    'mcp_federation':    'MCP ',
    'task_create':       'TASK+',
    'task_delegate':     'DELE',
    'task_revoke':       'REVK',
    'task_bind':         'BIND',
    'command_denied':    'DENY',
    'auto_revoke':       'KILL',
    'request_denied':    'DENY',
    'cert_issued':       'CERT',
    'cert_revoked':      'XCER',
    'policy_reload':     'LOAD',
    'host_toggle':       'TOGL',
    'service_toggle':    'TOGL',
    'terminal_open':     'TERM',
    'terminal_close':    'TERM',
}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except:
        continue

    sev = e.get('severity', 'INFO')[:4].upper()
    evt = e.get('event_type', '?')
    agent = e.get('agent', '-')
    ts = e.get('timestamp', '')
    details = e.get('details', {})

    # Parse timestamp
    try:
        t = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        time_str = t.strftime('%H:%M:%S')
    except:
        time_str = '??:??:??'

    # Color
    color = COLORS.get(sev, '')
    icon = EVENT_ICONS.get(evt, evt[:4].upper())

    # Build detail string
    parts = []
    for k, v in list(details.items())[:4]:
        if k in ('duration_ms',):
            parts.append(f'{v}ms')
        elif k in ('target', 'service', 'remote', 'task_id', 'command', 'pattern', 'role', 'description'):
            parts.append(f'{k}={v}')
        elif k == 'status_code':
            parts.append(f'HTTP {v}')
        elif k == 'cascade_count':
            parts.append(f'cascade={v}')
        else:
            parts.append(f'{k}={v}')
    detail_str = '  '.join(parts) if parts else ''

    print(f'{DIM}{time_str}{RESET} {color}{BOLD}{icon:5s}{RESET} {color}{sev:4s}{RESET}  {agent:12s} {detail_str}')
    sys.stdout.flush()
"
