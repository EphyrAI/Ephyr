#!/bin/bash
# Ephyr Live Audit Stream
# Shows real-time broker events in a clean, colored format
# Dependencies: sshpass, bash only (no python/jq required)
# Usage: ./ephyr-live.sh [BROKER_HOST] [PASSWORD]

HOST="${1:-192.168.100.75}"
PASS="${2:-ff3fmmmk}"

CYAN='\033[36m'
YELLOW='\033[33m'
RED='\033[31m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

clear
echo "============================================"
echo "  EPHYR LIVE AUDIT STREAM"
echo "  Broker: $HOST"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
echo ""

sshpass -p "$PASS" ssh -o StrictHostKeyChecking=accept-new root@"$HOST" \
  "tail -f /var/log/ephyr/audit.json" 2>/dev/null | \
while IFS= read -r line; do
    sev=$(echo "$line" | grep -o '"severity":"[^"]*"' | head -1 | cut -d'"' -f4)
    evt=$(echo "$line" | grep -o '"event_type":"[^"]*"' | head -1 | cut -d'"' -f4)
    agent=$(echo "$line" | grep -o '"agent":"[^"]*"' | head -1 | cut -d'"' -f4)
    ts=$(echo "$line" | grep -o '"timestamp":"[^"]*"' | head -1 | cut -d'"' -f4)

    time_str="${ts:11:8}"
    [ -z "$time_str" ] && time_str="??:??:??"
    [ -z "$sev" ] && sev="INFO"
    [ -z "$evt" ] && continue
    [ -z "$agent" ] && agent="-"
    sev="${sev:0:4}"

    case "$sev" in
        WARN) color="$YELLOW" ;;
        CRIT|ERR*) color="$RED" ;;
        *) color="$CYAN" ;;
    esac

    case "$evt" in
        mcp_exec)           label="EXEC " ;;
        http_proxy)         label="HTTP " ;;
        mcp_federation)     label="MCP  " ;;
        task_create)        label="TASK+" ;;
        task_delegate)      label="DELE " ;;
        task_revoke*)       label="REVK " ;;
        task_bind)          label="BIND " ;;
        command_denied)     label="DENY " ;;
        auto_revoke)        label="KILL " ;;
        request_denied)     label="DENY " ;;
        cert_issued)        label="CERT " ;;
        cert_revoked)       label="XCER " ;;
        policy_reload)      label="LOAD " ;;
        host_toggle)        label="TOGL " ;;
        service_toggle)     label="TOGL " ;;
        terminal_*)         label="TERM " ;;
        *)                  label="${evt:0:5}" ;;
    esac

    detail=""
    for key in target service remote task_id command pattern role description method status_code duration_ms cascade_count reason; do
        val=$(echo "$line" | grep -o "\"$key\":\"[^\"]*\"" | head -1 | cut -d'"' -f4)
        if [ -z "$val" ]; then
            val=$(echo "$line" | grep -o "\"$key\":[0-9]*" | head -1 | cut -d: -f2)
        fi
        if [ -n "$val" ]; then
            case "$key" in
                duration_ms) detail="$detail ${val}ms" ;;
                status_code) detail="$detail HTTP:${val}" ;;
                cascade_count) detail="$detail cascade=${val}" ;;
                *) detail="$detail ${key}=${val}" ;;
            esac
        fi
    done

    printf "${DIM}%s${RESET} ${color}${BOLD}%s${RESET} ${color}%s${RESET}  %-12s%s\n" \
        "$time_str" "$label" "$sev" "$agent" "$detail"
done
