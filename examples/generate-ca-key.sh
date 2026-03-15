#!/bin/bash
# Generate a CA key for Ephyr (run once)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_PATH="${SCRIPT_DIR}/ca_key"

if [ -f "$KEY_PATH" ]; then
    echo "CA key already exists at ${KEY_PATH}"
    echo "Remove it first if you want to regenerate."
    exit 1
fi

ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "ephyr-ca"
echo "CA key generated at ${KEY_PATH}"
echo "Run: docker compose up --build"
