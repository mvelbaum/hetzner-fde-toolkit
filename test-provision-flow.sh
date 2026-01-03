#!/bin/bash
set -eo pipefail

# test-provision-flow.sh - End-to-End Test Wrapper
# Re-provisions a server and monitors the boot process automatically.
# Usage: ./test-provision-flow.sh <server_name_or_id>

SERVER_TARGET=$1

if [ -z "$SERVER_TARGET" ]; then
    echo "Usage: $0 <server_name_or_id>"
    echo "Requires environment variables: HCLOUD_TOKEN, USER_SSH_KEY"
    exit 1
fi

SCRIPT_DIR=$(dirname "$0")
PROVISION_SCRIPT="$SCRIPT_DIR/provision.sh"

# Ensure we are in auto-reboot mode
export AUTO_REBOOT=1

# Avoid interactive prompts during tee/piped run
# NOTE: Do not force-set NETBIRD_SETUP_KEY here; let provision.sh
# prompt (blank input skips NetBird) unless the user explicitly set it.
export SUDO_NOPASSWD=${SUDO_NOPASSWD:-n}
export WARP_TUNNEL=${WARP_TUNNEL:-n}
# If WARP_TUNNEL_MODE is set, keep it. Otherwise let provision.sh decide.
if [ -n "${WARP_TUNNEL_MODE:-}" ]; then
    export WARP_TUNNEL_MODE
fi

# 1Password save in non-interactive mode:
# - OP_VAULT_REF: set to enable saving (example: op://Servers)
# - OP_OVERWRITE_EXISTING: y/n to control overwrite behavior
# - OP_SERVICE_ACCOUNT_TOKEN is recommended for automation
export OP_OVERWRITE_EXISTING=${OP_OVERWRITE_EXISTING:-n}

if [ -z "$PROVISION_USER" ]; then
    echo "Error: PROVISION_USER is not set."
    exit 1
fi

echo "=== Starting End-to-End Test for $SERVER_TARGET ==="
echo "Provisioning (full end-to-end)..."

# Run provisioning and capture output to a temporary file while also showing it
LOG_FILE=$(mktemp)
if ! $PROVISION_SCRIPT "$SERVER_TARGET" | tee "$LOG_FILE"; then
    echo "Error: Provisioning failed."
    rm "$LOG_FILE"
    exit 1
fi

rm "$LOG_FILE"

echo ""
echo "=== Test Complete ==="
