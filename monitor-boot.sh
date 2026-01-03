#!/bin/bash
set -e

# monitor-boot.sh - Monitor and Unlock Hetzner FDE Server
# Usage: ./monitor-boot.sh <primary_ip> <luks_password> <username> [secondary_ipv6]
# 
# The primary_ip can be IPv4 or IPv6. For dual-stack servers, pass IPv4 as primary
# and IPv6 as secondary. For IPv6-only servers, pass IPv6 as primary.
#
# Environment: PROVISION_USER can be set instead of passing username as argument

PRIMARY_IP=$1
LUKS_PASS=$2
PROVISION_USER=${3:-$PROVISION_USER}
SECONDARY_IPV6=$4

if [ -z "$PRIMARY_IP" ]; then
    echo "Error: Primary IP is required."
    exit 1
fi

if [ -z "$PROVISION_USER" ]; then
    echo "Error: Username is required (3rd argument or PROVISION_USER env var)."
    exit 1
fi

# Detect IP type
if [[ "$PRIMARY_IP" == *":"* ]]; then
    PRIMARY_IP_TYPE="IPv6"
else
    PRIMARY_IP_TYPE="IPv4"
fi

# SSH command
SSH_CMD=${SSH_CMD:-ssh}

# Default SSH options for automation
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10}"

# Function to get SSH target (strip brackets if present)
# Note: SSH with -6 flag works directly with IPv6 addresses without brackets
# Brackets cause issues with zsh glob expansion
get_ssh_target() {
    local ip=$1
    echo "$ip" | tr -d '[]'
}

# Function to get SSH options for a specific IP
get_ssh_opts() {
    local ip=$1
    local opts="$SSH_OPTS"
    [[ "$ip" == *":"* ]] && opts="$opts -6"
    echo "$opts"
}

# Load centralized wait utility
SCRIPT_DIR=$(dirname "$0")
# shellcheck disable=SC1091
source "$SCRIPT_DIR/wait_for_ssh.sh"

echo "--- Starting Boot Monitor ---"
echo "  Primary IP: $PRIMARY_IP ($PRIMARY_IP_TYPE)"
echo "  Secondary IPv6: ${SECONDARY_IPV6:-none}"
echo "  User: $PROVISION_USER"

unlock_luks() {
    local target_ip=$1
    local ssh_target
    ssh_target=$(get_ssh_target "$target_ip")
    local current_ssh_opts
    current_ssh_opts=$(get_ssh_opts "$target_ip")
    
    echo "Attempting LUKS Unlock on $target_ip..."
    local attempts=0
    local max_attempts=30
    local last_socket=""
    local unlock_sent=0

    while [ $attempts -lt $max_attempts ]; do
        # Check if OS is fully booted (user can log in)
        # shellcheck disable=SC2086
        if $SSH_CMD $current_ssh_opts "$PROVISION_USER@$ssh_target" "true" &>/dev/null 2>&1; then
            echo "LUKS Unlocked - OS is now running!"
            return 0
        fi
        
        # Check if LUKS is unlocked (root in initramfs can see vg0-root)
        # shellcheck disable=SC2086
        if $SSH_CMD $current_ssh_opts "root@$ssh_target" "ls /dev/mapper/vg0-root" &>/dev/null; then
            echo "LUKS Unlocked Successfully!"
            return 0
        fi

        # Find pending password request socket
        # NOTE: Must use single quotes to prevent local shell expansion - remote bash expands $s
        local socket_path
        socket_path=$(
            # shellcheck disable=SC2086,SC2016
            $SSH_CMD $current_ssh_opts "root@$ssh_target" \
                'bash -lc '\''for s in /run/systemd/ask-password/sck.*; do [ -S "$s" ] || continue; echo "$s"; break; done'\''' \
                2>/dev/null || true
        )

        
        if [ -z "$socket_path" ]; then
            # No socket found - could be:
            # 1. System is transitioning (rebooting after SELinux relabel)
            # 2. Socket not ready yet
            # 3. SSH failed
            if [ $unlock_sent -eq 1 ]; then
                echo "Waiting for system to complete boot sequence..."
            else
                echo "Waiting for password request socket..."
            fi
        elif [ "$socket_path" != "$last_socket" ]; then
            # New socket found (different from last one we tried)
            echo "Sending unlock command (Attempt $((attempts+1))) to socket: $socket_path"
            # Use systemd-reply-password directly - it reads password from stdin
            # Pass password via stdin (<<<) to avoid embedding it in the remote command string
            # shellcheck disable=SC2086
            $SSH_CMD $current_ssh_opts "root@$ssh_target" \
                "/usr/lib/systemd/systemd-reply-password 1 '$socket_path'" <<< "$LUKS_PASS" 2>/dev/null || true
            last_socket="$socket_path"
            unlock_sent=1
            
            # Give systemd a moment to process the unlock
            sleep 2
            continue  # Skip the normal sleep, check state immediately
        else
            # Same socket as before - it wasn't consumed, might be wrong password or timing issue
            echo "Socket still pending, waiting..."
        fi

        sleep 3
        ((attempts++))
    done

    echo "Failed to unlock LUKS on $target_ip after $max_attempts attempts."
    return 1
}

# Phase 1: First Boot (Initramfs)
echo "=== Phase 1: First Boot ==="
wait_for_ssh "root" "$PRIMARY_IP" 120 20 || exit 1

# If secondary IPv6 is provided, verify we can also reach it
if [ -n "$SECONDARY_IPV6" ]; then
    echo "Verifying dual-stack reachability in initramfs..."
    if wait_for_ssh "root" "$SECONDARY_IPV6" 30 5; then
        echo "SUCCESS: IPv6 is reachable in initramfs."
    else
        echo "WARNING: IPv6 is NOT reachable in initramfs. Check kernel arguments."
    fi
fi

unlock_luks "$PRIMARY_IP" || exit 1

# After first unlock, system may:
# 1. Reboot for SELinux relabel, then need second unlock
# 2. Boot directly to OS (rare for fresh install)
# The unlock_luks function now handles both cases by checking for user login

SSH_TARGET=$(get_ssh_target "$PRIMARY_IP")
CURRENT_SSH_OPTS=$(get_ssh_opts "$PRIMARY_IP")

# Check if we're already at OS (user can log in)
# shellcheck disable=SC2086
if $SSH_CMD $CURRENT_SSH_OPTS "$PROVISION_USER@$SSH_TARGET" "true" &>/dev/null 2>&1; then
    echo "OS is already running after first unlock (no SELinux relabel reboot)."
else
    # Need to handle SELinux relabel reboot sequence
    echo "=== Phase 2: Waiting for SELinux Relabel Reboot ==="
    echo "Waiting for system to reboot after SELinux relabel..."
    
    # Wait for SSH to drop (system rebooting)
     for _ in {1..60}; do
         # shellcheck disable=SC2086
         if ! $SSH_CMD $CURRENT_SSH_OPTS "root@$SSH_TARGET" "true" &>/dev/null; then
             echo "System rebooting..."
             break
         fi
         sleep 2
     done
    
    # Wait for second boot initramfs
    # Important: the relabel reboot may come back either as initramfs (root login works)
    # or directly into the real OS (root login is disabled). Avoid long waits on root.
    echo "Waiting for second boot (initramfs or OS)..."
    sleep 10  # Give system time to start rebooting

    if wait_for_ssh "root" "$PRIMARY_IP" 30 5; then
        echo "Initramfs is reachable for second boot."
    elif wait_for_ssh "$PROVISION_USER" "$PRIMARY_IP" 120 20; then
        echo "System booted directly to OS."
    else
        echo "ERROR: Could not reach system after relabel reboot."
        exit 1
    fi
    
    echo "=== Phase 3: Second Boot (Initramfs) ==="
    unlock_luks "$PRIMARY_IP" || exit 1
fi

# Phase 4: OS Boot
echo "=== Phase 4: OS Boot ==="
# Wait for user
if wait_for_ssh "$PROVISION_USER" "$PRIMARY_IP" 120 20; then
    echo "SUCCESS: User '$PROVISION_USER' can log in via $PRIMARY_IP_TYPE ($PRIMARY_IP)."
    
    if [ -n "$SECONDARY_IPV6" ]; then
        echo "Checking secondary IPv6 login..."
        if wait_for_ssh "$PROVISION_USER" "$SECONDARY_IPV6" 30 5; then
            echo "SUCCESS: User '$PROVISION_USER' can log in via IPv6 ($SECONDARY_IPV6)."
        else
            echo "WARNING: User '$PROVISION_USER' cannot log in via secondary IPv6 yet."
        fi
    fi
    
    echo "Boot complete: user SSH is available."
    exit 0
else
    echo "FAILURE: Could not log in as '$PROVISION_USER'."
    exit 1
fi
