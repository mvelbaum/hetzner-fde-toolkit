#!/bin/bash
set -e

# update-boot-ipv6.sh - Update the static IPv6 used for initramfs unlocking
# Usage: sudo ./update-boot-ipv6.sh [new_ipv6_address]

NEW_IP=$1

if [[ "$NEW_IP" =~ ^(-h|--help)$ ]]; then
    echo "Usage: sudo $0 [new_ipv6_address]" >&2
    exit 0
fi

# If no IP provided, try to fetch from Hetzner Metadata Service
if [ -z "$NEW_IP" ]; then
    echo "No IP provided, fetching from Hetzner metadata..."
    METADATA_URL="http://169.254.169.254/hetzner/v1/metadata"
    # Try to get the first IPv6 address from metadata
    NEW_IP=$(curl -s $METADATA_URL | grep "address:" | grep "::" | head -n 1 | awk '{print $2}' | sed 's|/.*||')
    if [ -z "$NEW_IP" ]; then
        echo "Error: Could not retrieve IPv6 from metadata."
        exit 1
    fi
    # If it's a prefix, append ::1
    if [[ "$NEW_IP" == *"::" ]]; then
        NEW_IP="${NEW_IP}1"
    fi
    echo "Found IP in metadata: $NEW_IP"
fi

# Determine interface
IFACE="enp1s0"
if ! ip link show "$IFACE" &>/dev/null; then
    IFACE=$(ip -o link show | grep -v lo | head -n1 | awk -F': ' '{print $2}')
fi

# Get hostname
HOSTNAME=$(hostname -s)

# Build the new argument using the combined IPv4 DHCP + IPv6 static format
# This format tells NetworkManager in initramfs to:
# - Set ipv6.method=manual with the static address and gateway
# - Set ipv4.method=auto (DHCP) on the same interface
NEW_ARG="ip=[${NEW_IP}]::[fe80::1]:64:${HOSTNAME}:${IFACE}:dhcp"

echo "Updating GRUB with: $NEW_ARG"

# 1. Remove old ip= arguments
# grubby treats all ip= as the same parameter, so we need to be careful.
# First, check if there's an existing IPv6 ip= argument
CURRENT_ARGS=$(grubby --info=DEFAULT | grep args)

# Remove any existing ip= arguments (both dhcp-only and combined)
# We remove any ip=... token from the args line to avoid confusing grubby.
# This intentionally removes both `ip=dhcp` and IPv6 combined formats.
OLD_IP_ARGS=$(echo "$CURRENT_ARGS" | tr -d '"' | grep -oE 'ip=[^ ]+' || true)
if [ -n "$OLD_IP_ARGS" ]; then
    while IFS= read -r arg; do
        [ -z "$arg" ] && continue
        echo "Removing old argument: $arg"
        grubby --update-kernel=ALL --remove-args="$arg"
    done <<<"$OLD_IP_ARGS"
fi

# 2. Add the new combined argument
grubby --update-kernel=ALL --args="$NEW_ARG"

echo "Success! The next boot will use $NEW_IP for the initramfs SSH server."
echo "Note: This does not change the running OS configuration (NetworkManager)."
