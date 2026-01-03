#!/bin/bash
set -eo pipefail

# finalize.sh - Post-boot finalization for Hetzner FDE provisioning
#
# This script is run from the provisioner host (your local machine) after the
# system is fully booted and the provisioned user can log in.
#
# It performs post-boot configuration that cannot reliably happen in the
# installimage chroot:
# - Persistent IPv6 configuration (NetworkManager)
# - Optional: IPv4 tunneling via Cloudflare WARP
# - Optional: NetBird install + registration (fails provisioning if not connected)
# - Optional: sudo hardening (remove NOPASSWD)
#
# Usage: ./finalize.sh <primary_ip> <username> [secondary_ipv6]

PRIMARY_IP=$1
PROVISION_USER=$2
SECONDARY_IPV6=${3:-}

if [ -z "$PRIMARY_IP" ]; then
    echo "Error: Primary IP is required." >&2
    exit 1
fi

if [ -z "$PROVISION_USER" ]; then
    echo "Error: Username is required." >&2
    exit 1
fi

# Inputs expected from the orchestrator (provision.sh):
# - SERVER_IPV4, SERVER_IPV6_NET, SERVER_IPV6_ADDR
# - NETBIRD_SETUP_KEY (optional)
# - WARP_TUNNEL, WARP_TUNNEL_MODE
# - SUDO_NOPASSWD

# SSH command
SSH_CMD=${SSH_CMD:-ssh}

SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10}"

get_ssh_target() {
    local ip=$1
    echo "$ip" | tr -d '[]'
}

get_ssh_opts() {
    local ip=$1
    local opts="$SSH_OPTS"
    [[ "$ip" == *":"* ]] && opts="$opts -6"
    echo "$opts"
}

SCRIPT_DIR=$(dirname "$0")
# shellcheck disable=SC1091
source "$SCRIPT_DIR/wait_for_ssh.sh"

# Prefer primary IP, fall back to secondary IPv6 if provided.
TARGET_IP="$PRIMARY_IP"

if ! wait_for_ssh "$PROVISION_USER" "$TARGET_IP" 60 10; then
    if [ -n "$SECONDARY_IPV6" ]; then
        echo "Primary IP login failed; trying secondary IPv6..." >&2
        TARGET_IP="$SECONDARY_IPV6"
        wait_for_ssh "$PROVISION_USER" "$TARGET_IP" 60 10
    else
        exit 1
    fi
fi

SSH_TARGET=$(get_ssh_target "$TARGET_IP")
CURRENT_SSH_OPTS=$(get_ssh_opts "$TARGET_IP")

echo "=== Finalize: Post-Boot Configuration ==="
echo "  Target IP: $TARGET_IP"
echo "  User: $PROVISION_USER"

SERVER_IPV4_VALUE="${SERVER_IPV4:-}"
SERVER_IPV6_NET_VALUE="${SERVER_IPV6_NET:-}"
NETBIRD_SETUP_KEY_VALUE="${NETBIRD_SETUP_KEY:-}"
WARP_TUNNEL_VALUE="${WARP_TUNNEL:-n}"
WARP_TUNNEL_MODE_VALUE="${WARP_TUNNEL_MODE:-proxy}"
SUDO_NOPASSWD_VALUE="${SUDO_NOPASSWD:-n}"

# Compute ::1 address from the prefix (Hetzner convention)
IPV6_ADDR=""
if [ -n "$SERVER_IPV6_NET_VALUE" ]; then
    IPV6_ADDR="${SERVER_IPV6_NET_VALUE%%/*}1"
fi

# Run all post-boot tasks in one remote sudo bash session.
# Note: the remote script contains lots of `$(...)` command substitutions.
# If we use an unquoted heredoc, those would execute locally before SSH runs.
# shellcheck disable=SC2086
{
    printf 'PROVISION_USER=%q\n' "$PROVISION_USER"
    printf 'SERVER_IPV4=%q\n' "$SERVER_IPV4_VALUE"
    printf 'SERVER_IPV6_NET=%q\n' "$SERVER_IPV6_NET_VALUE"
    printf 'IPV6_ADDR=%q\n' "$IPV6_ADDR"
    printf 'NETBIRD_SETUP_KEY=%q\n' "$NETBIRD_SETUP_KEY_VALUE"
    printf 'WARP_TUNNEL=%q\n' "$WARP_TUNNEL_VALUE"
    printf 'WARP_TUNNEL_MODE=%q\n' "$WARP_TUNNEL_MODE_VALUE"
    printf 'SUDO_NOPASSWD=%q\n' "$SUDO_NOPASSWD_VALUE"

    cat <<'EOF'
set -eo pipefail

log() {
    echo "[finalize] $*"
}

log "Starting post-boot finalization"

# 1) Persistent IPv6
if [ -n "$SERVER_IPV6_NET" ]; then
    log "Ensuring persistent IPv6: $IPV6_ADDR"

    current_ipv6=$(ip -6 addr show enp1s0 2>/dev/null | awk '/global/ {print $2; exit}')
    if [ "$current_ipv6" = "$IPV6_ADDR/64" ]; then
        log "IPv6 already configured ($current_ipv6)"
    else
        active_con=$(nmcli -t -f NAME connection show --active | grep -vE '^(lo|docker|wt)' | head -n1 || true)
        if [ -z "$active_con" ]; then
            echo "ERROR: Could not determine active NetworkManager connection" >&2
            exit 1
        fi

        nmcli con mod "$active_con" ipv6.method manual ipv6.addresses "$IPV6_ADDR/64" ipv6.gateway "fe80::1"
        nmcli con up "$active_con"
        log "IPv6 configured via NM connection: $active_con"
    fi
fi

# 2) System updates + base packages
log "Updating packages (dnf upgrade)"
dnf upgrade -y

log "Installing base dev packages"
dnf install -y dnf-plugins-core git ripgrep make python3-devel gcc clang

if [ -z "$SERVER_IPV4" ] && [[ "${WARP_TUNNEL:-n}" =~ ^[Nn]$ ]]; then
    log "IPv6-only without WARP: GitHub downloads may fail"
fi

# 3) Optional IPv4 tunneling via WARP
if [[ "${WARP_TUNNEL:-n}" =~ ^[Yy]$ ]]; then
    if [ "${WARP_TUNNEL_MODE:-proxy}" = "warp" ]; then
        log "Setting up Cloudflare WARP (warp mode)"
        dnf config-manager --add-repo https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo
        dnf install -y cloudflare-warp
        systemctl enable --now warp-svc

        for _ in {1..30}; do
            [ -S /run/cloudflare-warp/warp_service ] && break
            sleep 1
        done

        warp-cli --accept-tos registration new >/dev/null 2>&1 || true
        warp-cli --accept-tos mode warp >/dev/null 2>&1 || true
        warp-cli --accept-tos connect >/dev/null 2>&1 || true
        warp-cli --accept-tos status >/dev/null 2>&1 || true
    else
        log "Setting up WARP + tun2socks (proxy mode)"
        dnf config-manager --add-repo https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo
        dnf install -y cloudflare-warp
        systemctl enable --now warp-svc

        for _ in {1..30}; do
            [ -S /run/cloudflare-warp/warp_service ] && break
            sleep 1
        done

        warp-cli --accept-tos registration new >/dev/null 2>&1 || true
        warp-cli --accept-tos mode proxy >/dev/null 2>&1 || true
        warp-cli --accept-tos connect >/dev/null 2>&1 || true

        # tun2socks may not be installed yet; install it via the WARP SOCKS proxy.
        if ! command -v tun2socks >/dev/null 2>&1; then
            for _ in {1..30}; do
                ss -tln 2>/dev/null | grep -q '127.0.0.1:40000' && break
                sleep 1
            done

            mkdir -p /usr/local/bin
            curl -x socks5h://127.0.0.1:40000 -L -o /tmp/tun2socks.zip https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-linux-amd64.zip
            unzip -o /tmp/tun2socks.zip -d /tmp
            install -m 0755 /tmp/tun2socks-linux-amd64 /usr/local/bin/tun2socks
        fi

        systemctl daemon-reload
        systemctl enable --now warp-tun2socks.service

        # Fail if IPv4 still doesn't work.
        curl --connect-timeout 10 -I https://github.com >/dev/null
    fi
fi

# 4) Dev tooling (network required)

# GitHub CLI (gh) via official repo
if ! command -v gh >/dev/null 2>&1; then
    log "Installing GitHub CLI (gh)"
    dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
    dnf install -y gh
fi

# uv (Python packaging) - per-user install
if ! sudo -u "$PROVISION_USER" bash -lc '[ -x "$HOME/.local/bin/uv" ]'; then
    log "Installing uv"
    sudo -u "$PROVISION_USER" bash -lc 'curl -fsSL https://astral.sh/uv/install.sh | sh'
fi

# OpenCode CLI - per-user install
if ! sudo -u "$PROVISION_USER" bash -lc '[ -x "$HOME/.opencode/bin/opencode" ]'; then
    log "Installing OpenCode"
    sudo -u "$PROVISION_USER" bash -lc 'curl -fsSL https://opencode.ai/install | bash'
fi

# fnm + Node.js v24 - per-user install
# Install fnm for the provisioned user only.
if ! sudo -u "$PROVISION_USER" bash -lc '[ -x "$HOME/.local/share/fnm/fnm" ] || command -v fnm >/dev/null 2>&1'; then
    log "Installing fnm"
    sudo -u "$PROVISION_USER" bash -lc 'curl -fsSL https://fnm.vercel.app/install | bash'
fi

# Install Node 24 for the provisioned user only.
if ! sudo -u "$PROVISION_USER" bash -lc 'export PATH="$HOME/.local/share/fnm:$PATH"; command -v fnm >/dev/null 2>&1 && eval "$(fnm env)" && fnm list 2>/dev/null | grep -q "^v24"'; then
    log "Installing Node.js v24 via fnm"
    sudo -u "$PROVISION_USER" bash -lc 'export PATH="$HOME/.local/share/fnm:$PATH"; command -v fnm >/dev/null 2>&1 && eval "$(fnm env)" && fnm install 24 && fnm default 24'
fi

# Configure interactive shells for fnm (provisioned user only, idempotent)
if ! sudo -u "$PROVISION_USER" bash -lc 'grep -q "^# fnm$" ~/.bashrc 2>/dev/null'; then
    log "Enabling fnm in ~/.bashrc"
    sudo -u "$PROVISION_USER" bash -lc 'cat >> ~/.bashrc <<'\''FNMRC'\''

# fnm
FNM_PATH="$HOME/.local/share/fnm"
if [ -d "$FNM_PATH" ]; then
    export PATH="$FNM_PATH:$PATH"
    eval "$(fnm env)"
fi
FNMRC'
fi

if ! sudo -u "$PROVISION_USER" bash -lc 'grep -q "^# fnm$" ~/.zshrc 2>/dev/null'; then
    log "Enabling fnm in ~/.zshrc"
    sudo -u "$PROVISION_USER" bash -lc 'cat >> ~/.zshrc <<'\''FNMRC'\''

# fnm
FNM_PATH="$HOME/.local/share/fnm"
if [ -d "$FNM_PATH" ]; then
    export PATH="$FNM_PATH:$PATH"
    eval "$(fnm env)"
fi
FNMRC'
fi

# 1Password CLI
if ! command -v op >/dev/null 2>&1; then
    log "Installing 1Password CLI"

    op_arch=$(uname -m)
    case "$op_arch" in
        x86_64|aarch64|armv7l|i386)
            ;;
        *)
            echo "ERROR: Unsupported architecture for 1Password CLI: $op_arch" >&2
            exit 1
            ;;
    esac

    dnf install -y "https://downloads.1password.com/linux/rpm/stable/$op_arch/1password-cli-latest.$op_arch.rpm"
fi

# 5) Optional NetBird (FAIL provisioning if requested and not connected)
if [ -n "$NETBIRD_SETUP_KEY" ]; then
    log "Installing NetBird via DNF"

    cat > /etc/yum.repos.d/netbird.repo <<'NBREPO'
[netbird]
name=netbird
baseurl=https://pkgs.netbird.io/yum/
enabled=1
gpgcheck=0
gpgkey=https://pkgs.netbird.io/yum/repodata/repomd.xml.key
repo_gpgcheck=1
NBREPO

    dnf install -y netbird
    systemctl enable --now netbird >/dev/null 2>&1 || true

    log "Registering NetBird (netbird up)"
    if ! netbird up --setup-key "$NETBIRD_SETUP_KEY"; then
        # Retry once with WARP warp-mode if:
        # - server is IPv6-only
        # - WARP tunneling is enabled
        # - not already in warp mode
        if [ -z "$SERVER_IPV4" ] && [[ "${WARP_TUNNEL:-n}" =~ ^[Yy]$ ]] && [ "${WARP_TUNNEL_MODE:-proxy}" != "warp" ]; then
            log "NetBird up failed; retrying with WARP mode 'warp'"

            dnf config-manager --add-repo https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo
            dnf install -y cloudflare-warp
            systemctl enable --now warp-svc

            for _ in {1..30}; do
                [ -S /run/cloudflare-warp/warp_service ] && break
                sleep 1
            done

            warp-cli --accept-tos registration new >/dev/null 2>&1 || true
            warp-cli --accept-tos mode warp >/dev/null 2>&1 || true
            warp-cli --accept-tos connect >/dev/null 2>&1 || true

            netbird up --setup-key "$NETBIRD_SETUP_KEY"
        else
            echo "ERROR: NetBird registration failed" >&2
            exit 1
        fi
    fi

    log "Waiting for NetBird to report Connected"
    for _ in {1..24}; do
        if netbird status 2>/dev/null | grep -E 'Status:.*Connected|Connected' >/dev/null 2>&1; then
            break
        fi
        sleep 5
    done

    if ! netbird status 2>/dev/null | grep -E 'Status:.*Connected|Connected' >/dev/null 2>&1; then
        echo "ERROR: NetBird is installed but not connected" >&2
        netbird status || true
        exit 1
    fi

    log "NetBird is connected"
fi

# 6) Optional sudo hardening
if [[ "${SUDO_NOPASSWD:-n}" =~ ^[Nn]$ ]]; then
    log "Hardening sudo (removing NOPASSWD)"
    sed -i 's/ NOPASSWD://' /etc/sudoers.d/wheel
fi

# Final sanity checks
log "Verifying Docker"
docker --version >/dev/null

log "Finalization complete"
EOF
} | $SSH_CMD $CURRENT_SSH_OPTS "$PROVISION_USER@$SSH_TARGET" "sudo bash -se"
