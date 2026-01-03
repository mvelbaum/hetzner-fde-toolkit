#!/bin/bash
set -e

# This script is executed inside the chroot by the main orchestrator.
exec > /root/post-install.log 2>&1
echo "Starting post-install configuration..."

# 1. Enable EPEL and CRB (needed for Rocky 10)
echo "Installing EPEL and CRB..."
dnf config-manager --set-enabled crb || true
dnf install -y epel-release

# 2. Install necessary packages
echo "Installing core packages..."
dnf install -y dracut-sshd dracut-network grubby fail2ban dnf-automatic firewalld curl jq unzip

# Ensure update-boot-ipv6 is available on the installed OS.
if [ -n "${UPDATE_BOOT_IPV6_SH:-}" ]; then
    echo "Installing update-boot-ipv6 utility..."
    mkdir -p /usr/local/bin
    printf '%s\n' "$UPDATE_BOOT_IPV6_SH" > /usr/local/bin/update-boot-ipv6
    chmod 0755 /usr/local/bin/update-boot-ipv6
fi

# 2.1 Install Docker
echo "Installing Docker..."
dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 2.2 Configure Security Services
echo "Configuring security services..."
# Auto-updates
sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
systemctl enable dnf-automatic.timer

# Fail2ban
systemctl enable fail2ban

# Firewalld
systemctl enable firewalld
echo "Configuring offline firewall rules..."
firewall-offline-cmd --zone=public --add-service=ssh
firewall-offline-cmd --zone=public --add-service=https

# Docker
systemctl enable docker

# 3. Setup user
echo "Configuring user '$PROVISION_USER'..."
if ! id "$PROVISION_USER" &>/dev/null; then
    useradd -m -G wheel,docker "$PROVISION_USER"
fi
echo "$PROVISION_USER:$USER_PASSWORD" | chpasswd
mkdir -p /home/"$PROVISION_USER"/.ssh
echo "$USER_SSH_KEY" > /home/"$PROVISION_USER"/.ssh/authorized_keys
chmod 700 /home/"$PROVISION_USER"/.ssh
chmod 600 /home/"$PROVISION_USER"/.ssh/authorized_keys
chown -R "$PROVISION_USER":"$PROVISION_USER" /home/"$PROVISION_USER"/.ssh

# Set root password for console access
echo "Setting root password..."
echo "root:$ROOT_PASSWORD" | chpasswd

# Allow wheel to sudo WITHOUT password initially (for orchestrator)
echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/wheel

# 4. Setup dracut-sshd for remote unlock
echo "Configuring dracut-sshd..."
echo "DEBUG: UNLOCK_SSH_KEY length is ${#UNLOCK_SSH_KEY}"
mkdir -p /root/.ssh
echo "$UNLOCK_SSH_KEY" > /root/.ssh/dracut_authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/dracut_authorized_keys

if [ ! -s /root/.ssh/dracut_authorized_keys ]; then
    echo "ERROR: dracut_authorized_keys is empty!"
    exit 1
fi

# Fix Dracut Config (ensure spaces and explicit file inclusion)
# We overwrite any existing conf to ensure clean state
echo 'add_dracutmodules+=" network sshd "' > /etc/dracut.conf.d/ssh-unlock.conf
echo 'install_items+=" /root/.ssh/dracut_authorized_keys /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_ecdsa_key "' >> /etc/dracut.conf.d/ssh-unlock.conf

# 5. Configure Kernel Parameters
echo "Configuring GRUB..."
udevadm settle
# Find the LUKS partition
LUKS_PART=$(blkid | grep 'TYPE="crypto_LUKS"' | cut -d: -f1 | head -n1)
if [ -z "$LUKS_PART" ]; then
    # Fallback detection
    LUKS_PART=$(pvs --noheadings -o pv_name | tr -d ' ' | head -n1)
fi
LUKS_UUID=$(blkid -s UUID -o value "$LUKS_PART")

echo "Configuring GRUB with LUKS UUID: $LUKS_UUID"
# Determine interface for static IPv6
# On Hetzner Cloud, enp1s0 is the standard predictable interface name
IFACE="enp1s0"
# Fallback to detecting the first non-loopback interface if enp1s0 is missing
if ! ip link show "$IFACE" &>/dev/null; then
    IFACE=$(ip -o link show | grep -v lo | head -n1 | awk -F': ' '{print $2}')
fi

IP_ARGS="rd.neednet=1"
if [ -n "$SERVER_IPV6_ADDR" ] && [ -n "$SERVER_IPV4" ]; then
    # Dual-stack: Combined IPv4 DHCP + IPv6 static format for NetworkManager in initramfs:
    # ip=[ipv6-addr]::[ipv6-gw]:prefix:hostname:interface:dhcp
    # - Sets ipv6.method=manual with the static address and gateway
    # - Sets ipv4.method=auto (DHCP) on the same interface
    # - The gateway fe80::1 is Hetzner's standard link-local gateway
    echo "Adding dual-stack boot arguments: IPv4 DHCP + IPv6 static $SERVER_IPV6_ADDR (via $IFACE)"
    IP_ARGS="$IP_ARGS ip=[${SERVER_IPV6_ADDR}]::[fe80::1]:64:$(hostname):${IFACE}:dhcp"
elif [ -n "$SERVER_IPV6_ADDR" ]; then
    # IPv6-only: Use 'none' for IPv4 method
    # ip=[ipv6-addr]::[ipv6-gw]:prefix:hostname:interface:none
    # - Sets ipv6.method=manual with the static address and gateway
    # - Sets ipv4.method=disabled (none)
    echo "Adding IPv6-only boot arguments: $SERVER_IPV6_ADDR (via $IFACE)"
    IP_ARGS="$IP_ARGS ip=[${SERVER_IPV6_ADDR}]::[fe80::1]:64:$(hostname):${IFACE}:none"
else
    # IPv4-only fallback
    echo "Adding IPv4-only boot arguments: DHCP"
    IP_ARGS="$IP_ARGS ip=dhcp"
fi

grubby --update-kernel=ALL --args="$IP_ARGS rd.luks.uuid=${LUKS_UUID}"

# 6. Rebuild initramfs
# Important: We must target the INSTALLED kernel, not the running RESCUE kernel.
KERNEL_VERSION=
for kernel_path in /boot/vmlinuz-*; do
    kernel_base=$(basename "$kernel_path")
    if [[ "$kernel_base" != *rescue* ]]; then
        KERNEL_VERSION=${kernel_base#vmlinuz-}
        break
    fi
done

if [ -z "$KERNEL_VERSION" ]; then
    echo "ERROR: Could not determine installed kernel version." >&2
    exit 1
fi
echo "Rebuilding initramfs for kernel: $KERNEL_VERSION"

dracut -f -v --kver "$KERNEL_VERSION"

# 7. Harden SSH in the real OS
echo "Hardening SSH configuration..."
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Ensure we actually wrote it if it wasn't there
if ! grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
fi

# 8. Optional: IPv4 tunneling on IPv6-only servers.
#
# Modes:
# - proxy: WARP SOCKS proxy + tun2socks (TCP-only for IPv4)
# - warp:  WARP full-tunnel mode (UDP-capable IPv4, better for NetBird)
#
# Must be installed/configured in the running OS (not in chroot).
# For proxy mode, we drop a helper script + systemd unit, and let finalize.sh enable it post-boot.
if [[ "${WARP_TUNNEL:-n}" =~ ^[Yy]$ ]] && [ "${WARP_TUNNEL_MODE:-proxy}" = "proxy" ]; then
    echo "Staging Cloudflare WARP + tun2socks for IPv4 tunneling..."

    cat > /usr/local/sbin/warp-tun2socks-pre.sh <<'EOF'
#!/bin/bash
set -eo pipefail

WARP_SOCKS_ADDR="127.0.0.1:40000"
RUNDIR="/run/warp-tun2socks"

mkdir -p "$RUNDIR"

# Make sure WARP is in SOCKS proxy mode and connected.
    systemctl start warp-svc
    # Newer WARP clients require registration before first connect.
    warp-cli --accept-tos registration new >/dev/null 2>&1 || true
    warp-cli --accept-tos mode proxy >/dev/null 2>&1 || true
    warp-cli --accept-tos connect >/dev/null 2>&1 || true


# Wait for SOCKS port
for _ in {1..20}; do
    if ss -tln | grep -q "$WARP_SOCKS_ADDR"; then
        break
    fi
    sleep 1
done

if ! ss -tln | grep -q "$WARP_SOCKS_ADDR"; then
    echo "ERROR: WARP SOCKS5 not listening on $WARP_SOCKS_ADDR" >&2
    exit 1
fi

# Tighten exclude list:
# - WARP IPv4 endpoints from conf.json
# - common fallback endpoints and metadata safety
{
    jq -r '.endpoints[].v4' /var/lib/cloudflare-warp/conf.json 2>/dev/null | sed 's/:.*//'
    # Extra Cloudflare anycast / WARP endpoints (best-effort)
    echo "162.159.198.1"
    echo "162.159.198.2"
    echo "162.159.199.1"
    echo "162.159.199.2"
    echo "162.159.200.1"
    echo "162.159.200.2"
    echo "162.159.201.1"
    echo "162.159.201.2"
    # RFC1918 + link-local safety (do not tunnel private networks)
    echo "10.0.0.0/8"
    echo "172.16.0.0/12"
    echo "192.168.0.0/16"
    echo "169.254.0.0/16"
} | sort -u > "$RUNDIR/exclude_v4"
EOF
    chmod 0755 /usr/local/sbin/warp-tun2socks-pre.sh

    cat > /usr/local/sbin/warp-tun2socks-post.sh <<'EOF'
#!/bin/bash
set -eo pipefail

TUN_DEV="tun0"
TUN_ADDR="10.0.0.2/32"
TABLE_ID=100
RULE_PREF=1000
RUNDIR="/run/warp-tun2socks"

# Wait for tun device
for _ in {1..20}; do
    if ip link show "$TUN_DEV" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! ip link show "$TUN_DEV" >/dev/null 2>&1; then
    echo "ERROR: $TUN_DEV not present" >&2
    exit 1
fi

ip link set "$TUN_DEV" up
ip addr add "$TUN_ADDR" dev "$TUN_DEV" 2>/dev/null || true

# Policy routing: all IPv4 uses table 100
ip rule del pref "$RULE_PREF" 2>/dev/null || true
ip route flush table "$TABLE_ID" 2>/dev/null || true
ip rule add pref "$RULE_PREF" to 0.0.0.0/0 lookup "$TABLE_ID"
ip route replace default dev "$TUN_DEV" table "$TABLE_ID"

# Exclude list from pre-script
ip route replace unreachable 127.0.0.1/32 table "$TABLE_ID"
if [ -f "$RUNDIR/exclude_v4" ]; then
    while read -r entry; do
        [ -n "$entry" ] || continue
        if [[ "$entry" == */* ]]; then
            ip route replace unreachable "$entry" table "$TABLE_ID"
        else
            ip route replace unreachable "$entry/32" table "$TABLE_ID"
        fi
    done < "$RUNDIR/exclude_v4"
fi
EOF
    chmod 0755 /usr/local/sbin/warp-tun2socks-post.sh

    cat > /usr/local/sbin/warp-tun2socks-stop.sh <<'EOF'
#!/bin/bash
set -eo pipefail

TUN_DEV="tun0"
TUN_ADDR="10.0.0.2/32"
TABLE_ID=100
RULE_PREF=1000
RUNDIR="/run/warp-tun2socks"

ip rule del pref "$RULE_PREF" 2>/dev/null || true
ip route flush table "$TABLE_ID" 2>/dev/null || true
ip addr del "$TUN_ADDR" dev "$TUN_DEV" 2>/dev/null || true
ip link del "$TUN_DEV" 2>/dev/null || true
rm -rf "$RUNDIR" 2>/dev/null || true
EOF
    chmod 0755 /usr/local/sbin/warp-tun2socks-stop.sh

    cat > /etc/systemd/system/warp-tun2socks.service <<'EOF'
[Unit]
Description=WARP-backed IPv4 via tun2socks
After=network-online.target warp-svc.service
Wants=network-online.target warp-svc.service
Requires=warp-svc.service

[Service]
Type=simple
ExecStartPre=/usr/local/sbin/warp-tun2socks-pre.sh
ExecStart=/usr/local/bin/tun2socks -device tun://tun0 -proxy socks5://127.0.0.1:40000 -loglevel warning
ExecStartPost=/usr/local/sbin/warp-tun2socks-post.sh
ExecStopPost=/usr/local/sbin/warp-tun2socks-stop.sh
Restart=always
RestartSec=2
TimeoutStartSec=90
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable warp-svc || true
    systemctl enable warp-tun2socks.service || true

    echo "Staged: /etc/systemd/system/warp-tun2socks.service"
fi

# 9. Netbird installation is done post-boot by the provisioner (finalize phase).
# The chroot environment has no reliable network access, so we can't install it here.
echo "Note: Netbird will be installed after first boot (if setup key provided)."

# 9. Final Security Checks
echo "Ensuring SELinux Relabel..."
touch /.autorelabel

# 10. Copy utilities
echo "Copying utilities..."
# We expect the file to be at /tmp/update-boot-ipv6.sh because the provisioner uploads it there
# but installimage runs with /tmp of the rescue system mounted at /mnt/tmp or similar
# Actually, provisioner uploads to /tmp/update-boot-ipv6.sh in rescue.
# We need to reach OUT of the chroot to get it, or use a better upload path.
# For now, we look in /tmp inside the chroot (which should be empty unless we copied it there)
if [ -f /tmp/update-boot-ipv6.sh ]; then
    cp /tmp/update-boot-ipv6.sh /usr/local/bin/update-boot-ipv6
    chmod +x /usr/local/bin/update-boot-ipv6
fi

echo "Post-install configuration complete."
