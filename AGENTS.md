# Agent Guidelines: Hetzner FDE Provisioning Toolkit

This document provides instructions and guidelines for agentic coding agents operating in this repository.

## Project Overview

This project is a collection of Bash scripts designed to automate the deployment of RHEL-family Linux (Rocky/Alma/CentOS Stream) with Full Disk Encryption (FDE) on Hetzner Cloud. It leverages Hetzner's `installimage` tool and `dracut-sshd` for remote LUKS unlocking.

## Where to find human usage docs

Humans should read `README.md` for usage examples and operational notes.

This file (`AGENTS.md`) is the single source of truth for coding agents: repo conventions, pitfalls, and how to validate changes.

## Build, Lint, and Test Commands

### 1. Testing (End-to-End)
To run the full provisioning flow (install + boot unlock + post-boot finalization):
```bash
export HCLOUD_TOKEN="your-api-token"
# Get key from ssh-agent (recommended)
export USER_SSH_KEY="$(ssh-add -L | grep 'your-key-name' | head -n1)"
export UNLOCK_SSH_KEY="$USER_SSH_KEY"
# Or provide key directly (can be multiple newline-separated keys)
# export USER_SSH_KEY="ssh-ed25519 AAAA..."
# Required: Set username to create
export PROVISION_USER="your-username"
# Optional: Install and connect NetBird (fails provisioning if not connected)
# export NETBIRD_SETUP_KEY="your-setup-key"
./test-provision-flow.sh <server_name_or_id>
```
*Note: This script is destructive and will wipe the target server.*

**Non-Interactive Mode Notes:** `test-provision-flow.sh` pipes output through `tee`, making stdin non-TTY. The provisioning script automatically:
- Skips the NetBird prompt (defaults to empty, unless `NETBIRD_SETUP_KEY` is explicitly set)
- Skips the sudo prompt (uses `SUDO_NOPASSWD` env var or defaults to `n`)
- Skips the IPv4 tunneling prompt (uses `WARP_TUNNEL` env var or defaults to `n`)
- Skips the 1Password vault prompt (defaults to "skip", unless `OP_VAULT_REF` is explicitly set)
- Skips the 1Password overwrite prompt (defaults to "no", unless `OP_OVERWRITE_EXISTING` is explicitly set)
- Uses `FORCE_IMAGE` if set; otherwise prefers `Rocky-10-latest-*` (then any `*-10-latest-*`/`CentOS-1000-*` match) and finally falls back to the first available image

The provisioning flow always runs:
- `monitor-boot.sh` to handle initramfs unlock (including SELinux relabel reboot)
- `finalize.sh` to apply post-boot configuration (IPv6 persistence, optional WARP, optional NetBird, sudo hardening)

**Keep the authoritative list of prompt-skipping env vars in `provision.sh`:**
If you add a new prompt to `provision.sh`, update the non-interactive behavior so automation stays reliable.

### 2. Unit/Component Testing
To test specific parts of the workflow without a full re-provision:
- **Boot Monitor (Unlock + Wait):** `./monitor-boot.sh <primary_ip> <luks_password> <username> [secondary_ipv6]`
  - For dual-stack servers: use IPv4 as primary_ip, IPv6 as secondary
  - For IPv6-only servers: use IPv6 as primary_ip, leave secondary empty
- **Post-Boot Finalization:** `./finalize.sh <primary_ip> <username> [secondary_ipv6]`
  - Requires env vars from `provision.sh` (e.g. `SERVER_IPV6_NET`, optional `NETBIRD_SETUP_KEY`)
- **SSH Connectivity:** `source wait_for_ssh.sh && wait_for_ssh <user> <target> [max_connect_wait] [max_login_attempts]`
- **IPv6 Update:** `sudo /usr/local/bin/update-boot-ipv6` (on the target VM)

### 3. Linting
Use `shellcheck` for all scripts:
```bash
shellcheck *.sh
```

### 4. Build
There is no build step. Scripts are executed directly.

## Code Style & Conventions

### 1. General Bash Rules
- Use `#!/bin/bash` as the shebang.
- Use `set -e` or `set -eo pipefail` at the start of scripts to ensure failures stop execution.
- Use `SCRIPT_DIR=$(dirname "$0")` to resolve absolute paths for sourcing or referencing files in the same repo.
- Indentation: 4 spaces.

### 2. Variables and Naming
- **Global Variables:** `UPPER_CASE_WITH_UNDERSCORES` (e.g., `SERVER_IP`, `LUKS_PASSWORD`).
- **Local Variables:** `lower_case_with_underscores` (e.g., `local attempt=1`).
- **Functions:** `snake_case` (e.g., `wait_for_ssh`, `unlock_luks`).

### 3. Error Handling
- Always check if critical variables are set:
  ```bash
  if [ -z "$HCLOUD_TOKEN" ]; then
      echo "Error: HCLOUD_TOKEN is not set."
      exit 1
  fi
  ```
- `provision.sh` validates required local tools at startup; if you add new external commands to `provision.sh` (or to any script it runs/sources, e.g. `wait_for_ssh.sh`, `post-install.sh`, `monitor-boot.sh`), update the required-tools list so the script fails fast with a clear error.
- Provide clear error messages before exiting.

### 4. SSH & Networking
- Use `wait_for_ssh.sh` for all connectivity checks. It handles the TCP port-open wait separately from login attempts.
- **IPv6 Handling:** Do NOT use brackets around IPv6 addresses in SSH commands (zsh glob expansion issues). Instead use the `-6` flag:
  ```bash
  # CORRECT: Use -6 flag without brackets
  ssh -6 root@2a01:4f9:c011:bbfc::1 "echo test"
  
  # WRONG: Brackets cause zsh glob expansion errors
  ssh root@[2a01:4f9:c011:bbfc::1] "echo test"
  ```
- Default SSH options for automation:
  ```bash
  SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes"
  # Add -6 for IPv6: SSH_OPTS="$SSH_OPTS -6"
  ```

### 5. Interaction with Hetzner
- Prefer `hcloud` CLI for infrastructure management.
- When enabling rescue mode or rebooting, always use `wait_for_ssh` to verify the system is ready before proceeding.
- Interface naming:
    - `initramfs` (boot): Use `eth0` as it is the most consistent name across Hetzner architectures in early boot.
    - OS (RHEL-family): Use `enp1s0` for NetworkManager configuration.

### 6. File Operations
- Use `cat << EOF` for multi-line file generation.
- When modifying configuration files (like GRUB or NetworkManager), prefer tools like `grubby` or `nmcli` over direct `sed` where possible.
- If using `sed` to update GRUB, ensure you target both BIOS (`/boot/grub2/grub.cfg`) and UEFI/BLS (`/boot/loader/entries/*.conf`) paths if applicable.

## Common Pitfalls & Lessons Learned

### 1. Boot Stages and `monitor-boot.sh`
- **Context-Specific:** `monitor-boot.sh` is strictly for the **first-time provisioning flow**. Do NOT use it on a server that is already fully provisioned and configured.
- **Root Access:** In `initramfs`, `root` login is allowed via SSH keys. In the final OS, `PermitRootLogin` is disabled. The script detects this transition by checking if the provisioned user can log in.
- **State Flow:** The script handles First Boot -> (optional) SELinux Relabel Reboot -> Second Boot -> OS. It detects the OS boot by checking for user login capability.
- **LUKS Unlock Mechanism:** Uses `systemd-reply-password` to send the passphrase to the ask-password socket:
  ```bash
  # Find the socket
  socket_path=$(ssh root@host 'bash -lc '\''for s in /run/systemd/ask-password/sck.*; do [ -S "$s" ] || continue; echo "$s"; break; done'\''')
  # Send password via stdin
  ssh root@host "/usr/lib/systemd/systemd-reply-password 1 '$socket_path'" <<< "$LUKS_PASS"
  ```
  **Important:** The old method (`systemd-tty-ask-password-agent --query`) does NOT work in this initramfs environment.

### 2. Infrastructure Management (`hcloud`)
- **Documentation:**
    - Main Docs: https://github.com/hetznercloud/cli/tree/main/docs
    - Command Reference: https://github.com/hetznercloud/cli/tree/main/docs/reference/manual
- **Power Operations:**
    - DO NOT use `hcloud server stop` or `start`; use `hcloud server poweroff` and `hcloud server poweron` if needed.
    - For reboots, ALWAYS prefer `hcloud server reset` (hard reset) when the system is stuck or at the LUKS screen, as `hcloud server reboot` (soft) may be ignored by a hung `initramfs`.
- **Rescue Mode Activation:** `hcloud server enable-rescue` only sets the boot flag. It rarely triggers an immediate reboot into rescue. Always follow it with a `hcloud server reset` and a connectivity check.
- **Verify Rescue State:** Always verify the rescue flag is active using `hcloud server describe <id> -o json | jq -r .rescue_enabled` before waiting for SSH.
- **NFS Mounts:** In Hetzner Rescue, `/root/images` is an NFS mount. If you don't see images, check `mount | grep nfs`.

### 3. Networking & Interface Naming
- **The "eth0" vs "enp1s0" Trap:** 
    - **Boot (`initramfs`):** RHEL-family with predictable names may use `enp1s0` even in initramfs.
    - **OS (RHEL-family):** Uses `enp1s0` for NetworkManager configuration.
- **Atomic NM Updates:** When modifying networking over SSH, use atomic commands. 
    - *Bad:* `nmcli con delete "Wired Connection" && nmcli con add ...` (kills the connection).
    - *Good:* `nmcli con mod "$UUID" ... && nmcli con up "$UUID"` (updates existing connection).
- **Metadata Parsing:** When querying the Hetzner Metadata service (`169.254.169.254`), be specific with `grep`. MAC addresses and IPv6 addresses look similar; always match the key (e.g., `address:`) to avoid capturing the MAC.

### 3a. IPv6 Kernel Boot Arguments (Critical)
RHEL-family (Rocky/Alma/CentOS Stream) uses NetworkManager in initramfs via `nm-initrd-generator`. The `ip=` kernel argument format is critical for dual-stack (IPv4 + IPv6) configuration.

- **WRONG format (will fail):**
  ```
  ip=dhcp ip=[2a01:4f8:c014:ec74::1]::fe80::1%enp1s0:64:hostname:enp1s0:none
  ```
  Problems: 
  - Two separate `ip=` parameters create conflicting NM connection profiles
  - The `%interface` scope identifier in the gateway is not supported
  - Results in "Unknown kernel command line parameters" in dmesg

- **CORRECT format (combined IPv4 DHCP + IPv6 static):**
  ```
  ip=[2a01:4f8:c014:ec74::1]::[fe80::1]:64:hostname:enp1s0:dhcp
  ```
  This single parameter tells `nm-initrd-generator` to create one connection with:
  - `ipv4.method=auto` (DHCP) - from the `:dhcp` suffix
  - `ipv6.method=manual` with static address and gateway
  - `ipv6.gateway=fe80::1` - Hetzner's standard link-local gateway

- **IPv6-only format (no IPv4):**
  ```
  ip=[2a01:4f8:c014:ec74::1]::[fe80::1]:64:hostname:enp1s0:none
  ```
  Use `:none` suffix instead of `:dhcp` to disable IPv4 entirely. This tells NetworkManager:
  - `ipv4.method=disabled` (none)
  - `ipv6.method=manual` with static address and gateway

- **Testing the format:** Use `nm-initrd-generator -s` on the target system to verify:
  ```bash
  /usr/libexec/nm-initrd-generator -s -- 'ip=[IPv6]::[fe80::1]:64:hostname:iface:dhcp'
  ```
  This shows the NetworkManager connection profile that will be generated.

- **Verification in initramfs:** After boot, check:
  ```bash
  ip -6 addr show enp1s0  # Should show global IPv6 address
  ip -6 route             # Should show default via fe80::1
  ```

### 4. SSH Debugging
- **Agent Verification:** Always verify that the key provided in `UNLOCK_SSH_KEY` is currently loaded in the local SSH agent (`ssh-add -l`).
- **Wait Logic:** SSH connectivity is two-stage. Use `nc -z` to check the TCP port before attempting a login. High-frequency login attempts can trigger rate-limiting or `fail2ban`.
- **Key Mismatch:** `Permission denied (publickey)` during boot usually means the `dracut-sshd` module failed to include the key in the `initramfs` image during the `post-install.sh` phase.

### 5. Initramfs Environment Limitations
- **Missing utilities:** In initramfs on Rocky 10, many basic tools aren't present (`head`, `socat`, `cryptsetup` binary may differ).
- **Shell:** Remote login shell can be `zsh`, so globbing like `sck.*` can error; use `bash -lc` explicitly for commands that rely on bash behavior.
- **Variable expansion:** Any ssh command string containing `$s` / `$var` inside double quotes will expand locally unless escaped. Use single-quote wrapping for remote commands that need shell expansion on the remote side.

### 5a. Heredocs Over SSH (Critical)
- **Always quote heredocs that feed remote shells.** If the content contains command substitutions like `$(...)`, an unquoted heredoc will execute them *locally* before `ssh` runs.
  - Prefer: `cat <<'EOF' | ssh ... "bash -se"`
  - Avoid: `ssh ... "bash -se" <<EOF` when the body contains `$(...)`.
- If you need to pass variables into a quoted heredoc, print them as shell assignments first (e.g., `printf 'FOO=%q\n' "$FOO"`) and then append the quoted heredoc.

### 5b. installimage Mount Points (Copying Files)
- **Do not assume installimage will leave the target filesystem mounted at `/mnt` after completion.** In some rescue environments `/mnt` may be empty immediately after `installimage` returns.
- Prefer installing helper utilities (like `update-boot-ipv6`) from inside `post-install.sh` (chroot context) rather than trying to copy into `/mnt/usr/local/bin` from the rescue host.

### 5c. E2E Testing Timeouts
- E2E runs can take longer than 10 minutes due to `dnf upgrade` and dev tooling installs in `finalize.sh`. If your harness has a command timeout, re-run `./finalize.sh <ip> <user> [ipv6]` after the VM is reachable to complete provisioning.
- When validating in a non-interactive environment, prefer checks that don't require sudo (`docker --version`, `netbird status`, presence of `/usr/local/bin/update-boot-ipv6`).
  - Root login is disabled in the final OS; validate via the provisioned user.
  - If `SUDO_NOPASSWD=n`, avoid sudo-based validation unless you explicitly provide a password via `sudo -S`.

### 6. Firewall & Connectivity
- **ICMP (Ping):** Hetzner's external firewall may have ICMP Echo disabled. Do NOT rely on `ping` to check if a server is up. Always use `nc -z` or `ssh` with a short timeout.
- **Port 22:** Ensure the Hetzner Firewall allows incoming TCP/22 for both your local IP (IPv4 and IPv6).

### 7. IPv6-Only Server Limitations
- **No NAT64 by default:** Hetzner Cloud does not provide NAT64/DNS64 by default. IPv6-only servers cannot reach IPv4-only hosts (like GitHub).
- **Optional IPv4 tunneling via WARP:** The toolkit can enable IPv4 tunneling on IPv6-only servers using Cloudflare WARP.
  - Set `WARP_TUNNEL=y` to enable, or leave unset / `n` to skip.
  - **Modes:**
    - `WARP_TUNNEL_MODE=proxy`: WARP SOCKS proxy + `tun2socks` (TCP-only IPv4). Policy routing sends IPv4 to a `tun0` TUN; IPv6 routing stays unchanged.
    - `WARP_TUNNEL_MODE=warp`: WARP full-tunnel mode (UDP-capable IPv4). Prefer this when running NetBird on IPv6-only.

#### WARP troubleshooting (proxy mode)

If you enabled `WARP_TUNNEL=y` on an IPv6-only server and IPv4 connectivity is not working, these are the most common checks.

1. Check that WARP is connected and SOCKS is listening:
   ```bash
   sudo systemctl status warp-svc --no-pager
   warp-cli --accept-tos status

   # If status says "Registration Missing", register once:
   warp-cli --accept-tos registration new

   ss -tlnp | grep 40000
   ```

2. Check that tun2socks is running and the policy route is present:
   ```bash
   sudo systemctl status warp-tun2socks.service --no-pager
   ip link show tun0
   ip rule list | head -20
   ip route show table 100
   ```
   Expected: `default dev tun0` in table `100`.

3. Verify the recursion-avoidance exclude list is applied:

   The service prevents WARP from “tunneling into itself” by adding `unreachable` routes (in routing table `100`) for WARP’s own IPv4 endpoint(s) and common private ranges.

   ```bash
   # The raw WARP endpoints come from this file:
   sudo jq -r '.endpoints[].v4' /var/lib/cloudflare-warp/conf.json

   # The service builds its exclude list here at runtime:
   sudo cat /run/warp-tun2socks/exclude_v4

   # The applied result should show up as unreachable routes in table 100:
   ip route show table 100 | head -50
   ```

   Expected: `unreachable <warp-endpoint-ip>/32` entries (and private ranges like `10.0.0.0/8`).

4. Test IPv4 without per-app proxy config:
   ```bash
   curl --connect-timeout 10 http://example.com
   curl --connect-timeout 10 -I https://github.com
   ```

5. Check logs:
   ```bash
   sudo journalctl -u warp-svc -n 50 --no-pager
   sudo journalctl -u warp-tun2socks.service -n 50 --no-pager
   ```

6. Understand UDP limitations:
   - WARP SOCKS does not support `UDP ASSOCIATE`.
   - You may see log lines like `UDP ASSOCIATE: command not supported`.
   - TCP IPv4 (most package downloads, HTTPS, git over HTTPS) should work fine.

#### WARP recursion / "lockout" symptoms

If WARP gets stuck in `Connecting`, or `ss -tlnp | grep 40000` shows no listener, it can mean traffic is being routed “into itself”. This setup mitigates that by adding WARP endpoint IPv4s as `unreachable` routes in routing table `100`.

If you need to recover quickly:
```bash
sudo systemctl stop warp-tun2socks.service
warp-cli --accept-tos disconnect
warp-cli --accept-tos mode proxy
warp-cli --accept-tos connect
```

#### Disable IPv4 tunneling

To disable the system-wide IPv4 tunnel (and go back to IPv6-only behavior):

```bash
# Stop and disable the tunnel
sudo systemctl disable --now warp-tun2socks.service

# Optional: keep WARP installed but stop it too
sudo systemctl disable --now warp-svc

# Remove the policy routing table (best-effort)
sudo ip rule del pref 1000 2>/dev/null || true
sudo ip route flush table 100 2>/dev/null || true

# Verify that plain IPv4 no longer works
curl --connect-timeout 5 -I https://github.com || true
```

#### Re-enable IPv4 tunneling

If WARP + tun2socks are already installed (you only disabled them), re-enable with:

```bash
sudo systemctl enable --now warp-svc
sudo systemctl enable --now warp-tun2socks.service

# Verify
warp-cli --accept-tos status
ip route show table 100
curl --connect-timeout 10 -I https://github.com
```

- **NetBird installation:** The install script (`pkgs.netbird.io/install.sh`) redirects to GitHub releases which doesn't support IPv6. Use the DNF repo method instead (see `finalize.sh`).
- **Package downloads:** Some package repositories may not support IPv6. Check IPv6 support before relying on external downloads in scripts.
