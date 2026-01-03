# Hetzner FDE Provisioning Toolkit

Automate full disk encryption (LUKS) on Hetzner Cloud with remote SSH unlock capability.

## Overview

Hetzner Cloud provides excellent value for cloud infrastructure, but does not offer platform-managed disk encryption with customer-controlled keys. Their own [data privacy FAQ](https://docs.hetzner.com/general/general-terms-and-conditions/data-privacy-faq/) states that customers are responsible for encrypting data on rented servers.

This toolkit solves that problem by automating:

- **Full disk encryption** using LUKS2 + LVM on the root disk
- **Remote unlock via SSH** using `dracut-sshd` (no console access needed)
- **Post-boot hardening** and optional tooling (Docker, NetBird, Cloudflare WARP)

It targets RHEL-family distributions (Rocky Linux, AlmaLinux, CentOS Stream) on Hetzner Cloud.

---

## The `hz` Command

The `hz` tool is the primary way to interact with your encrypted Hetzner VMs after provisioning. It wraps SSH/SCP with automatic LUKS unlock support.

### Installation

Add `hz` to your PATH:

```bash
ln -s "$(pwd)/hz" ~/bin/hz
# or
cp hz /usr/local/bin/hz
```

### Basic Usage

```bash
# SSH into a Hetzner VM (by name or ID)
hz ssh myuser@hetzner-vm

# Run a remote command
hz ssh hetzner-vm 'uptime'

# Copy files to/from the VM
hz scp localfile.txt myuser@hetzner-vm:/tmp/
hz scp myuser@hetzner-vm:/etc/hosts ./hosts-backup
hz scp -r myuser@hetzner-vm:/var/log/ ./logs/
```

### Automatic LUKS Unlock

If the server is waiting at the LUKS unlock prompt (in the dracut-sshd initramfs), `hz` will:

1. Detect the LUKS unlock prompt
2. Prompt for the passphrase (or fetch from 1Password via `op://` reference)
3. Send the passphrase to unlock the disk
4. Wait for boot to complete, then connect

This means you can reboot an encrypted server and simply run `hz ssh myserver` - the unlock happens automatically.

### 1Password Integration

Store your LUKS passphrases in 1Password and reference them:

```bash
# Full reference
export HZ_LUKS_UNLOCK="op://Private/my-server/luks-password"

# Short form (expands to op://<vault>/<server-name>/luks-password)
export HZ_LUKS_UNLOCK="op://Private"

hz ssh my-server
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HZ_LUKS_UNLOCK` | - | LUKS passphrase or `op://` 1Password reference |
| `HZ_OP_ACCOUNT` | - | 1Password account (if you have multiple) |
| `HZ_SSH_STRICT` | `y` | `y` = normal host key checking; `n` = disable |
| `HZ_RDNS` | `n` | `y` = use rDNS hostname for SSH config matching |
| `HZ_CONNECT_WAIT` | `120` | Seconds to wait for TCP port 22 |
| `HZ_BOOT_WAIT` | `600` | Max seconds to wait for unlock + boot |
| `HZ_RESET_ON_CRYPTFAIL` | - | `y` = auto-reset on wrong password; `n` = fail; unset = prompt |
| `HZ_RESET_MAX` | `1` | Max automatic resets per run |
| `HZ_SSH_CMD` | `ssh` | Override SSH binary |
| `HZ_SCP_CMD` | `scp` | Override SCP binary |

---

## Provisioning a New Server

### Prerequisites

- Hetzner Cloud API token
- `hcloud` CLI installed and configured
- `jq`, `ssh`, `openssl` available locally
- An existing Hetzner Cloud server to provision (the script will wipe it)

### Interactive Provisioning

```bash
export HCLOUD_TOKEN="your-token"
./provision.sh <server-name-or-id>
```

You'll be prompted for:
- Username to create
- SSH key(s) to use
- Optional features (sudo NOPASSWD, WARP for IPv6-only, NetBird)

The script generates and displays the LUKS and user passwords - **save these**.

### Non-Interactive / CI Provisioning

```bash
export HCLOUD_TOKEN="your-token"
export PROVISION_USER="your-username"
export USER_SSH_KEY="ssh-ed25519 AAAA..."    # Can be multiple newline-separated keys
export UNLOCK_SSH_KEY="$USER_SSH_KEY"        # Optional: separate key for initramfs

# Optional configuration
export LUKS_PASSWORD="your-shared-luks-pass" # Optional: override generated password
export ROOT_PASSWORD="your-shared-root-pass" # Optional: override generated password
export USER_PASSWORD="your-shared-user-pass" # Optional: override generated password
export NETBIRD_SETUP_KEY="your-setup-key"    # Install and connect NetBird
export WARP_TUNNEL=y                          # Enable IPv4 tunneling on IPv6-only servers
export WARP_TUNNEL_MODE=proxy                 # proxy (TCP-only) or warp (UDP-capable)
export SUDO_NOPASSWD=n                        # Keep passwordless sudo? (y/n)

# Optional: save credentials to 1Password (requires `op`)
# Interactive mode: prompts for vault ref
# Non-interactive mode: set these explicitly
export OP_VAULT_REF="op://Servers"           # Target vault (enables saving)
export OP_OVERWRITE_EXISTING=n                # Overwrite existing item? (y/n)
# For automation/CI, prefer service accounts:
# export OP_SERVICE_ACCOUNT_TOKEN="ops_..."

export FORCE_IMAGE="Rocky-10-latest-amd64-base.tar.gz"  # Specific image

./provision.sh <server-name-or-id>
```

### What Provisioning Does

1. **Validates** local tools and `HCLOUD_TOKEN`
2. **Switches** the server into Hetzner rescue mode
3. **Installs** a RHEL-family OS with LUKS encryption via `installimage`
4. **Configures** `dracut-sshd` for SSH access during boot
5. **Boots** and automatically unlocks (handles SELinux relabel reboot)
6. **Finalizes** with networking, hardening, and optional tools

### Post-Provisioning Tools

The finalization phase installs a developer workstation baseline:

- System: `git`, `ripgrep`, `make`, `gcc`, `clang`
- Python: `python3-devel`, `uv`
- Node.js: `fnm` + Node.js 24
- Tools: GitHub CLI (`gh`), 1Password CLI (`op`), OpenCode

---

## End-to-End Testing

For automation or testing the full flow:

```bash
export HCLOUD_TOKEN="your-token"
export PROVISION_USER="your-username"
export USER_SSH_KEY="ssh-ed25519 AAAA..."
export UNLOCK_SSH_KEY="$USER_SSH_KEY"

./test-provision-flow.sh <server-name-or-id>
```

**Warning:** This is destructive and will wipe the target server.

---

## Troubleshooting

### First Boot Double Reboot (SELinux)

On first boot, SELinux relabeling may trigger an automatic reboot:

1. LUKS unlock
2. System reboots for SELinux relabel
3. LUKS unlock again
4. Normal boot completes

The provisioning scripts handle this automatically. If using `hz` manually, just run the command again.

### Manual LUKS Unlock

If you need to unlock manually without `hz`:

```bash
# SSH into initramfs (IPv4)
ssh root@<server-ip>

# SSH into initramfs (IPv6 - use -6 flag, no brackets)
ssh -6 root@<ipv6-address>

# Find and unlock
socket=$(for s in /run/systemd/ask-password/sck.*; do [ -S "$s" ] && echo "$s" && break; done)
printf '%s' 'YOUR-LUKS-PASSWORD' | /usr/lib/systemd/systemd-reply-password 1 "$socket"
```

### IPv6-Only Servers

Hetzner Cloud does not provide NAT64/DNS64, so IPv6-only servers cannot reach IPv4-only hosts by default.

Enable Cloudflare WARP for IPv4 tunneling:

```bash
export WARP_TUNNEL=y
export WARP_TUNNEL_MODE=proxy  # or 'warp' for UDP support (needed for NetBird)
```

### Permission Denied Errors

If SSH keys are rejected:

1. Verify the key is loaded: `ssh-add -l`
2. Check that `USER_SSH_KEY` / `UNLOCK_SSH_KEY` match your loaded keys
3. Verify the right SSH agent/keys are in use

---

## Project Structure

| File | Purpose |
|------|---------|
| `hz` | SSH/SCP wrapper with auto LUKS unlock |
| `provision.sh` | Main provisioning orchestrator |
| `monitor-boot.sh` | Handles LUKS unlock during boot |
| `finalize.sh` | Post-boot configuration and hardening |
| `post-install.sh` | Runs inside rescue to configure the installed system |
| `wait_for_ssh.sh` | SSH connectivity helper (sourced by other scripts) |
| `update-boot-ipv6.sh` | Updates initramfs IPv6 config (installed on target) |

---

## Contributing

For development guidance, code conventions, and common pitfalls, see [AGENTS.md](AGENTS.md).

Run `shellcheck *.sh` before submitting changes.
