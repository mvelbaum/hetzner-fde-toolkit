#!/bin/bash
set -e

# provision-hetzner.sh - Automate Hetzner RHEL-family FDE Install (Rocky/Alma/CentOS) for Hetzner Cloud via installimage/rescue.
# Usage: ./provision.sh <server_name_or_id>
#
# Optional 1Password integration (requires 1Password CLI `op`):
# - If `op` is installed and authenticated (interactive `op signin` or via `OP_SERVICE_ACCOUNT_TOKEN`),
#   provision.sh can save credentials to a Server item.
# - Set `OP_VAULT_REF` to skip the prompt (example: `op://Servers`).
# - Set `OP_OVERWRITE_EXISTING` to control overwrite behavior in non-interactive runs (y/n).

SERVER_TARGET=$1

if [ -z "$SERVER_TARGET" ]; then
    echo "Usage: $0 <server_name_or_id>"
    exit 1
fi

# 1. Verification
echo "--- Verification ---"

missing_cmds=()
require_cmd() {
    local cmd=$1
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing_cmds+=("$cmd")
    fi
}

# Ensure local dependencies are available before starting.
for cmd in awk basename cat dirname grep head hcloud jq nc openssl sed sort ssh ssh-add ssh-keygen scp tr xargs; do
    require_cmd "$cmd"
done

if [ ${#missing_cmds[@]} -gt 0 ]; then
    echo "Error: Missing required tools:" >&2
    for cmd in "${missing_cmds[@]}"; do
        echo "  - $cmd" >&2
    done
    echo "" >&2
    echo "Install the missing tools and re-run provision.sh." >&2
    exit 1
fi

SSH_CMD="ssh"

# SSH Options to ignore host key changes in rescue
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10"

# Helper function to format SSH target (strip brackets if present)
# Note: SSH with -6 flag works directly with IPv6 addresses without brackets
# Brackets cause issues with zsh glob expansion
format_ssh_target() {
    local ip=$1
    echo "$ip" | tr -d '[]'
}

# Helper function to get SSH options (add -6 for IPv6)
get_ssh_opts() {
    local ip=$1
    local opts="$SSH_OPTS"
    if [[ "$ip" == *":"* ]]; then
        opts="$opts -6"
    fi
    echo "$opts"
}

# Path to installimage in rescue
INSTALLIMAGE_PATH="/root/.oldroot/nfs/install/installimage"

have_tty() {
    # Most prompts should come from an interactive terminal.
    if [ -t 0 ]; then
        return 0
    fi

    # Fall back to /dev/tty if it can be opened.
    # Use a grouped redirect so errors don't leak if /dev/tty is unusable
    # (e.g. "Device not configured").
    if [ -c /dev/tty ] && { : </dev/tty; } 2>/dev/null; then
        return 0
    fi

    return 1
}

# Ensure HCLOUD_TOKEN is available
if [ -z "${HCLOUD_TOKEN:-}" ]; then
    if have_tty; then
        read -r -s -p "Enter HCLOUD_TOKEN: " HCLOUD_TOKEN </dev/tty
        printf "\n" >/dev/tty

        if [ -z "${HCLOUD_TOKEN:-}" ]; then
            echo "Error: HCLOUD_TOKEN is required." >&2
            exit 1
        fi
    else
        echo "Error: HCLOUD_TOKEN is not set and no TTY is available to prompt." >&2
        echo "Set HCLOUD_TOKEN in the environment and re-run." >&2
        exit 1
    fi
fi

export HCLOUD_TOKEN

# Get Server Info
SERVER_JSON=$(hcloud server describe "$SERVER_TARGET" -o json)
SERVER_ID=$(echo "$SERVER_JSON" | jq -r .id)
SERVER_IPV4=$(echo "$SERVER_JSON" | jq -r '.public_net.ipv4.ip // empty')
SERVER_IPV6_NET=$(echo "$SERVER_JSON" | jq -r '.public_net.ipv6.ip // empty')
if [ -n "$SERVER_IPV6_NET" ]; then
    SERVER_IPV6_ADDR="${SERVER_IPV6_NET%%/*}1"
else
    SERVER_IPV6_ADDR=""
fi
SERVER_NAME=$(echo "$SERVER_JSON" | jq -r .name)
SERVER_ARCH=$(echo "$SERVER_JSON" | jq -r .server_type.architecture)

# Determine primary IP for SSH connections (prefer IPv4 if available)
if [ -n "$SERVER_IPV4" ]; then
    SERVER_IP="$SERVER_IPV4"
    IP_TYPE="IPv4"
elif [ -n "$SERVER_IPV6_ADDR" ]; then
    SERVER_IP="$SERVER_IPV6_ADDR"
    IP_TYPE="IPv6"
else
    echo "Error: Server has no public IP address (IPv4 or IPv6)."
    exit 1
fi

# Map Hetzner architecture to installimage naming
# Hetzner: x86|arm -> installimage: amd64|arm64
case "$SERVER_ARCH" in
    x86)
        IMAGE_ARCH_SUFFIX="amd64"
        ;;
    arm)
        IMAGE_ARCH_SUFFIX="arm64"
        ;;
    *)
        echo "Error: Unknown server architecture '$SERVER_ARCH'."
        echo "Expected: x86 or arm."
        exit 1
        ;;
esac

# Display network configuration
echo "Targeting: $SERVER_NAME ($SERVER_ID) - $SERVER_ARCH"
echo "  IPv4: ${SERVER_IPV4:-none}"
echo "  IPv6: ${SERVER_IPV6_NET:-none}"
echo "  Primary IP ($IP_TYPE): $SERVER_IP"

# 2. Key Collection
 echo ""
 echo "--- SSH Key Collection ---"
 
 validate_pubkey_line() {
     local key_line=$1
 
     if [[ -z "$key_line" ]]; then
         return 1
     fi
 
     if [[ ! "$key_line" =~ ^(ssh-(rsa|ed25519)|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[^[:space:]]+ ]]; then
         return 1
     fi
 
     if ! ssh-keygen -lf - >/dev/null 2>&1 <<<"$key_line"; then
         return 1
     fi
 
     return 0
 }
 
 format_agent_key_entry() {
     local key_line=$1
     local index=$2
     local key_type
     local key_fp
     local key_comment
 
     key_type=$(awk '{print $1}' <<<"$key_line")
     key_fp=$(ssh-keygen -lf - <<<"$key_line" 2>/dev/null | awk '{print $2}')
     key_comment=$(awk '{print $3}' <<<"$key_line")
 
     if [ -z "$key_comment" ]; then
         key_comment="(no comment)"
     fi
 
     printf "[%s] %s  %s  %s\n" "$index" "$key_type" "$key_fp" "$key_comment"
 }
 
 select_agent_keys() {
     local purpose=$1
     local -a agent_keys=()
     local ssh_add_out
     local selected_line
     local -a selected_indices=()
     local idx
     local token
 
     if ! ssh_add_out=$(ssh-add -L 2>&1); then
         return 1
     fi
 
     if grep -qi "no identities" <<<"$ssh_add_out"; then
         return 1
     fi
 
     while IFS= read -r selected_line; do
         if validate_pubkey_line "$selected_line"; then
             agent_keys+=("$selected_line")
         fi
     done <<<"$ssh_add_out"
 
     if [ ${#agent_keys[@]} -eq 0 ]; then
         return 1
     fi
 
      if [ ${#agent_keys[@]} -eq 1 ]; then
          echo "1 SSH key loaded in your agent for: $purpose" >&2
          format_agent_key_entry "${agent_keys[0]}" 1 >&2
          echo "" >&2

          while true; do
              read -r -p "Press Enter to use this key, or paste a public key to override: " token
              if [ -z "$token" ]; then
                  printf '%s\n' "${agent_keys[0]}"
                  return 0
              fi

              if validate_pubkey_line "$token"; then
                  printf '%s\n' "$token"
                  return 0
              fi

              echo "Error: Input was not a valid SSH public key." >&2
              echo "" >&2
              echo "Tip: show agent keys with: ssh-add -L" >&2
          done
      fi
 
      while true; do
          echo "SSH keys loaded in your agent for: $purpose" >&2
          echo "" >&2
          idx=1
          for selected_line in "${agent_keys[@]}"; do
              format_agent_key_entry "$selected_line" "$idx" >&2
              idx=$((idx + 1))
          done
          echo "" >&2
          echo "Select one or more keys by number (e.g. '1 3'), or type:" >&2
          echo "  p = paste custom key(s)" >&2
          echo "  a = select all" >&2
          echo "  r = re-scan agent" >&2
          echo "  q = quit" >&2

          read -r -p "> " token
          if [ -z "$token" ]; then
              echo "No selection made." >&2
              echo "" >&2
              continue
          fi
 
         case "$token" in
             p)
                 return 2
                 ;;
             a)
                 printf '%s\n' "${agent_keys[@]}"
                 return 0
                 ;;
             r)
                 return 3
                 ;;
             q)
                  echo "Aborted." >&2
                  exit 1
                 ;;
         esac
 
         selected_indices=()
         for token in $token; do
             if [[ "$token" =~ ^[0-9]+$ ]]; then
                 if [ "$token" -ge 1 ] && [ "$token" -le "${#agent_keys[@]}" ]; then
                     selected_indices+=("$token")
                 fi
             fi
         done
 
          if [ ${#selected_indices[@]} -eq 0 ]; then
              echo "Error: Please select key numbers, or use 'p', 'a', 'r', 'q'." >&2
              echo "" >&2
              continue
          fi
 
        for token in "${selected_indices[@]}"; do
            idx=$((token - 1))
            printf '%s\n' "${agent_keys[$idx]}"
        done
        return 0
     done
 }
 
 collect_pasted_keys() {
     local purpose=$1
     local -a keys=()
     local key_line
     local add_more
 
      while true; do
          read -r -p "Paste public key for $purpose (or press Enter to cancel): " key_line
          if [ -z "$key_line" ]; then
              if [ ${#keys[@]} -eq 0 ]; then
                  return 1
              fi
              printf '%s\n' "${keys[@]}"
              return 0
          fi

          if ! validate_pubkey_line "$key_line"; then
              echo "Error: Invalid SSH public key." >&2
              continue
          fi

          keys+=("$key_line")
          read -r -p "Add another key? (y/N): " add_more
          if [[ ! "$add_more" =~ ^[Yy]$ ]]; then
              printf '%s\n' "${keys[@]}"
              return 0
          fi
      done
 }
 
 collect_ssh_keys() {
     local purpose=$1
     local selected
 
     while true; do
         if selected=$(select_agent_keys "$purpose"); then
             printf '%s\n' "$selected" | sort -u
             return 0
         fi
 
         case $? in
              1)
                  if selected=$(collect_pasted_keys "$purpose"); then
                      printf '%s\n' "$selected" | sort -u
                      return 0
                  fi
                  echo "Error: No keys selected for $purpose." >&2
                  ;;
              2)
                  if selected=$(collect_pasted_keys "$purpose"); then
                      printf '%s\n' "$selected" | sort -u
                      return 0
                  fi
                  echo "Error: No keys selected for $purpose." >&2
                  ;;
             3)
                 continue
                 ;;
              *)
                  echo "Error: Failed to read SSH keys from agent." >&2
                  ;;
         esac
     done
 }
 
 # Prompt for username if not set
 if [ -z "$PROVISION_USER" ]; then
     if [ -t 0 ]; then
         read -r -p "Enter username to create: " PROVISION_USER
         if [ -z "$PROVISION_USER" ]; then
             echo "Error: Username is required."
             exit 1
         fi
     else
         echo "Error: PROVISION_USER is not set."
         exit 1
     fi
 fi

 if [ -z "$USER_SSH_KEY" ]; then
     USER_SSH_KEY=$(collect_ssh_keys "user '$PROVISION_USER'")
 fi
 
  if [ -z "$UNLOCK_SSH_KEY" ]; then
       if have_tty; then
           read -r -p "Reuse the same key(s) for initramfs unlock? (Y/n): " REUSE_KEY </dev/tty
       else
           # Non-interactive (or no controlling TTY): default to reuse.
           REUSE_KEY="y"
       fi

       # Default to reusing the same key(s)
       REUSE_KEY="${REUSE_KEY:-y}"
       if [[ "$REUSE_KEY" =~ ^[Yy]$ ]]; then
           UNLOCK_SSH_KEY="$USER_SSH_KEY"
       else
           UNLOCK_SSH_KEY=$(collect_ssh_keys "initramfs unlock")
       fi
   fi




# Ask for Netbird Setup Key (Optional)
# - If NETBIRD_SETUP_KEY is set (even empty), do not prompt.
# - If unset and a TTY is available, prompt.
# - Blank input means "skip" (NetBird will not be installed).
if [ -z "${NETBIRD_SETUP_KEY+x}" ]; then
    if have_tty; then
        read -r -p "Enter Netbird Setup Key (optional, press Enter to skip): " NETBIRD_SETUP_KEY </dev/tty
    else
        NETBIRD_SETUP_KEY=""
    fi
fi

# Ask whether to enable IPv4 tunneling (IPv6-only servers only)
# If WARP_TUNNEL is set (even empty), do not prompt.
#
# Modes:
# - proxy: WARP SOCKS proxy + tun2socks (TCP-only for IPv4)
# - warp:  WARP "warp" mode (UDP-capable IPv4, better for NetBird)
if [ -z "${WARP_TUNNEL+x}" ]; then
    if [ -z "$SERVER_IPV4" ] && [ -n "$SERVER_IPV6_ADDR" ]; then
        if [ -t 0 ]; then
            echo "IPv6-only server detected."
            read -r -p "Enable IPv4 tunneling via Cloudflare WARP? (y/N): " WARP_TUNNEL_INPUT
            WARP_TUNNEL="${WARP_TUNNEL_INPUT:-n}"
        else
            WARP_TUNNEL="n"
        fi
    else
        WARP_TUNNEL="n"
    fi
fi

if [[ "$WARP_TUNNEL" =~ ^[Yy]$ ]]; then
    WARP_TUNNEL="y"
else
    WARP_TUNNEL="n"
fi

# Select WARP tunnel mode.
# If WARP_TUNNEL_MODE is set (even empty), do not prompt.
# Default logic:
# - If NetBird is requested on an IPv6-only host, prefer 'warp' mode (UDP-capable).
# - Otherwise default to 'proxy' mode (existing behavior).
if [ -z "${WARP_TUNNEL_MODE+x}" ]; then
    if [ "$WARP_TUNNEL" = "y" ] && [ -z "$SERVER_IPV4" ] && [ -n "$SERVER_IPV6_ADDR" ] && [ -n "$NETBIRD_SETUP_KEY" ]; then
        WARP_TUNNEL_MODE="warp"
    else
        WARP_TUNNEL_MODE="proxy"
    fi
fi

case "${WARP_TUNNEL_MODE}" in
    warp|proxy)
        ;;
    *)
        echo "WARNING: Unknown WARP_TUNNEL_MODE='$WARP_TUNNEL_MODE' (expected: warp|proxy). Defaulting to 'proxy'."
        WARP_TUNNEL_MODE="proxy"
        ;;
esac

 # 3. Password Generation
  echo ""
  echo "--- Password Generation ---"
  
  # Allow repeat provisioning with stable credentials:
  # - If environment variables are provided (non-empty), use them.
  # - Otherwise, generate random defaults.
  # - If a TTY is available, offer a one-time prompt to override the generated values.
  ENV_LUKS_PASSWORD="${LUKS_PASSWORD-}"
  ENV_ROOT_PASSWORD="${ROOT_PASSWORD-}"
  ENV_USER_PASSWORD="${USER_PASSWORD-}"
  
  # Generate 24-char alphanumeric hyphenated password for LUKS: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
  RAW_LUKS=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24)
  LUKS_PASSWORD=$(echo "$RAW_LUKS" | sed 's/.\{4\}/&-/g; s/-$//')
  
  # Generate 12-char alphanumeric hyphenated passwords for users: XXXX-XXXX-XXXX
  RAW_ROOT=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 12)
  ROOT_PASSWORD=$(echo "$RAW_ROOT" | sed 's/.\{4\}/&-/g; s/-$//')
  
  RAW_USER=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 12)
  USER_PASSWORD=$(echo "$RAW_USER" | sed 's/.\{4\}/&-/g; s/-$//')
  
  if [ -n "${ENV_LUKS_PASSWORD}" ]; then
      LUKS_PASSWORD="$ENV_LUKS_PASSWORD"
  fi
  if [ -n "${ENV_ROOT_PASSWORD}" ]; then
      ROOT_PASSWORD="$ENV_ROOT_PASSWORD"
  fi
  if [ -n "${ENV_USER_PASSWORD}" ]; then
      USER_PASSWORD="$ENV_USER_PASSWORD"
  fi
  
  prompt_password_override() {
      local label=$1
      local current_value=$2
      local input
  
      printf "Override %s? (press Enter to keep generated): " "$label" >/dev/tty
      read -r -s input </dev/tty
      printf "\n" >/dev/tty
  
      if [ -n "$input" ]; then
          printf '%s' "$input"
      else
          printf '%s' "$current_value"
      fi
  }
  
  if have_tty; then
      if [ -z "${ENV_LUKS_PASSWORD}" ]; then
          LUKS_PASSWORD=$(prompt_password_override "LUKS password" "$LUKS_PASSWORD")
      fi
      if [ -z "${ENV_ROOT_PASSWORD}" ]; then
          ROOT_PASSWORD=$(prompt_password_override "root password" "$ROOT_PASSWORD")
      fi
      if [ -z "${ENV_USER_PASSWORD}" ]; then
          USER_PASSWORD=$(prompt_password_override "${PROVISION_USER} password" "$USER_PASSWORD")
      fi
  fi

  normalize_op_vault() {
      local ref=$1

      ref="${ref#op://}"
      ref="${ref%%/*}"

      printf '%s' "$ref"
  }

  normalize_yes_no() {
      local value=$1

      case "$value" in
          y|Y|yes|YES|Yes|true|TRUE|True|1)
              printf 'y'
              ;;
          n|N|no|NO|No|false|FALSE|False|0)
              printf 'n'
              ;;
          *)
              printf ''
              ;;
      esac
  }

  save_credentials_to_1password() {
      local vault_ref
      local vault

      local existing_items_json
      local existing_item_id
      local overwrite_choice
      local overwrite_input

      if ! command -v op >/dev/null 2>&1; then
          return 0
      fi

      # Auth note:
      # - If OP_SERVICE_ACCOUNT_TOKEN is set, op runs as a service account and must be usable non-interactively.
      # - Without OP_SERVICE_ACCOUNT_TOKEN, `op` may be using 1Password desktop integration (biometric unlock).
      #   In that mode, `op whoami` can report "account is not signed in" even though vault reads work.
      #   So we avoid pre-checking with `op whoami` and instead rely on the actual vault/item operations.
      if [ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]; then
          if ! op whoami >/dev/null 2>&1; then
              echo "INFO: 1Password CLI (op) detected but OP_SERVICE_ACCOUNT_TOKEN auth failed; skipping vault save." >&2
              return 0
          fi
      fi

      vault_ref="${OP_VAULT_REF:-}"
      if [ -z "$vault_ref" ]; then
          if [ -t 0 ]; then
              read -r -p "Enter 1Password vault reference to save credentials (e.g. op://Servers), or press Enter to skip: " vault_ref </dev/tty
          else
              vault_ref=""
          fi
      fi

      if [ -z "$vault_ref" ]; then
          return 0
      fi

      vault=$(normalize_op_vault "$vault_ref")
      if [ -z "$vault" ]; then
          echo "WARNING: Invalid OP_VAULT_REF '$vault_ref'; skipping 1Password save." >&2
          return 0
      fi

      if have_tty && [ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]; then
          # Allow desktop integration to prompt on /dev/tty if needed.
          if ! existing_items_json=$(op item list --vault "$vault" --format json </dev/tty 2>/dev/tty); then
              echo "WARNING: Unable to list items in vault '$vault'; skipping 1Password save." >&2
              return 0
          fi
      else
          if ! existing_items_json=$(op item list --vault "$vault" --format json 2>/dev/null); then
              echo "WARNING: Unable to list items in vault '$vault'; skipping 1Password save." >&2
              return 0
          fi
      fi

      existing_item_id=$(jq -r --arg title "$SERVER_NAME" '.[] | select(.title == $title) | .id' <<<"$existing_items_json" | head -n 1)
      if [ "$existing_item_id" = "null" ]; then
          existing_item_id=""
      fi

      overwrite_choice=""
      if [ -n "${OP_OVERWRITE_EXISTING+x}" ]; then
          overwrite_choice=$(normalize_yes_no "$OP_OVERWRITE_EXISTING")
      fi

      if [ -n "$existing_item_id" ]; then
          if [ -z "$overwrite_choice" ]; then
              if [ -t 0 ]; then
                  read -r -p "1Password item '$SERVER_NAME' already exists in vault '$vault'. Overwrite? (Y/n): " overwrite_input </dev/tty
                  overwrite_input="${overwrite_input:-y}"
                  overwrite_choice=$(normalize_yes_no "$overwrite_input")
              else
                  overwrite_choice="n"
              fi
          fi

          if [ "$overwrite_choice" != "y" ]; then
              echo "INFO: Keeping existing 1Password item '$SERVER_NAME' (skipping save)." >&2
              return 0
          fi
      fi


      if [ -n "$existing_item_id" ]; then
          if ! op item template get server --format json \
              | jq -c \
                  --arg title "$SERVER_NAME" \
                  --arg ipv4 "${SERVER_IPV4:-}" \
                  --arg ipv6 "${SERVER_IPV6_ADDR:-}" \
                  --arg user "$PROVISION_USER" \
                  --arg user_pass "$USER_PASSWORD" \
                  --arg root_pass "$ROOT_PASSWORD" \
                  --arg luks_pass "$LUKS_PASSWORD" \
                  '
                  .title = $title
                  | (.fields[] | select(.id=="url") | .value) = ""
                  | (.fields[] | select(.id=="username") | .value) = ""
                  | (.fields[] | select(.id=="password") | .value) = ""
                  | .sections += [
                      {"id":"provision_user_account","label":($user + " account")},
                      {"id":"root_account","label":"root account"}
                    ]
                  | .fields += (
                  (if $ipv4 != "" then [{"type":"STRING","label":"ipv4","value":$ipv4}] else [] end)
                  + (if $ipv6 != "" then [{"type":"STRING","label":"ipv6","value":$ipv6}] else [] end)
                  + [{"type":"CONCEALED","label":"luks-password","value":$luks_pass}]
                  + [
                          {"section":{"id":"provision_user_account","label":($user + " account")},"type":"STRING","label":"username","value":$user},
                          {"section":{"id":"provision_user_account","label":($user + " account")},"type":"CONCEALED","label":"password","value":$user_pass},
                          {"section":{"id":"root_account","label":"root account"},"type":"STRING","label":"username","value":"root"},
                          {"section":{"id":"root_account","label":"root account"},"type":"CONCEALED","label":"password","value":$root_pass}
                        ]
                    )
                  ' \
              | {
                  if have_tty && [ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]; then
                      op item edit --vault "$vault" "$existing_item_id" >/dev/null 2>/dev/tty
                  else
                      op item edit --vault "$vault" "$existing_item_id" >/dev/null 2>&1
                  fi
              }; then
              echo "WARNING: Failed to update 1Password item '$SERVER_NAME' in vault '$vault'." >&2
              return 0
          fi

          echo "Updated credentials in 1Password vault '$vault' (Server item '$SERVER_NAME')." >&2
          return 0
      fi

      if ! op item template get server --format json \
          | jq -c \
              --arg title "$SERVER_NAME" \
              --arg ipv4 "${SERVER_IPV4:-}" \
              --arg ipv6 "${SERVER_IPV6_ADDR:-}" \
              --arg user "$PROVISION_USER" \
              --arg user_pass "$USER_PASSWORD" \
              --arg root_pass "$ROOT_PASSWORD" \
              --arg luks_pass "$LUKS_PASSWORD" \
              '
              .title = $title
              | (.fields[] | select(.id=="url") | .value) = ""
              | (.fields[] | select(.id=="username") | .value) = ""
              | (.fields[] | select(.id=="password") | .value) = ""
              | .sections += [
                  {"id":"provision_user_account","label":($user + " account")},
                  {"id":"root_account","label":"root account"}
                ]
              | .fields += (
                  (if $ipv4 != "" then [{"type":"STRING","label":"ipv4","value":$ipv4}] else [] end)
                  + (if $ipv6 != "" then [{"type":"STRING","label":"ipv6","value":$ipv6}] else [] end)
                  + [{"type":"CONCEALED","label":"luks-password","value":$luks_pass}]
                  + [
                      {"section":{"id":"provision_user_account","label":($user + " account")},"type":"STRING","label":"username","value":$user},
                      {"section":{"id":"provision_user_account","label":($user + " account")},"type":"CONCEALED","label":"password","value":$user_pass},
                      {"section":{"id":"root_account","label":"root account"},"type":"STRING","label":"username","value":"root"},
                      {"section":{"id":"root_account","label":"root account"},"type":"CONCEALED","label":"password","value":$root_pass}
                    ]
                )
              ' \
          | {
              if have_tty && [ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]; then
                  op item create --vault "$vault" - >/dev/null 2>/dev/tty
              else
                  op item create --vault "$vault" - >/dev/null 2>&1
              fi
          }; then
          echo "WARNING: Failed to create 1Password item '$SERVER_NAME' in vault '$vault'." >&2
          return 0
      fi

      echo "Saved credentials to 1Password vault '$vault' as Server item '$SERVER_NAME'." >&2
  }

  save_credentials_to_1password
  
 if [ -z "${SUDO_NOPASSWD+x}" ]; then
     if [ -t 0 ]; then
         read -r -p "Allow user '$PROVISION_USER' to use sudo without a password? (y/N): " SUDO_NOPASSWD_INPUT
         SUDO_NOPASSWD="${SUDO_NOPASSWD_INPUT:-n}"
     else
         SUDO_NOPASSWD="n"
     fi
 fi


echo "==========================================="
echo "!!! SAVE THESE CREDENTIALS NOW !!!"
echo "==========================================="
echo "LUKS Password:  $LUKS_PASSWORD"
echo "root Password:  $ROOT_PASSWORD"
echo "$PROVISION_USER Password:  $USER_PASSWORD"
echo "Sudo NOPASSWD:  $SUDO_NOPASSWD"
echo "Primary IP:     $SERVER_IP ($IP_TYPE)"
echo "IPv4 Address:   ${SERVER_IPV4:-none}"
echo "IPv6 Network:   ${SERVER_IPV6_NET:-none}"
echo "Netbird Key:    ${NETBIRD_SETUP_KEY:-}"
echo "IPv4 Tunnel:    $WARP_TUNNEL"
if [ "$WARP_TUNNEL" = "y" ]; then
    echo "WARP Mode:      ${WARP_TUNNEL_MODE:-proxy}"
fi
echo "==========================================="
echo ""

# 4. Enable Rescue Mode
echo "Enabling Rescue Mode..."
# Find the ssh key name (using the first one found if not specified)
SSH_KEY_NAME=$(hcloud ssh-key list -o json | jq -r '.[0].name')
echo "Using SSH key: $SSH_KEY_NAME for rescue mode"

hcloud server enable-rescue --ssh-key "$SSH_KEY_NAME" "$SERVER_ID"

echo "Rebooting into Rescue..."
hcloud server reset "$SERVER_ID"

# Use centralized wait utility
SCRIPT_DIR=$(dirname "$0")
# shellcheck disable=SC1091
source "$SCRIPT_DIR/wait_for_ssh.sh"
wait_for_ssh root "$SERVER_IP" 120 10 || exit 1

echo " Rescue system is up!"

# 5. Detect Image Name
# We support RHEL-family images provided by Hetzner installimage (e.g. Rocky/Alma/CentOS Stream).
# Filter images based on the server architecture.
echo "Detecting available RHEL-family images (Rocky/Alma/CentOS Stream) for $IMAGE_ARCH_SUFFIX..."
SSH_TARGET=$(format_ssh_target "$SERVER_IP")
CURRENT_SSH_OPTS=$(get_ssh_opts "$SERVER_IP")
# shellcheck disable=SC2086
AVAILABLE_IMAGES=$(
    $SSH_CMD $CURRENT_SSH_OPTS root@$SSH_TARGET \
        "ls /root/images/{Rocky-,Alma-,CentOS-}*${IMAGE_ARCH_SUFFIX}-base.tar.gz 2>/dev/null" \
    | xargs -n1 basename \
    | sort
)

if [ -z "$AVAILABLE_IMAGES" ]; then
    echo "No supported RHEL-family images found in /root/images/ for architecture: $IMAGE_ARCH_SUFFIX"
    echo "Expected patterns: Rocky-*, Alma-*, CentOS-* (*${IMAGE_ARCH_SUFFIX}-base.tar.gz)."
    exit 1
fi

IMAGE_LIST=()
while IFS= read -r image_line; do
    [ -z "$image_line" ] && continue
    IMAGE_LIST+=("$image_line")
done <<<"$AVAILABLE_IMAGES"

echo "Available Images:"
idx=1
for image in "${IMAGE_LIST[@]}"; do
    printf "%2d) %s\n" "$idx" "$image"
    idx=$((idx + 1))
done
echo ""

# Prefer Rocky 10 latest, then any 10 latest, then first match
DEFAULT_IMAGE=$(echo "$AVAILABLE_IMAGES" | grep -E "Rocky-10-latest-${IMAGE_ARCH_SUFFIX}-base\.tar\.gz" | head -n 1)
[ -z "$DEFAULT_IMAGE" ] && DEFAULT_IMAGE=$(echo "$AVAILABLE_IMAGES" | grep -E "(-10-latest-${IMAGE_ARCH_SUFFIX}-base\.tar\.gz|1000-${IMAGE_ARCH_SUFFIX}-base\.tar\.gz)" | head -n 1)
[ -z "$DEFAULT_IMAGE" ] && DEFAULT_IMAGE=$(echo "$AVAILABLE_IMAGES" | head -n 1)

DEFAULT_INDEX=1
for i in "${!IMAGE_LIST[@]}"; do
    if [ "${IMAGE_LIST[$i]}" = "$DEFAULT_IMAGE" ]; then
        DEFAULT_INDEX=$((i + 1))
        break
    fi
done

if [ -n "$FORCE_IMAGE" ]; then
    IMAGE_NAME="$FORCE_IMAGE"
else
    if [ -t 0 ]; then
        while true; do
            read -r -p "Select image [${DEFAULT_INDEX}: ${DEFAULT_IMAGE}] (enter number or exact name): " SELECTED_IMAGE
            SELECTED_IMAGE="${SELECTED_IMAGE:-$DEFAULT_INDEX}"
            echo ""

            if [[ "$SELECTED_IMAGE" =~ ^[0-9]+$ ]]; then
                if [ "$SELECTED_IMAGE" -ge 1 ] && [ "$SELECTED_IMAGE" -le "${#IMAGE_LIST[@]}" ]; then
                    IMAGE_NAME="${IMAGE_LIST[$((SELECTED_IMAGE - 1))]}"
                    break
                fi

                echo "Error: Selection must be between 1 and ${#IMAGE_LIST[@]}." >&2
                continue
            fi

            if printf '%s\n' "${IMAGE_LIST[@]}" | grep -Fxq "$SELECTED_IMAGE"; then
                IMAGE_NAME="$SELECTED_IMAGE"
                break
            fi

            echo "Error: Unknown image name. Enter a number from the list, or paste an exact image name." >&2
        done
    else
        echo "Non-interactive mode detected; using default image: $DEFAULT_IMAGE"
        IMAGE_NAME="$DEFAULT_IMAGE"
    fi
fi

echo "Using image: $IMAGE_NAME"

# 6. Prepare and Upload Payloads
echo "Preparing configuration files..."
SCRIPT_DIR=$(dirname "$0")

# Prepare post-install script with embedded keys and helper utilities
cat > /tmp/post-install-ready.sh <<EOF
USER_SSH_KEY=\$(cat <<'USER_SSH_KEY_EOF'
$USER_SSH_KEY
USER_SSH_KEY_EOF
)
export USER_SSH_KEY

UNLOCK_SSH_KEY=\$(cat <<'UNLOCK_SSH_KEY_EOF'
$UNLOCK_SSH_KEY
UNLOCK_SSH_KEY_EOF
)
export UNLOCK_SSH_KEY

export ROOT_PASSWORD='$ROOT_PASSWORD'
export PROVISION_USER='$PROVISION_USER'
export USER_PASSWORD='$USER_PASSWORD'
export NETBIRD_SETUP_KEY='$NETBIRD_SETUP_KEY'
export WARP_TUNNEL='$WARP_TUNNEL'
export WARP_TUNNEL_MODE='${WARP_TUNNEL_MODE:-proxy}'
export SERVER_IPV4='$SERVER_IPV4'
export SERVER_IPV6_NET='$SERVER_IPV6_NET'
export SERVER_IPV6_ADDR='$SERVER_IPV6_ADDR'
export DISK='/dev/sda'
EOF

# Embed update-boot-ipv6.sh without local expansion.
# shellcheck disable=SC2129
cat >> /tmp/post-install-ready.sh <<'EOF'
UPDATE_BOOT_IPV6_SH=$(cat <<'UPDATE_BOOT_IPV6_EOF'
EOF
cat "$SCRIPT_DIR/update-boot-ipv6.sh" >> /tmp/post-install-ready.sh
cat >> /tmp/post-install-ready.sh <<'EOF'
UPDATE_BOOT_IPV6_EOF
)
export UPDATE_BOOT_IPV6_SH
EOF

cat "$SCRIPT_DIR/post-install.sh" >> /tmp/post-install-ready.sh



# Prepare update utility
cat "$SCRIPT_DIR/update-boot-ipv6.sh" > /tmp/update-boot-ipv6-ready.sh

# Get full path to image in rescue
IMAGE_PATH="/root/images/$IMAGE_NAME"

sed "s|__IMAGE__|$IMAGE_PATH|; s/__PASSWORD__/$LUKS_PASSWORD/; s/__HOSTNAME__/$SERVER_NAME/" "$SCRIPT_DIR/install.conf.tpl" > /tmp/install.conf

# Use cat and ssh to upload to avoid scp path issues
# shellcheck disable=SC2086
cat /tmp/install.conf | $SSH_CMD $CURRENT_SSH_OPTS root@$SSH_TARGET "cat > /tmp/install.conf"
# shellcheck disable=SC2086
cat /tmp/post-install-ready.sh | $SSH_CMD $CURRENT_SSH_OPTS root@$SSH_TARGET "cat > /tmp/post-install.sh; chmod +x /tmp/post-install.sh"
# shellcheck disable=SC2086
cat /tmp/update-boot-ipv6-ready.sh | $SSH_CMD $CURRENT_SSH_OPTS root@$SSH_TARGET "cat > /tmp/update-boot-ipv6.sh; chmod +x /tmp/update-boot-ipv6.sh"

# 7. Execute Installation
echo "Starting installation (this will wipe the disk!)..."
# shellcheck disable=SC2086
$SSH_CMD $CURRENT_SSH_OPTS root@$SSH_TARGET << EOF
    set -e
    export TERM=xterm
    # Run installimage in automatic mode
    yes | $INSTALLIMAGE_PATH -a -c /tmp/install.conf -x /tmp/post-install.sh
    
    # Copy utilities to the newly installed system (mount points depend on installimage)
    # Usually the root is at /mnt. Keep variable expansion on the rescue host
    # by escaping $ inside this SSH heredoc.
    target_root=/mnt
    if [ ! -f "\$target_root/etc/os-release" ] && [ -f /mnt/target/etc/os-release ]; then
        target_root=/mnt/target
    fi

    if [ -d "\$target_root" ]; then
        mkdir -p "\$target_root/usr/local/bin"
        cp /tmp/update-boot-ipv6.sh "\$target_root/usr/local/bin/update-boot-ipv6"
        chmod +x "\$target_root/usr/local/bin/update-boot-ipv6"
    else
        echo "WARNING: Unable to locate installimage mountpoint; update-boot-ipv6 not installed." >&2
    fi
EOF

echo ""
echo "--- Installation Complete ---"
echo "==========================================="
echo "LUKS Password:  $LUKS_PASSWORD"
echo "root Password:  $ROOT_PASSWORD"
echo "$PROVISION_USER Password:  $USER_PASSWORD"
echo "==========================================="
echo "You can now reboot and unlock the server."
echo "Note: this system may reboot twice on first boot (SELinux relabel)."
echo "The provisioner will monitor boot, auto-unlock as needed, and then finalize configuration (NetBird/WARP if requested)."
echo "Manual unlock command (if needed): ssh root@$SSH_TARGET"
echo "Then run: systemd-tty-ask-password-agent"
echo ""

DID_REBOOT=0
if [ -n "$AUTO_REBOOT" ]; then
    echo "AUTO_REBOOT is set. Rebooting now..."
    hcloud server reset "$SERVER_ID"
    DID_REBOOT=1
else
    read -r -p "Reboot now? (Y/n): " REBOOT_NOW
    REBOOT_NOW="${REBOOT_NOW:-y}"
    if [[ "$REBOOT_NOW" =~ ^[Yy]$ ]]; then
        hcloud server reset "$SERVER_ID"
        DID_REBOOT=1
    fi
fi

# Monitor boot and auto-unlock until OS is ready.
# This handles the common SELinux relabel reboot that would otherwise require
# a second manual unlock.
if [ "$DID_REBOOT" -eq 1 ]; then
    SCRIPT_DIR=$(dirname "$0")
    MONITOR_SCRIPT="$SCRIPT_DIR/monitor-boot.sh"
    FINALIZE_SCRIPT="$SCRIPT_DIR/finalize.sh"

    if [ -n "$SERVER_IPV4" ]; then
        MONITOR_PRIMARY_IP="$SERVER_IPV4"
        MONITOR_SECONDARY_IPV6="$SERVER_IPV6_ADDR"
    else
        MONITOR_PRIMARY_IP="$SERVER_IPV6_ADDR"
        MONITOR_SECONDARY_IPV6=""
    fi

    echo "Starting boot monitor (auto-unlock until user SSH works)..."
    "$MONITOR_SCRIPT" "$MONITOR_PRIMARY_IP" "$LUKS_PASSWORD" "$PROVISION_USER" "$MONITOR_SECONDARY_IPV6"

    echo "Starting post-boot finalization (networking, optional NetBird/WARP, sudo hardening)..."
    SERVER_IPV4="$SERVER_IPV4" \
    SERVER_IPV6_NET="$SERVER_IPV6_NET" \
    SERVER_IPV6_ADDR="$SERVER_IPV6_ADDR" \
    NETBIRD_SETUP_KEY="$NETBIRD_SETUP_KEY" \
    WARP_TUNNEL="$WARP_TUNNEL" \
    WARP_TUNNEL_MODE="$WARP_TUNNEL_MODE" \
    SUDO_NOPASSWD="$SUDO_NOPASSWD" \
    "$FINALIZE_SCRIPT" "$MONITOR_PRIMARY_IP" "$PROVISION_USER" "$MONITOR_SECONDARY_IPV6"

    echo "==========================================="
    echo "Provisioning complete."
    if [ -n "$SERVER_IPV4" ]; then
        echo "SSH: ssh $PROVISION_USER@$SERVER_IPV4"
    fi
    if [ -n "$SERVER_IPV6_ADDR" ]; then
        echo "SSH (IPv6): ssh -6 $PROVISION_USER@$SERVER_IPV6_ADDR"
    fi
    echo "==========================================="
fi
