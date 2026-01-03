#!/bin/bash

# wait_for_ssh.sh - Centralized SSH connectivity utility
# Usage: source wait_for_ssh.sh && wait_for_ssh <user> <target> [max_connect_wait] [max_login_attempts]

wait_for_ssh() {
    local user=$1
    local target=$2
    local max_connect_wait=${3:-120} # Default 2 minutes for port 22 to open
    local max_login_attempts=${4:-10} # Increase attempts but keep total time low
    local port=22

    # Strip brackets for nc if it's IPv6
    local nc_target
    nc_target=$(echo "$target" | tr -d '[]')
    
    echo "--- Waiting for SSH Connectivity ($target:$port) ---"
    local start_time
    start_time=$(date +%s)
    local port_open=0
    
    while [ $(($(date +%s) - start_time)) -lt "$max_connect_wait" ]; do
        if nc -z -w 3 "$nc_target" "$port" 2>/dev/null; then
            port_open=1
            echo "TCP Port $port is OPEN."
            break
        fi
        printf "."
        sleep 2
    done

    if [ "$port_open" -eq 0 ]; then
        echo -e "\nERROR: Timeout waiting for TCP port $port to open on $target."
        return 1
    fi

    echo "--- Port is open. Testing SSH Login for $user@$target ---"
    
    local ssh_cmd="ssh"

    local opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes)
    
    # Format target for SSH: strip brackets if present, use -6 flag for IPv6
    local ssh_target
    ssh_target=$(echo "$target" | tr -d '[]')
    if [[ "$ssh_target" == *":"* ]]; then
        opts+=(-6)
    fi

    local attempt=1
    while [ "$attempt" -le "$max_login_attempts" ]; do
        echo "Login attempt $attempt/$max_login_attempts..."
        local output
        output=$($ssh_cmd "${opts[@]}" "$user@$ssh_target" "echo READY" 2>&1)
        local ret=$?
        
        if [ $ret -eq 0 ]; then
            echo "SSH Login SUCCESSFUL ($user)."
            return 0
        fi

        echo "Login failed: $output"
        
        if echo "$output" | grep -iq "Permission denied"; then
            echo "CRITICAL: Permission denied (publickey). Your SSH key is likely not authorized."
            # We don't return immediately because sometimes SSH services (like dropbear in initramfs) 
            # take a few seconds to load the authorized_keys file.
        fi

        sleep 5
        ((attempt++))
    done

    echo "ERROR: Failed to log in as $user after $max_login_attempts attempts."
    return 1
}
