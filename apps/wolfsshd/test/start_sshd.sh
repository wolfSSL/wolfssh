#!/bin/bash

# starts up a sshd session, takes in the sshd_config file as an argument
start_wolfsshd() {
    CURRENT_PIDS=`ps -e | grep wolfsshd | grep -oE "[0-9]+"`

    # git cannot persist a 0600 file mode, so tighten any configured host key
    # before launching. wolfSSHd refuses a group/world readable private key.
    while read -r HOSTKEY; do
        if [ -n "$HOSTKEY" ] && [ -f "$HOSTKEY" ]; then
            chmod 600 "$HOSTKEY" || { echo "chmod 600 failed for host key: $HOSTKEY" >&2; return 1; }
        fi
    done < <(grep -E '^[[:space:]]*HostKey[[:space:]]+' "$1" | awk '{print $2}')

    # find a port
    sudo ../wolfsshd -d -E ./log.txt -f $1

    # set the PID of started sshd
    NEW_PID=`ps -e | grep wolfsshd | grep -oE "[0-9]+"`
    PID=`diff <(echo "$CURRENT_PIDS") <(echo "$NEW_PID") | grep '>' | grep -oE "[0-9]+" | head -n1`
    printf "SSHD running on PID $PID\n"
}

# closes down the sshd session taking argument $1 as the PID of the session
stop_wolfsshd() {
    printf "Stopping SSHD, killing pid $PID\n"
    sudo kill $PID
}
