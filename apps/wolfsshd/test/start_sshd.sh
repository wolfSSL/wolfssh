#!/bin/bash

# starts up a sshd session, takes in the sshd_config file as an argument
start_wolfsshd() {
    CURRENT_PIDS=`ps -e | grep wolfsshd | grep -oE "[0-9]+"`

    CONFIG="$1"

    # SSHD_BIN picks the binary; SSHD_ENV passes env (e.g. LD_PRELOAD) that plain
    # sudo would strip. SSHD_ENV is unquoted to split NAME=VALUE, so no spaces.
    SSHD_BIN="${SSHD_BIN:-../wolfsshd}"
    sudo env $SSHD_ENV "$SSHD_BIN" -d -E ./log.txt -f "$CONFIG"

    # set the PID of started sshd
    NEW_PID=`ps -e | grep wolfsshd | grep -oE "[0-9]+"`
    PID=`diff <(echo "$CURRENT_PIDS") <(echo "$NEW_PID") | grep '>' | grep -oE "[0-9]+" | head -n1`
    printf "SSHD running on PID $PID\n"
}

# closes down the sshd session taking argument $1 as the PID of the session
stop_wolfsshd() {
    printf "Stopping SSHD, killing pid $PID\n"
    sudo kill $PID

    # Wait for the process to actually exit so a subsequent start_wolfsshd on
    # the same port doesn't race the listening socket's release (EADDRINUSE).
    for i in $(seq 1 50); do
        sudo kill -0 $PID 2>/dev/null || break
        sleep 0.1
    done
}
