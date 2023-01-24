#!/bin/bash

# starts up a sshd session, takes in the sshd_config file as an argument
start_wolfsshd() {
    CURRENT_PIDS=`ps -e | grep wolfsshd | grep -oE "[0-9]+"`
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
