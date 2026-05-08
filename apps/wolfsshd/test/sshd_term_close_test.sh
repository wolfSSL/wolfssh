#!/bin/sh

# sshd local test

ROOT_PWD=$(pwd)
cd ../../..

TEST_CLIENT="./examples/client/client"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222 $USER"
    exit 1
fi

# get the current wolfsshd pid count to compare with
WOLFSSHD_PID_COUNT=$(pgrep wolfsshd | wc -l)

timeout 3 $TEST_CLIENT -p $2 -i $PRIVATE_KEY -j $PUBLIC_KEY -h $1 -c '/bin/sleep 10' -u $3 &
sleep 1
WOLFSSHD_PID_COUNT_AFTER=$(pgrep wolfsshd | wc -l)
if [ "$WOLFSSHD_PID_COUNT" = "$WOLFSSHD_PID_COUNT_AFTER" ]; then
    echo "Expecting another wolfSSHd pid after connection"
    echo "PID count before = $WOLFSSHD_PID_COUNT"
    echo "PID count after  = $WOLFSSHD_PID_COUNT_AFTER"
    exit 1
fi

netstat -nt | grep ESTABLISHED
RESULT=$?
if [ "$RESULT" != "0" ]; then
    echo "Expecting to find the TCP connection established"
    exit 1
fi

sleep 2

netstat -nt | grep CLOSE_WAIT
RESULT=$?
if [ "$RESULT" = "0" ]; then
    echo "Found close wait and was not expecting it"
    exit 1
fi

netstat -nt | grep TIME_WAIT
RESULT=$?
if [ "$RESULT" != "0" ]; then
    echo "Did not find timed wait for TCP close down"
    exit 1
fi

cd "$ROOT_PWD"
exit 0


