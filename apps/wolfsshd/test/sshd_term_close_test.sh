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

# get the current wolfsshd pids to compare with
WOLFSSHD_PIDS=$(pgrep wolfsshd | tr '\n' ' ')

# True once a wolfsshd exists that did not before this connection. Comparing
# counts instead misses the new child whenever a previous test's child exits
# in the same window.
new_wolfsshd_pid() {
    for P in $(pgrep wolfsshd); do
        case " $WOLFSSHD_PIDS " in
            *" $P "*) ;;
            *) return 0 ;;
        esac
    done
    return 1
}

timeout 3 $TEST_CLIENT -p $2 -i $PRIVATE_KEY -j $PUBLIC_KEY -h $1 -c '/bin/sleep 10' -u $3 &
CLIENT_PID=$!

# Poll for the child rather than sampling a fixed second in. NewConnection()
# forks right after accept(), so the connection is up by the time it appears.
WAITED=0
while [ "$WAITED" -lt 30 ] && ! new_wolfsshd_pid; do
    sleep 0.1
    WAITED=$((WAITED + 1))
done

if ! new_wolfsshd_pid; then
    echo "Expecting another wolfSSHd pid after connection"
    echo "PIDs before = $WOLFSSHD_PIDS"
    echo "PIDs after  = $(pgrep wolfsshd | tr '\n' ' ')"
    exit 1
fi

# Only consider sockets for the test port so unrelated host traffic
# (other CLOSE_WAIT/TIME_WAIT connections) does not skew the result.
netstat -nt | grep ":$2 " | grep ESTABLISHED
RESULT=$?
if [ "$RESULT" != "0" ]; then
    echo "Expecting to find the TCP connection established"
    exit 1
fi

# Wait for the client's own timeout to kill it. Sampling a fixed two seconds
# in lands at the same instant the kill fires, in the middle of the teardown
# being measured.
wait $CLIENT_PID

# The server side legitimately passes through CLOSE_WAIT on its way to closed,
# so one sample can catch a healthy teardown mid-flight. Poll for the settled
# state instead; what this test is for is a connection that never leaves
# CLOSE_WAIT.
# Sample after the wait, never before: the first sample would be taken the
# instant the client was killed, when the server side has not reached
# CLOSE_WAIT yet, and a TIME_WAIT left on this port by an earlier test
# against the shared daemon would satisfy the other half on its own. Both
# halves could then be true at once without this teardown being observed.
DEADLINE=10
WAITED=0
while [ "$WAITED" -lt "$DEADLINE" ]; do
    sleep 1
    WAITED=$((WAITED + 1))
    netstat -nt | grep ":$2 " | grep CLOSE_WAIT > /dev/null
    CLOSE_WAIT_FOUND=$?
    netstat -nt | grep ":$2 " | grep TIME_WAIT > /dev/null
    TIME_WAIT_FOUND=$?
    if [ "$CLOSE_WAIT_FOUND" != "0" ] && [ "$TIME_WAIT_FOUND" = "0" ]; then
        break
    fi
done

if [ "$CLOSE_WAIT_FOUND" = "0" ]; then
    echo "Found close wait and was not expecting it after ${WAITED}s"
    netstat -nt | grep ":$2 "
    exit 1
fi

if [ "$TIME_WAIT_FOUND" != "0" ]; then
    echo "Did not find timed wait for TCP close down after ${WAITED}s"
    netstat -nt | grep ":$2 "
    exit 1
fi

cd "$ROOT_PWD"
exit 0


