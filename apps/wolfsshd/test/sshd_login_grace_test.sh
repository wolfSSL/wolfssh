#!/bin/bash

# sshd local test

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_exec_test.sh 127.0.0.1 22222"
    exit 1
fi

PWD=`pwd`
USER=`whoami`
TEST_PORT="$2"
TEST_HOST="$1"

if [ -f ./log.txt ]; then
    sudo rm -rf log.txt
fi
touch log.txt

source ./start_sshd.sh
cat <<EOF > sshd_config_test_login_grace
Port $TEST_PORT
Protocol 2
LoginGraceTime 5
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
AuthorizedKeysFile $PWD/authorized_keys_test
EOF

start_wolfsshd "sshd_config_test_login_grace"
# ensure the daemon is stopped on every exit path, including the failure
# exits below, so a leftover wolfsshd cannot interfere with later tests
trap stop_wolfsshd EXIT
pushd ../../..

TEST_CLIENT="./examples/client/client"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

RESULT=`$TEST_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT -c 'sleep 6 && echo still connected && exit'`
echo "$RESULT" | grep "still connected"
RESULT=$?
if [ "$RESULT" != 0 ]; then
    echo "FAIL: Connection was not held open"
    exit 1
fi

popd

# Test the grace-time timeout behaviorally: open a raw TCP connection, never
# authenticate, and confirm the server closes it at the grace deadline. This
# asserts the actual behavior rather than scraping the log, matching the Windows
# PowerShell test (and not relying on the daemon log being readable).
GRACE=5
if ! exec 3<>"/dev/tcp/$TEST_HOST/$TEST_PORT"; then
    echo "FAIL: could not connect to $TEST_HOST:$TEST_PORT"
    exit 1
fi

# The server sends its banner, waits for ours (which never comes), then closes
# the connection once the grace time expires. Read until the server closes the
# connection (EOF) or the per-read timeout elapses, and measure how long it
# took. Use a large read timeout (GRACE + 8) and decide by elapsed time rather
# than read's exit status, which differs across bash versions (timeout returns
# >128 on modern bash but 1 on the macOS bash 3.2).
START=$SECONDS
while true; do
    if IFS= read -r -t $((GRACE + 8)) -n 1024 _ <&3; then
        : # received banner/data, keep waiting for the server to close
    else
        break # server closed (EOF) or the read timeout elapsed
    fi
done
ELAPSED=$((SECONDS - START))
exec 3>&-

# An exit well before the read timeout means the server closed the connection;
# an exit near GRACE + 8 means it stayed open (not enforced).
if [ "$ELAPSED" -le $((GRACE + 4)) ]; then
    DROPPED=1
else
    DROPPED=0
fi

echo "connection closed=$DROPPED after ${ELAPSED}s (grace=$GRACE)"

if [ "$DROPPED" = 1 ] && [ "$ELAPSED" -ge $((GRACE - 1)) ]; then
    echo "PASS: unauthenticated connection dropped at login grace deadline"
elif [ "$DROPPED" = 1 ]; then
    echo "FAIL: connection closed at ${ELAPSED}s, before the grace deadline ($GRACE s)"
    exit 1
else
    echo "FAIL: connection still open past the grace time (not enforced)"
    exit 1
fi

exit 0


