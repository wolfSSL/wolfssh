#!/bin/bash

# The child's stderr reaching end of file must not end the shell loop while
# its stdout still has bytes queued for the peer.
#
# read() returns 0 at EOF and leaves errno alone, so an errno tested there
# reports whatever the last call left. A shell loop holding a backlog stops
# reading the child's pipes, so stdout backs up and the stderr EOF arrives
# behind it; if that EOF is read as an error the loop ends and everything
# still queued is dropped. The peer sees a short transfer and no error.
#
# Whether the stale errno happens to be fatal is a race, so one transfer
# proves nothing and this repeats. A short transfer is never correct, so a
# failure here is always real; a regression can only hide by passing every
# iteration.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_stderr_eof_test.sh 127.0.0.1 22222"
    exit 1
fi

PWD=`pwd`

if [ ! -z "$3" ]; then
    USER="$3"
else
    USER=`whoami`
fi
TEST_HOST="$1"
TEST_PORT="$2"

# Enough data to outrun the send window, a reader that stalls long enough for
# the child to finish and exit while the backlog is held, and enough passes to
# make the race show.
TEST_SIZE=16777216
TEST_STALL=4
TEST_ITERS=12

source ./start_sshd.sh
cat <<CONF > sshd_config_test_stderr_eof
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
AuthorizedKeysFile $PWD/authorized_keys_test
CONF

start_wolfsshd "sshd_config_test_stderr_eof"
cd ../../..

TEST_CLIENT="./examples/client/client"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"
PWD=`pwd`

head -c $TEST_SIZE /dev/urandom > stderr-eof-test.txt
EXPECTED=`wc -c < stderr-eof-test.txt`

RESULT=0
for i in `seq 1 $TEST_ITERS`; do
    # The inner client cats the file through the outer session, so the shell
    # loop is the one relaying it. Stalling the outer client's reader fills
    # the window and leaves the loop holding a backlog.
    $TEST_CLIENT -q -c "cd $PWD; $TEST_CLIENT -q -c \"cat $PWD/stderr-eof-test.txt\" -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT" \
        -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT 2>/dev/null \
        | { sleep $TEST_STALL; cat; } > stderr-eof-test-result.txt

    GOT=`wc -c < stderr-eof-test-result.txt`
    if [ "$GOT" != "$EXPECTED" ]; then
        echo "pass $i of $TEST_ITERS truncated the shell output"
        echo "expected $EXPECTED bytes, got $GOT, short by $((EXPECTED-GOT))"
        RESULT=1
        break
    fi
done

rm -f stderr-eof-test.txt stderr-eof-test-result.txt
cd apps/wolfsshd/test
stop_wolfsshd

exit $RESULT
