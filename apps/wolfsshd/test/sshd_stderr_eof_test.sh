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

# A byte count cannot tell a short transfer from one that never finished, and
# the runner invokes this test synchronously: a regression that leaves the
# session open would stall the whole suite here. One pass takes about four
# seconds, so this is only a deadline, not a budget. Degraded rather than
# skipped where "timeout" is missing, matching run_all_sshd_tests.sh.
TEST_TIMEOUT=120
TIMEOUT=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT="timeout $TEST_TIMEOUT"
fi

source ./start_sshd.sh

# The runner leases a port block per run so two runs can share a host, and
# fixed names in the checkout are the other half of that: a second run
# overwrites this one's config and payload, and whichever finishes first
# removes them from under the other, which then reports a short transfer that
# never happened. Everything this test writes goes in a directory of its own.
TEST_TMP=`mktemp -d 2>/dev/null` || TEST_TMP=`mktemp -d -t stderreof`
if [ -z "$TEST_TMP" ] || [ ! -d "$TEST_TMP" ]; then
    echo "Failed to create a temp dir"
    exit 1
fi
TEST_CONFIG="$TEST_TMP/sshd_config_test_stderr_eof"
TEST_FILE="$TEST_TMP/stderr-eof-test.txt"
TEST_RESULT_FILE="$TEST_TMP/stderr-eof-test-result.txt"

# The payload is 16 MB and the daemon is shared with the rest of the run, so
# neither may be left behind by an interrupted pass. Installed before the
# daemon starts so a failure in between is covered too; stop_wolfsshd is
# idempotent, so the explicit call at the end still stands.
trap 'rm -rf "$TEST_TMP"; stop_wolfsshd' EXIT

cat <<CONF > "$TEST_CONFIG"
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

start_wolfsshd "$TEST_CONFIG"
if [ -z "$PID" ]; then
    echo "Failed to start wolfsshd"
    exit 1
fi
cd ../../..

TEST_CLIENT="./examples/client/client"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"
PWD=`pwd`

head -c $TEST_SIZE /dev/urandom > "$TEST_FILE"
EXPECTED=`wc -c < "$TEST_FILE"`

RESULT=0
for i in `seq 1 $TEST_ITERS`; do
    # The inner client cats the file through the outer session, so the shell
    # loop is the one relaying it. Stalling the outer client's reader fills
    # the window and leaves the loop holding a backlog.
    $TIMEOUT $TEST_CLIENT -q -c "cd $PWD; $TEST_CLIENT -q -c \"cat $TEST_FILE\" -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT" \
        -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT 2>/dev/null \
        | { sleep $TEST_STALL; cat; } > "$TEST_RESULT_FILE"
    # The client's own status, not the reader's. 124 is the deadline above,
    # which a byte count would go on to report as a short transfer.
    CLIENT_RESULT=${PIPESTATUS[0]}

    if [ "$CLIENT_RESULT" = 124 ]; then
        echo "pass $i of $TEST_ITERS never finished"
        echo "the client was still running after $TEST_TIMEOUT seconds"
        RESULT=1
        break
    fi

    GOT=`wc -c < "$TEST_RESULT_FILE"`
    if [ "$GOT" != "$EXPECTED" ]; then
        echo "pass $i of $TEST_ITERS truncated the shell output"
        echo "expected $EXPECTED bytes, got $GOT, short by $((EXPECTED-GOT))"
        RESULT=1
        break
    fi
done

rm -rf "$TEST_TMP"
cd apps/wolfsshd/test
stop_wolfsshd

exit $RESULT
