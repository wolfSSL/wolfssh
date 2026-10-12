#!/bin/bash

# A child that exits with error output still in its pipe must have all of it
# relayed before the session ends.
#
# A loop that ends the session once the child is gone and its stdout has
# reported EOF leaves the rest of stderr to the drain below it, which reads one
# bufferful. The peer sees a truncated error stream and no error.
#
# The child grows its stderr pipe and queues the whole payload before it
# exits; a default pipe leaves too little behind for the drain to miss. How
# much the loop reads first is a race, so this repeats. A short stream is never
# correct, so a failure is always real.
#
# A pty session has no stderr pipe; the last check covers its exit.
#
# Lines are counted rather than bytes because the client's own "Error reading
# stdin" lands in the same capture.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_stderr_drain_test.sh 127.0.0.1 22222"
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

# Several bufferfuls, all of which fit in the grown pipe.
TEST_LINE="wolfsshd-stderr-drain"
TEST_LINES=9000
TEST_ITERS=40
TEST_TIMEOUT=60
TEST_PTY_TIMEOUT=15
TEST_PIPE_SZ=1048576

# The shell cannot resize a pipe, so the child is perl.
if ! command -v perl >/dev/null 2>&1; then
    echo "perl not found, skipping"
    exit 77
fi

# The regression this covers ends the session early rather than hanging, but
# the runner invokes this test synchronously and has no deadline of its own.
# Degraded rather than skipped where "timeout" is missing, matching
# run_all_sshd_tests.sh.
TIMEOUT=""
PTY_TIMEOUT=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT="timeout $TEST_TIMEOUT"
    PTY_TIMEOUT="timeout $TEST_PTY_TIMEOUT"
fi

source ./start_sshd.sh

# Everything this test writes goes in a directory of its own, so a second run
# sharing the host cannot overwrite the payload or remove it mid-transfer.
TEST_TMP=`mktemp -d 2>/dev/null` || TEST_TMP=`mktemp -d -t stderrdrain`
if [ -z "$TEST_TMP" ] || [ ! -d "$TEST_TMP" ]; then
    echo "Failed to create a temp dir"
    exit 1
fi
TEST_CONFIG="$TEST_TMP/sshd_config_test_stderr_drain"
TEST_FILE="$TEST_TMP/stderr-drain-test.txt"
TEST_RESULT_FILE="$TEST_TMP/stderr-drain-test-result.txt"
TEST_CHILD="$TEST_TMP/stderr-drain-child.pl"

# Installed before the daemon starts so a failure in between is covered too.
# stop_wolfsshd is idempotent, so the explicit call at the end still stands.
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

yes "$TEST_LINE" | head -n $TEST_LINES > "$TEST_FILE"

# 1031 is Linux's F_SETPIPE_SZ. If it fails the test is weaker, never wrong.
cat <<CHILD > "$TEST_CHILD"
fcntl(STDERR, 1031, $TEST_PIPE_SZ);
open(my \$f, "<", \$ARGV[0]) or die "\$ARGV[0]: \$!";
local \$/;
my \$d = <\$f>;
while (length \$d) {
    my \$n = syswrite(STDERR, \$d);
    die "write: \$!" unless defined \$n;
    substr(\$d, 0, \$n) = "";
}
CHILD

RESULT=0
for i in `seq 1 $TEST_ITERS`; do
    # The child exits with its output still queued and nothing slows the
    # peer, so the loop has to relay the rest on its own.
    $TIMEOUT $TEST_CLIENT -q -c "perl $TEST_CHILD $TEST_FILE" \
        -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT \
        < /dev/null > /dev/null 2> "$TEST_RESULT_FILE"
    CLIENT_RESULT=$?

    if [ "$CLIENT_RESULT" = 124 ]; then
        echo "pass $i of $TEST_ITERS never finished"
        echo "the client was still running after $TEST_TIMEOUT seconds"
        RESULT=1
        break
    fi

    # A truncated stream still exits 0; anything else is a setup failure.
    if [ "$CLIENT_RESULT" != 0 ]; then
        echo "pass $i of $TEST_ITERS could not run the client"
        echo "the client exited $CLIENT_RESULT"
        cat "$TEST_RESULT_FILE"
        RESULT=1
        break
    fi

    GOT=`grep -c "^$TEST_LINE\$" "$TEST_RESULT_FILE"`
    if [ "$GOT" != "$TEST_LINES" ]; then
        echo "pass $i of $TEST_ITERS truncated the child's stderr"
        echo "expected $TEST_LINES lines, got $GOT, short by"\
            "$((TEST_LINES-GOT))"
        RESULT=1
        break
    fi
done

# A pty session has no stderr pipe, so the drain must start out satisfied.
# Seeded wrong, the loop waits for an EOF that never comes and the shell's
# exit never ends the session. The exit status proves the session ended and
# carried the shell's own code back.
if [ "$RESULT" = 0 ]; then
    printf 'exit 3\n' | $PTY_TIMEOUT $TEST_CLIENT -t \
        -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT \
        > /dev/null 2>&1
    CLIENT_RESULT=$?

    if [ "$CLIENT_RESULT" = 124 ]; then
        echo "pty session never ended after the shell exited"
        echo "the client was still running after $TEST_PTY_TIMEOUT seconds"
        RESULT=1
    elif [ "$CLIENT_RESULT" != 3 ]; then
        echo "pty session exit status $CLIENT_RESULT, expected 3"
        RESULT=1
    fi
fi

rm -rf "$TEST_TMP"
cd apps/wolfsshd/test
stop_wolfsshd

exit $RESULT
