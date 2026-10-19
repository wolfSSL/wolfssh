#!/bin/bash

# Accept-loop regression: a fork() that fails for one connection must drop that
# connection only. The daemon used to store the failure in its accept loop's
# control variable and shut down, so one EAGAIN at a process limit stopped it
# listening for good. The failure is injected against the stock wolfsshd with
# an LD_PRELOAD interposer (sshd_fork_preload.c) that fails the first
# connection's fork() once.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and the runner's shared port as arguments;"
    echo "this test binds WOLFSSHD_FORK_PORT, or that port + 7"
    echo "./sshd_fork_fail_test.sh 127.0.0.1 22300"
    exit 1
fi

# Not PWD: that is bash's own variable and the shell rewrites it on every cd,
# so a saved copy is gone by the time it is read.
TESTDIR=`pwd`
USER=`whoami`
TEST_HOST="$1"

# Own daemon on a port leased by the runner, so the isolation holds against
# another run of the suite on the same host. Standalone, fall back to an
# offset from the port passed in.
TEST_PORT="${WOLFSSHD_FORK_PORT:-$(( $2 + 7 ))}"

SSHD_BIN="../wolfsshd"
if [ ! -x "$SSHD_BIN" ]; then
    echo "SKIP: $SSHD_BIN not built"
    exit 77
fi

# macOS strips DYLD_INSERT_LIBRARIES from the sudo-launched daemon, so Linux only.
if [ "`uname -s`" != "Linux" ]; then
    echo "SKIP: fork fault injection needs Linux LD_PRELOAD"
    exit 77
fi

# start_sshd.sh word-splits SSHD_ENV to build "sudo env NAME=VALUE ...", so a
# preload path holding whitespace would be torn in half.
case "$TESTDIR" in
    *[[:space:]]*)
        echo "SKIP: test directory path contains whitespace"
        exit 77
        ;;
esac

ROOT="$TESTDIR/../../.."
TEST_CLIENT="$ROOT/examples/client/client"
if [ ! -x "$TEST_CLIENT" ]; then
    echo "SKIP: $TEST_CLIENT not built"
    exit 77
fi

# Absolute: the example client calls ChangeToWolfSshRoot() before parsing
# anything, so a relative path would be resolved from the repository root.
PRIVATE_KEY="$ROOT/keys/hansel-key-ecc.der"
PUBLIC_KEY="$ROOT/keys/hansel-key-ecc.pub"

source ./start_sshd.sh

# Teardown on every exit path; log.txt and the client logs are kept for
# debugging like the other tests.
cleanup() {
    stop_wolfsshd
    rm -f sshd_config_test_fork "$PRELOAD_LIB"
    return 0
}
trap cleanup EXIT

# Build the interposer next to this script; skip if no compiler. Relative "./"
# path so the LD_PRELOAD value has no space (see SSHD_ENV in start_sshd.sh).
PRELOAD_SRC="sshd_fork_preload.c"
PRELOAD_LIB="./sshd_fork_preload.so"
CC_BIN="${CC:-cc}"
if ! "$CC_BIN" -shared -fPIC -o "$PRELOAD_LIB" "$PRELOAD_SRC" -ldl 2>/dev/null; then
    echo "SKIP: could not build $PRELOAD_LIB with $CC_BIN"
    exit 77
fi

# The runner creates this in its setup step; a standalone run does not get that.
if [ ! -f authorized_keys_test ]; then
    ./create_authorized_test_file.sh || exit 1
fi

touch log.txt 2>/dev/null

cat <<EOF > sshd_config_test_fork
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $ROOT/keys/server-key.pem
AuthorizedKeysFile $TESTDIR/authorized_keys_test
EOF

# Read through sudo: the daemon runs under sudo, so log.txt may be root-owned.
log_count() {
    local n
    n=`sudo grep -c "$1" log.txt 2>/dev/null`
    echo "${n:-0}"
}

DEADLINE=30
TIMEOUT=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT="timeout $DEADLINE"
fi

# Runs one exec session; output in $CLIENT_LOG, exit status in $CLIENT_RET.
run_client() {
    CLIENT_LOG="$TESTDIR/fork_client_$1.log"
    $TIMEOUT "$TEST_CLIENT" -q -c "echo $TOKEN" -u "$USER" -i "$PRIVATE_KEY" \
        -j "$PUBLIC_KEY" -h "$TEST_HOST" -p "$TEST_PORT" \
        > "$CLIENT_LOG" 2>&1
    CLIENT_RET=$?
}

client_said() {
    echo "  client said: `tail -n 3 "$CLIENT_LOG" | tr '\n' '|'`"
    echo "  full client output in $CLIENT_LOG"
}

# Echoed by the exec session. Present only when a shell actually ran.
TOKEN="wolfsshd_fork_ok_$$"

BEFORE_FORK_FAIL=`log_count "Issue spawning new process"`

SSHD_ENV="LD_PRELOAD=$PRELOAD_LIB WOLFSSHD_FAULT_FORK=1"
export SSHD_BIN SSHD_ENV
start_wolfsshd "sshd_config_test_fork"
if [ -z "$PID" ]; then
    echo "FAIL: fork-fault daemon did not start"
    exit 1
fi

# First connection: its fork() is failed, so the daemon drops it. The client's
# own result does not matter, only that the daemon reached the failure.
run_client "faulted"
AFTER_FORK_FAIL=`log_count "Issue spawning new process"`
if [ "$AFTER_FORK_FAIL" -le "$BEFORE_FORK_FAIL" ]; then
    echo "FAIL: injected fork() failure never reached the daemon"
    client_said
    exit 1
fi

# The daemon must still be up. Give a daemon that is on its way out the time to
# finish exiting, so this does not pass on a race.
sleep 1
if ! wolfsshd_alive "$PID"; then
    echo "FAIL: daemon exited after one connection's fork() failed"
    exit 1
fi

# Second connection: the interposer forwards this fork(), so the session must
# run end to end.
run_client "after"
if [ "$CLIENT_RET" -ne 0 ] || ! grep -q "$TOKEN" "$CLIENT_LOG"; then
    echo "FAIL: daemon did not serve a connection after a failed fork()"
    client_said
    exit 1
fi

rm -f "$TESTDIR"/fork_client_*.log
echo "PASS: daemon keeps accepting after a failed fork()"
exit 0
