#!/bin/bash

# Fail-closed chroot regression for SetupChroot(): once one step of the chroot
# sequence has failed, the steps after it must not run. chroot() after a failed
# chdir() into the target would leave the session chrooted with a working
# directory outside the new root; chdir("/") after a failed chroot() would move
# the session somewhere it was never meant to be.
#
# The failures are injected against a stock wolfsshd with an LD_PRELOAD
# interposer (sshd_chroot_preload.c), so no fault code lives in the daemon or
# library. The same interposer records each chroot() and each chdir() made
# after one, and that record is what the assertions read: a recorded call is a
# step that ran.
#
# Drives SHELL_Subsystem, whose SetupChroot() failure is the one reported as
# "Error setting chroot". SFTP and SCP reach the same helper, and the guard
# under test is inside it.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_chroot_fail_test.sh 127.0.0.1 22222"
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
TEST_PORT="${WOLFSSHD_CHROOT_PORT:-$(( $2 + 6 ))}"

SSHD_BIN="../wolfsshd"
if [ ! -x "$SSHD_BIN" ]; then
    echo "SKIP: $SSHD_BIN not built"
    exit 77
fi

# macOS strips DYLD_INSERT_LIBRARIES from the sudo-launched daemon, so Linux only.
if [ "`uname -s`" != "Linux" ]; then
    echo "SKIP: chroot fault injection needs Linux LD_PRELOAD"
    exit 77
fi

# chroot(2) needs root, and start_sshd.sh gets there with sudo. Without a usable
# non-interactive sudo the healthy case could not chroot at all, so the run would
# prove nothing.
if [ "`id -u`" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    echo "SKIP: chroot test needs root or non-interactive sudo"
    exit 77
fi

# start_sshd.sh word-splits SSHD_ENV to build "sudo env NAME=VALUE ...", so a
# fault path holding whitespace would be torn in half.
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

# Absolute, and that matters. Unlike most of the sshd tests this one runs from
# its own directory rather than the repository root, and the example clients
# call ChangeToWolfSshRoot() before parsing anything, so every path they are
# handed is resolved from the repository root instead of here.
PRIVATE_KEY="$ROOT/keys/hansel-key-ecc.der"
PUBLIC_KEY="$ROOT/keys/hansel-key-ecc.pub"

source ./start_sshd.sh

# Teardown on every exit path, set before anything below creates a file;
# log.txt is kept for debugging like the other tests.
cleanup() {
    # Unconditional: it also removes the temp dir a failed start leaves behind.
    stop_wolfsshd
    rm -f sshd_config_test_chroot sshd_config_test_chroot_ok "$PRELOAD_LIB"
    rm -f "$TESTDIR"/chroot_client_*.log
    sudo rm -f "$TRACE_CHDIR_FAIL" "$TRACE_CHROOT_FAIL" "$TRACE_OK"
    rmdir "$CHROOT_DIR" 2>/dev/null
    return 0
}
trap cleanup EXIT

# Build the interposer next to this script; skip if no compiler. Relative "./"
# path so the LD_PRELOAD value has no space (see SSHD_ENV in start_sshd.sh).
PRELOAD_SRC="sshd_chroot_preload.c"
PRELOAD_LIB="./sshd_chroot_preload.so"
CC_BIN="${CC:-cc}"
if ! "$CC_BIN" -shared -fPIC -o "$PRELOAD_LIB" "$PRELOAD_SRC" -ldl 2>/dev/null; then
    echo "SKIP: could not build $PRELOAD_LIB with $CC_BIN"
    exit 77
fi

# The runner creates this in its setup step; a standalone run does not get that.
if [ ! -f authorized_keys_test ]; then
    ./create_authorized_test_file.sh || exit 1
fi

# start_sshd.sh hardcodes "-E ./log.txt", so the daemon appends here. Counts are
# read as before/after deltas rather than wiping the file, which keeps whatever
# the suite logged earlier in the run.
touch log.txt 2>/dev/null

# The chroot target has to exist. The point of faulting one step at a time is
# that the others would have succeeded, so a daemon missing the guard really
# does take them rather than failing on its own.
CHROOT_DIR="$TESTDIR/chroot_target"
mkdir -p "$CHROOT_DIR"

# One record per case, so a case never reads a file left by another.
TRACE_CHDIR_FAIL="$TESTDIR/chroot_trace_chdir_fail.txt"
TRACE_CHROOT_FAIL="$TESTDIR/chroot_trace_chroot_fail.txt"
TRACE_OK="$TESTDIR/chroot_trace_ok.txt"
sudo rm -f "$TRACE_CHDIR_FAIL" "$TRACE_CHROOT_FAIL" "$TRACE_OK"

# Echoed by the exec session. Present only when a shell actually ran.
TOKEN="wolfsshd_chroot_ok_$$"

cat <<EOF > sshd_config_test_chroot
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
ChrootDirectory $CHROOT_DIR
EOF

# Healthy control. "/" is the one chroot the daemon can complete and still find
# a shell in, so that case asserts the guarded code left a working chroot
# session working, not merely that chroot() was reached.
sed "s|^ChrootDirectory .*|ChrootDirectory /|" \
    sshd_config_test_chroot > sshd_config_test_chroot_ok

DEADLINE=30

# grep -c prints 0 and exits 1 when there is no match, so the count is usable as
# is. Do not add "|| echo 0": the fallback appends a second 0 and every later
# use of the count becomes a syntax error. Default the empty case instead, which
# is a missing or unreadable log.
# Read through sudo: start_sshd.sh launches the daemon under sudo, so in a
# suite run log.txt already exists owned by root, and the touch above only
# wins when the file is absent. sshd_pubkey_reject_test.sh reads the same
# file the same way.
log_count() {
    local n
    n=`sudo grep -c "$1" log.txt 2>/dev/null`
    echo "${n:-0}"
}

# Starts a daemon with $1 as its config and $2 as its SSHD_ENV, runs one exec
# session through it, and stops it again. Leaves the client output in
# $CLIENT_LOG and the per-case log deltas in NEW_SPAWN / NEW_CHDIR_FAIL /
# NEW_CHROOT_FAIL / NEW_SETUP_FAIL.
run_case() {
    CFG="$1"
    CASE_ENV="$2"
    LABEL="$3"

    BEFORE_SPAWN=`log_count "Spawned new process"`
    BEFORE_CHDIR_FAIL=`log_count "chdir to chroot path failed"`
    BEFORE_CHROOT_FAIL=`log_count "chroot failed to path"`
    BEFORE_SETUP_FAIL=`log_count "Error setting chroot"`

    SSHD_ENV="$CASE_ENV"
    export SSHD_BIN SSHD_ENV
    start_wolfsshd "$CFG"
    if [ -z "$PID" ]; then
        echo "FAIL: $LABEL daemon did not start"
        exit 1
    fi

    CLIENT_LOG="$TESTDIR/chroot_client_$LABEL.log"
    TIMEOUT=""
    if command -v timeout >/dev/null 2>&1; then
        TIMEOUT="timeout $DEADLINE"
    fi
    # The exit status is not checked: under a fault the session is killed from
    # the far side, and what matters is what the daemon did, not how the client
    # reported it. The output is kept, because a client that dies before opening
    # a socket leaves the daemon-side counts flat and looks like a daemon fault.
    $TIMEOUT "$TEST_CLIENT" -c "echo $TOKEN" -u "$USER" -i "$PRIVATE_KEY" \
        -j "$PUBLIC_KEY" -h "$TEST_HOST" -p "$TEST_PORT" \
        > "$CLIENT_LOG" 2>&1

    # The daemon logs from the connection process, so wait for the fork to show
    # up rather than assuming it landed before the client returned.
    WAITED=0
    while [ "$WAITED" -lt "$DEADLINE" ]; do
        NEW_SPAWN=`expr \`log_count "Spawned new process"\` - $BEFORE_SPAWN`
        if [ "$NEW_SPAWN" -gt 0 ]; then
            break
        fi
        sleep 1
        WAITED=`expr $WAITED + 1`
    done

    stop_wolfsshd
    PID=""

    NEW_SPAWN=`expr \`log_count "Spawned new process"\` - $BEFORE_SPAWN`
    NEW_CHDIR_FAIL=`expr \`log_count "chdir to chroot path failed"\` \
        - $BEFORE_CHDIR_FAIL`
    NEW_CHROOT_FAIL=`expr \`log_count "chroot failed to path"\` \
        - $BEFORE_CHROOT_FAIL`
    NEW_SETUP_FAIL=`expr \`log_count "Error setting chroot"\` \
        - $BEFORE_SETUP_FAIL`

    if [ "$NEW_SPAWN" -le 0 ]; then
        echo "FAIL: $LABEL daemon never forked a connection process"
        echo "  client said: `tail -n 3 "$CLIENT_LOG" | tr '\n' '|'`"
        exit 1
    fi
}

fail_case() {
    echo "FAIL: $1"
    shift
    for extra in "$@"; do
        echo "  $extra"
    done
    exit 1
}

# Case 1: the chdir into the chroot target fails. chroot() must not run.
run_case sshd_config_test_chroot \
    "LD_PRELOAD=$PRELOAD_LIB WOLFSSHD_FAULT_CHDIR_PATH=$CHROOT_DIR WOLFSSHD_FAULT_CHROOT_MARKER=$TRACE_CHDIR_FAIL" \
    chdir_fail

if [ "$NEW_CHDIR_FAIL" -le 0 ]; then
    fail_case "the chdir fault never fired, so nothing was tested" \
        "client said: `tail -n 3 "$TESTDIR/chroot_client_chdir_fail.log" | tr '\n' '|'`"
fi
if [ -e "$TRACE_CHDIR_FAIL" ]; then
    fail_case "chroot() ran after the chdir into the chroot path failed" \
        "recorded: `tr '\n' '|' < "$TRACE_CHDIR_FAIL"`"
fi
if [ "$NEW_SETUP_FAIL" -le 0 ]; then
    fail_case "the failed chroot setup was not reported to the caller"
fi
if grep -q "$TOKEN" "$TESTDIR/chroot_client_chdir_fail.log"; then
    fail_case "the session ran a command after the chroot setup failed"
fi
printf "  chdir_fail: chroot skipped and the session terminated\n"

# Case 2: the chdir succeeds and chroot() fails. The chdir("/") that would have
# followed must not run.
run_case sshd_config_test_chroot \
    "LD_PRELOAD=$PRELOAD_LIB WOLFSSHD_FAULT_CHROOT_FAIL=1 WOLFSSHD_FAULT_CHROOT_MARKER=$TRACE_CHROOT_FAIL" \
    chroot_fail

if [ "$NEW_CHROOT_FAIL" -le 0 ]; then
    fail_case "the chroot fault never fired, so nothing was tested" \
        "client said: `tail -n 3 "$TESTDIR/chroot_client_chroot_fail.log" | tr '\n' '|'`"
fi
if [ "$NEW_CHDIR_FAIL" -ne 0 ]; then
    fail_case "the chdir into the chroot path failed in the chroot-fault case"
fi
if ! grep -q "^chroot " "$TRACE_CHROOT_FAIL" 2>/dev/null; then
    fail_case "chroot() was never reached, so the record proves nothing"
fi
if grep -q "^chdir " "$TRACE_CHROOT_FAIL"; then
    fail_case "chdir() ran after chroot() failed" \
        "recorded: `tr '\n' '|' < "$TRACE_CHROOT_FAIL"`"
fi
if [ "$NEW_SETUP_FAIL" -le 0 ]; then
    fail_case "the failed chroot setup was not reported to the caller"
fi
if grep -q "$TOKEN" "$TESTDIR/chroot_client_chroot_fail.log"; then
    fail_case "the session ran a command after the chroot setup failed"
fi
printf "  chroot_fail: chdir skipped and the session terminated\n"

# Case 3: no fault. The same guarded code must still chroot, still chdir into
# the new root, and still run the command. The recorded chdir is also what makes
# its absence above meaningful.
run_case sshd_config_test_chroot_ok \
    "LD_PRELOAD=$PRELOAD_LIB WOLFSSHD_FAULT_CHROOT_MARKER=$TRACE_OK" \
    ok

if [ "$NEW_CHDIR_FAIL" -ne 0 ] || [ "$NEW_CHROOT_FAIL" -ne 0 ] || \
   [ "$NEW_SETUP_FAIL" -ne 0 ]; then
    fail_case "the unfaulted chroot setup failed"
fi
if ! grep -q "^chroot " "$TRACE_OK" 2>/dev/null; then
    fail_case "chroot() never ran on the healthy path"
fi
if ! grep -q "^chdir /$" "$TRACE_OK"; then
    fail_case "chdir into the new root never ran on the healthy path" \
        "recorded: `tr '\n' '|' < "$TRACE_OK"`"
fi
if ! grep -q "$TOKEN" "$TESTDIR/chroot_client_ok.log"; then
    fail_case "the chrooted session did not run its command" \
        "client said: `tail -n 3 "$TESTDIR/chroot_client_ok.log" | tr '\n' '|'`"
fi
printf "  ok: the whole sequence ran and the chrooted session worked\n"

echo "PASS: each chroot step is skipped after an earlier failure, and none otherwise"
exit 0
