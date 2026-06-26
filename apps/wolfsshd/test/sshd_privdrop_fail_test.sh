#!/bin/bash

# Fail-closed privilege-drop regression: when the per-connection drop fails, the
# subsystem handlers must terminate the child, not continue as root. The drop is
# forced to fail against the stock wolfsshd with an LD_PRELOAD interposer
# (sshd_privdrop_preload.c), so no fault code lives in the daemon or library.
# Drives all three dropping subsystems: exec/shell, sftp, scp.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_privdrop_fail_test.sh 127.0.0.1 22222"
    exit 1
fi

PWD=`pwd`
USER=`whoami`
TEST_HOST="$1"

# Own daemon on a dedicated port for isolation from the runner's shared daemon.
TEST_PORT="22822"

SSHD_BIN="../wolfsshd"
if [ ! -x "$SSHD_BIN" ]; then
    echo "SKIP: $SSHD_BIN not built"
    exit 77
fi

# macOS strips DYLD_INSERT_LIBRARIES from the sudo-launched daemon, so Linux only.
if [ "`uname -s`" != "Linux" ]; then
    echo "SKIP: privilege-drop fault injection needs Linux LD_PRELOAD"
    exit 77
fi

# Build the interposer next to this script; skip if no compiler. Relative "./"
# path so the LD_PRELOAD value has no space (see SSHD_ENV in start_sshd.sh).
PRELOAD_SRC="sshd_privdrop_preload.c"
PRELOAD_LIB="./sshd_privdrop_preload.so"
CC_BIN="${CC:-cc}"
if ! "$CC_BIN" -shared -fPIC -o "$PRELOAD_LIB" "$PRELOAD_SRC" -ldl 2>/dev/null; then
    echo "SKIP: could not build $PRELOAD_LIB with $CC_BIN"
    exit 77
fi

if [ -f ./log.txt ]; then
    sudo rm -rf log.txt
fi
touch log.txt

TEST_CLIENT="../../../examples/client/client"
SFTP_CLIENT="../../../examples/sftpclient/wolfsftp"
SCP_CLIENT="../../../examples/scpclient/wolfscp"
PRIVATE_KEY="../../../keys/hansel-key-ecc.der"
PUBLIC_KEY="../../../keys/hansel-key-ecc.pub"

# Small payload for the sftp/scp transfers. The connection dies at the failed
# drop long before any data moves, so the contents do not matter.
PAYLOAD="privdrop_payload.txt"
echo "privdrop" > "$PAYLOAD"

source ./start_sshd.sh

cat <<EOF > sshd_config_test_privdrop
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
EOF

# Preload and arm the interposer via SSHD_ENV (start_sshd.sh passes it through
# "sudo env"). "UsePrivilegeSeparation no" is the worst case: old fallback = noop.
SSHD_ENV="LD_PRELOAD=$PRELOAD_LIB WOLFSSHD_FAULT_PRIVDROP=1"
export SSHD_BIN SSHD_ENV

# Teardown on every exit path; log.txt is kept for debugging like the other tests.
cleanup() {
    stop_wolfsshd
    rm -f sshd_config_test_privdrop "$PAYLOAD" "$PRELOAD_LIB"
    return 0
}
trap cleanup EXIT

start_wolfsshd "sshd_config_test_privdrop"

if [ -z "$PID" ]; then
    echo "FAIL: privilege-drop daemon did not start"
    exit 1
fi

DEADLINE=30

# Drives one client; the connection dies, so its exit status is not checked.
# Counts are per-call deltas since all three subsystems share the one log.
check_subsystem() {
    LABEL="$1"
    shift

    BEFORE_DROP=`grep -c "Error setting user ID" log.txt`
    BEFORE_CLOSE=`grep -c "Attempting to close down connection" log.txt`
    BEFORE_SPAWN=`grep -c "Spawned new process" log.txt`

    "$@" > /dev/null 2>&1 &
    CLIENT_PID=$!

    # Wait for the connection child to fork and hit the failed drop, then take
    # its real pid from the daemon's own "Spawned new process" log line.
    WAITED=0
    CHILD=""
    while [ "$WAITED" -lt "$DEADLINE" ]; do
        AFTER_SPAWN=`grep -c "Spawned new process" log.txt`
        AFTER_DROP=`grep -c "Error setting user ID" log.txt`
        if [ "$AFTER_SPAWN" -gt "$BEFORE_SPAWN" ] && \
           [ "$AFTER_DROP" -gt "$BEFORE_DROP" ]; then
            CHILD=`grep "Spawned new process" log.txt | tail -1 | \
                sed -n 's/.*process \([0-9][0-9]*\).*/\1/p'`
            break
        fi
        sleep 1
        WAITED=`expr $WAITED + 1`
    done

    kill $CLIENT_PID > /dev/null 2>&1
    wait $CLIENT_PID > /dev/null 2>&1

    if [ -z "$CHILD" ]; then
        echo "FAIL: $LABEL never reached the privilege drop"
        exit 1
    fi

    # Positive fail-closed signal: that child must terminate. Wait for it to
    # exit, on its own DEADLINE budget separate from the detection loop above.
    EXITED=0
    while [ "$EXITED" -lt "$DEADLINE" ] && ps -p "$CHILD" > /dev/null 2>&1; do
        sleep 1
        EXITED=`expr $EXITED + 1`
    done
    if ps -p "$CHILD" > /dev/null 2>&1; then
        echo "FAIL: $LABEL connection process still running after ${DEADLINE}s"
        exit 1
    fi

    # The buggy path logs this before exiting; the fix exit(1)s before the gate.
    # The child is gone, so the line is either present now or never.
    AFTER_CLOSE=`grep -c "Attempting to close down connection" log.txt`
    if [ "$AFTER_CLOSE" -gt "$BEFORE_CLOSE" ]; then
        echo "FAIL: $LABEL handler continued after a failed privilege drop"
        exit 1
    fi

    printf "  %s: connection process terminated on privilege-drop failure\n" \
        "$LABEL"
}

# SHELL_Subsystem, via an exec session.
check_subsystem "exec" \
    "$TEST_CLIENT" -c 'echo privdrop' -u "$USER" -i "$PRIVATE_KEY" \
    -j "$PUBLIC_KEY" -h "$TEST_HOST" -p "$TEST_PORT"

# SFTP_Subsystem. -g is a one-shot put, so the client cannot sit at a prompt.
check_subsystem "sftp" \
    "$SFTP_CLIENT" -u "$USER" -i "$PRIVATE_KEY" -j "$PUBLIC_KEY" \
    -g -l "$PAYLOAD" -r "/tmp/privdrop_remote_$$.txt" \
    -h "$TEST_HOST" -p "$TEST_PORT"

# SCP_Subsystem.
check_subsystem "scp" \
    "$SCP_CLIENT" -u "$USER" -i "$PRIVATE_KEY" -j "$PUBLIC_KEY" \
    -S"$PWD/$PAYLOAD:." -H "$TEST_HOST" -p "$TEST_PORT"

echo "PASS: all subsystems terminate on privilege-drop failure"
exit 0
