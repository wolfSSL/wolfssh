#!/bin/bash

echo "Running all wolfSSHd tests"

# Define an array of test cases
test_cases=(
 "sshd_exec_test.sh"
 "sshd_term_size_test.sh"
 "sshd_large_sftp_test.sh"
 "sshd_bad_sftp_test.sh"
 "sshd_scp_fail.sh"
 "sshd_term_close_test.sh"
 "ssh_kex_algos.sh"
)

# Set defaults
USER=$USER

# Parse arguments
MATCH=""
EXCLUDE=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --match)
            MATCH="$2"
            shift 2
            ;;

        --exclude)
            EXCLUDE="$2"
            shift 2
            ;;

        --user)
            USER="$2"
            shift 2
            ;;

        --host)
            TEST_HOST="$2"
            shift 2
            ;;

        --port)
            TEST_PORT="$2"
            shift 2
            ;;

        *)
            echo "Unknown option: $1"
            echo "Expecting --host <host> | --port <port> | --user <user> | --match <test case> | --exclude <test case>"
            echo "All test cases:"
            for test in "${test_cases[@]}"; do
                echo "    $test"
            done
            exit 1
            ;;
    esac
done

TOTAL=0
SKIPPED=0

# validate the requested test before any setup so a bad name does not leave
# a wolfSSHd running
if [[ -n "$MATCH" ]]; then
    MATCH_FOUND=0
    for test in "${test_cases[@]}"; do
        if [[ "$test" == "$MATCH" ]]; then
            MATCH_FOUND=1
            break
        fi
    done
    if [[ "$MATCH_FOUND" -eq 0 ]]; then
        echo "Error: Test '$MATCH' not found."
        echo "All test cases:"
        for test in "${test_cases[@]}"; do
            echo "    $test"
        done
        exit 1
    fi
fi

# setup
set -e
./create_authorized_test_file.sh
./create_sshd_config.sh $USER
set +e

if [ ! -z "$TEST_HOST" ] && [ ! -z "$TEST_PORT" ]; then
    USING_LOCAL_HOST=0
    echo "Connecting to external host $TEST_HOST:$TEST_PORT"
else
    USING_LOCAL_HOST=1
    source ./start_sshd.sh
    echo "Starting up local wolfSSHd for tests on 127.0.0.1:22222"
    TEST_HOST="127.0.0.1"
    TEST_PORT="22222"
    start_wolfsshd "sshd_config_test"
    if [ -z "$PID" ]; then
        echo "Issue starting up wolfSSHd"
        exit 1
    fi
fi

run_test() {
    printf "$1 ... "
    ./"$1" "$TEST_HOST" "$TEST_PORT" "$USER" &> stdout.txt
    RESULT=$?
    TOTAL=$((TOTAL+1))
    if [ "$RESULT" == 77 ]; then
        printf "SKIPPED\n"
        SKIPPED=$((SKIPPED+1))
    elif [ "$RESULT" == 0 ]; then
        printf "PASSED\n"
    else
        printf "FAILED!\n"
        cat stdout.txt
        if [ "$USING_LOCAL_HOST" == 1 ]; then
            printf "Shutting down test wolfSSHd\n"
            stop_wolfsshd
        fi
        exit 1
    fi
}

# Negative trust-anchor check: a group/world readable host private key must make
# wolfSSHd refuse to start. The host private key is a secret loaded through the
# secure gate (getBufferFromFile/wolfSSHD_OpenSecureFile in SetupCTX), which is
# always enforced and independent of StrictModes, so this config sets
# "StrictModes no" to prove the gate still rejects. Runs without sudo: privilege
# separation is off and a high port is used, so no root is needed.
run_strictmodes_negative_test() {
    printf "Host key trust-anchor negative test ... "
    # Use a relative host key path: wolfSSH log lines are capped at 120 chars,
    # so a long absolute path would truncate the "group or world readable"
    # message this test greps for.
    cp ../../../keys/server-key.pem strictmodes_hostkey.pem
    chmod 644 strictmodes_hostkey.pem
    cat <<EOF > sshd_config_test_strictmodes
Port 22622
StrictModes no
UsePrivilegeSeparation no
HostKey strictmodes_hostkey.pem
EOF
    rm -f strictmodes_log.txt
    # -D keeps wolfSSHd in the foreground; a StrictModes failure makes it exit
    # rather than serve, so this returns on its own. Wrap in 'timeout' when
    # available so a regression fails the test instead of hanging the runner.
    TIMEOUT=""
    if command -v timeout >/dev/null 2>&1; then
        TIMEOUT="timeout 30"
    fi
    $TIMEOUT ../wolfsshd -D -d -f sshd_config_test_strictmodes -E strictmodes_log.txt
    TOTAL=$((TOTAL+1))
    if grep -q "group or world readable" strictmodes_log.txt; then
        printf "PASSED\n"
    else
        printf "FAILED!\n"
        cat strictmodes_log.txt
        rm -f strictmodes_hostkey.pem sshd_config_test_strictmodes strictmodes_log.txt
        stop_wolfsshd
        exit 1
    fi
    rm -f strictmodes_hostkey.pem sshd_config_test_strictmodes strictmodes_log.txt
}

# Negative authorized_keys StrictModes test: a group/world writable
# authorized_keys file must make public-key authentication fail (exercises the
# StrictModes branch in SearchForPubKey). Uses the already-running local sshd,
# whose AuthorizedKeysFile is ./authorized_keys_test and whose log is ./log.txt.
run_strictmodes_authkeys_negative_test() {
    printf "StrictModes negative authorized_keys test ... "
    local tmo=""
    if command -v timeout >/dev/null 2>&1; then
        tmo="timeout 30"
    fi
    TOTAL=$((TOTAL+1))

    # Positive control: with safe 0644 perms the same client must succeed, so a
    # non-zero exit below can be attributed to the permission change rather than
    # an unrelated client/connection failure.
    chmod 0644 authorized_keys_test
    ( cd ../../.. && $tmo ./examples/client/client -c 'exit' -u "$USER" \
        -i ./keys/hansel-key-ecc.der -j ./keys/hansel-key-ecc.pub \
        -h "$TEST_HOST" -p "$TEST_PORT" ) > /dev/null 2>&1
    if [ "$?" != 0 ]; then
        printf "FAILED! (public-key auth failed with safe 0644 authorized_keys; setup issue)\n"
        stop_wolfsshd
        exit 1
    fi

    # Negative: a world-writable authorized_keys must make public-key auth fail
    # AND make the daemon log the StrictModes rejection, so the failure is for
    # the right reason and not an unrelated client error. Count existing
    # rejection lines first so a re-run is not confused by stale matches.
    local before
    before=$(grep -c "failed StrictModes check" log.txt 2>/dev/null || echo 0)
    chmod 0666 authorized_keys_test
    ( cd ../../.. && $tmo ./examples/client/client -c 'exit' -u "$USER" \
        -i ./keys/hansel-key-ecc.der -j ./keys/hansel-key-ecc.pub \
        -h "$TEST_HOST" -p "$TEST_PORT" ) > /dev/null 2>&1
    local result=$?
    chmod 0644 authorized_keys_test
    local after
    after=$(grep -c "failed StrictModes check" log.txt 2>/dev/null || echo 0)
    if [ "$result" != 0 ] && [ "$after" -gt "$before" ]; then
        printf "PASSED\n"
    else
        printf "FAILED! (expected StrictModes rejection: client exit=%s, new log matches=%s)\n" \
            "$result" "$((after - before))"
        stop_wolfsshd
        exit 1
    fi
}

# Self-contained check for the ownership and symlink gate in getBufferFromFile().
# The host key, host certificate, and user CA all load through the same
# getBufferFromFile(..., WOLFSSHD_LOAD_SECRET/WOLFSSHD_LOAD_TRUST) call, which
# delegates to wolfSSHD_OpenSecureFile(), so exercising the gate via the host
# key covers the identical code for the other two trust anchors. Starts a
# private wolfSSHd with substituted host keys and asserts startup is refused for
# a symlink, a group/world-writable file, and (when run as a non-root user with
# sudo) a file owned by another user, and accepted for a proper mode-600 regular
# file. Does not use the shared daemon, so it runs the same whether or not one
# was started.
run_hostkey_perm_check() {
    printf "host key ownership/symlink gate ... "
    TOTAL=$((TOTAL+1))

    HK_SSHD=../wolfsshd
    HK_KEY=../../../keys/server-key.pem
    HK_PORT=22399
    if [ ! -x "$HK_SSHD" ] || [ ! -f "$HK_KEY" ]; then
        printf "SKIPPED\n"
        SKIPPED=$((SKIPPED+1))
        return
    fi

    HK_WORK=$(mktemp -d 2>/dev/null) || HK_WORK=$(mktemp -d -t sshdperm)
    if [ -z "$HK_WORK" ] || [ ! -d "$HK_WORK" ]; then
        printf "SKIPPED (mktemp failed)\n"
        SKIPPED=$((SKIPPED+1))
        return
    fi

    cp "$HK_KEY" "$HK_WORK/hostkey.pem" || {
        printf "SKIPPED (could not prepare hostkey)\n"
        SKIPPED=$((SKIPPED+1))
        rm -rf "$HK_WORK"
        return
    }
    chmod 600 "$HK_WORK/hostkey.pem"
    touch "$HK_WORK/authorized_keys"
    hk_cfg() {
        cat > "$HK_WORK/cfg" <<EOF
Port $HK_PORT
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
UsePrivilegeSeparation no
UseDNS no
HostKey $1
AuthorizedKeysFile $HK_WORK/authorized_keys
EOF
    }

    # Load happens during startup before the listener; start, poll the log
    # rather than sleeping a fixed time, then stop. Both the host key load and
    # the listener emit a line, so stop as soon as either appears (max ~15s).
    # $1 (optional): "sudo" to launch the daemon as root for the owner branch.
    hk_run() {
        HK_PRE="$1"
        $HK_PRE "$HK_SSHD" -D -d -f "$HK_WORK/cfg" -p $HK_PORT > "$HK_WORK/log.txt" 2>&1 &
        HK_PID=$!
        i=0
        while [ $i -lt 15 ]; do
            if grep -qE "Listening on port|Refusing to load" "$HK_WORK/log.txt" 2>/dev/null; then
                break
            fi
            sleep 1
            i=$((i+1))
        done
        # When launched via sudo, $HK_PID is the sudo pid, not the daemon, and
        # sudo does not reliably forward the signal, so match the daemon by port.
        # This guarantees a regression cannot leave a root daemon bound to it.
        if [ -n "$HK_PRE" ]; then
            $HK_PRE pkill -f "$HK_SSHD.*$HK_PORT" 2>/dev/null
        else
            kill $HK_PID 2>/dev/null
        fi
        wait $HK_PID 2>/dev/null
    }

    hk_fail() {
        printf "FAILED!\n%s\n" "$1"
        cat "$HK_WORK/log.txt"
        rm -rf "$HK_WORK"
        if [ "$USING_LOCAL_HOST" == 1 ]; then
            printf "Shutting down test wolfSSHd\n"
            stop_wolfsshd
        fi
        exit 1
    }

    # proper mode-600 regular file must load. The only gate failure here is the
    # daemon refusing a properly-owned key; any other reason the daemon does not
    # reach the listener (port in use, environment cannot run the daemon) is
    # unrelated to the gate, so skip rather than fail the whole suite.
    hk_cfg "$HK_WORK/hostkey.pem"; hk_run
    if grep -q "Refusing to load" "$HK_WORK/log.txt"; then
        hk_fail "valid host key was refused"
    fi
    if ! grep -q "Listening on port" "$HK_WORK/log.txt"; then
        printf "SKIPPED (daemon could not listen)\n"
        SKIPPED=$((SKIPPED+1))
        rm -rf "$HK_WORK"
        return
    fi

    # symlink must be refused
    ln -s "$HK_WORK/hostkey.pem" "$HK_WORK/link.pem"
    hk_cfg "$HK_WORK/link.pem"; hk_run
    grep -q "Refusing to load" "$HK_WORK/log.txt" || hk_fail "symlinked host key was not refused"

    # non-regular file (FIFO) must be refused. Skip where mkfifo is unavailable.
    if mkfifo "$HK_WORK/fifo.pem" 2>/dev/null; then
        hk_cfg "$HK_WORK/fifo.pem"; hk_run
        grep -q "Refusing to load" "$HK_WORK/log.txt" || hk_fail "FIFO host key was not refused"
    fi

    # group/world-writable file must be refused
    cp "$HK_KEY" "$HK_WORK/ww.pem"; chmod 666 "$HK_WORK/ww.pem"
    hk_cfg "$HK_WORK/ww.pem"; hk_run
    grep -q "Refusing to load" "$HK_WORK/log.txt" || hk_fail "world-writable host key was not refused"

    # Owner-rejection branch (st_uid != 0 && st_uid != geteuid()): the primary
    # substitution vector. The mode-600 host key is owned by the invoking user,
    # so launching the daemon as root (euid 0) must refuse it. Needs a non-root
    # invoker and non-interactive sudo; skip the sub-case otherwise.
    if [ "`id -u`" -ne 0 ] && sudo -n true 2>/dev/null; then
        hk_cfg "$HK_WORK/hostkey.pem"; hk_run sudo
        grep -q "Refusing to load" "$HK_WORK/log.txt" || hk_fail "non-root-owned host key was not refused under root daemon"
    fi

    rm -rf "$HK_WORK"
    printf "PASSED\n"
}

# Run the tests
if [[ -n "$MATCH" ]]; then
    echo "Running test: $MATCH"
    run_test "$MATCH"

    if [ "$USING_LOCAL_HOST" == 1 ]; then
        printf "Shutting down test wolfSSHd\n"
        stop_wolfsshd
    fi
else
    echo "Running all tests..."
    for test in "${test_cases[@]}"; do
        if [[ "$test" != "$EXCLUDE" ]]; then
            echo "Running test: $test"
            run_test "$test"
        else
            echo "Test '$test' is excluded. Skipping."
            SKIPPED=$((SKIPPED+1))
        fi
    done

    #Github actions needs resolved for these test cases
    #run_test "error_return.sh"

    # add additional tests here, check on var USING_LOCAL_HOST if can make sshd
    # server start/restart with changes

    # trust-anchor ownership/symlink gate (host key, host cert, user CA). Runs a
    # private daemon, so it does not depend on the shared local sshd.
    run_hostkey_perm_check

    # exercise the authorized_keys StrictModes path against the running sshd
    if [ "$USING_LOCAL_HOST" == 1 ]; then
        run_strictmodes_authkeys_negative_test
    else
        SKIPPED=$((SKIPPED+1))
    fi

    if [ "$USING_LOCAL_HOST" == 1 ]; then
        printf "Shutting down test wolfSSHd\n"
        stop_wolfsshd
    fi

    # these tests require setting up an sshd
    if [ "$USING_LOCAL_HOST" == 1 ]; then
        run_test "sshd_forcedcmd_test.sh"
        run_test "sshd_window_full_test.sh"
        run_test "sshd_empty_password_test.sh"
        run_strictmodes_negative_test
        run_test "sshd_login_grace_test.sh"
        run_test "sshd_privdrop_fail_test.sh"
    else
        printf "Skipping tests that need to setup local SSHD\n"
        SKIPPED=$((SKIPPED+6))
    fi

    # these tests run with X509 sshd-config loaded
    if [ "$USING_LOCAL_HOST" == 1 ]; then
        start_wolfsshd "sshd_config_test_x509"
    fi
    run_test "sshd_x509_test.sh"
    if [ "$USING_LOCAL_HOST" == 1 ]; then
        printf "Shutting down test wolfSSHd\n"
        stop_wolfsshd
    fi
fi

# Teardown safety net: the start/stop pairs above stop each daemon they start,
# but background test daemons survive across CI steps that share this runner,
# and a later step (the valgrind "memory after close down" check) binds the same
# port 22222. Make sure no test daemon lingers when this script exits so that
# step does not fail with "tcp bind failed". Harmless when nothing is running.
if [ "$USING_LOCAL_HOST" == 1 ]; then
    sudo pkill -f "wolfsshd" 2>/dev/null || true
fi

printf "All tests ran, $TOTAL passed, $SKIPPED skipped\n"

exit 0
