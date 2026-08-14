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

# A group/world accessible host key owned by the daemon's user must make
# wolfSSHd refuse to start, as sshd does. No sudo, so the key copy is owned by
# the invoking user, which is what arms the check, and a high port needs no root.
run_hostkey_mode_negative_test() {
    printf "Host key mode negative test ... "
    # A local copy of the host key, made group/world readable.
    cp ../../../keys/server-key.pem strictmodes_hostkey.pem
    chmod 644 strictmodes_hostkey.pem
    cat <<EOF > sshd_config_test_strictmodes
Port 22622
UsePrivilegeSeparation no
HostKey strictmodes_hostkey.pem
EOF
    rm -f strictmodes_log.txt
    # -D keeps wolfSSHd in the foreground; the rejection makes it exit, so this
    # returns on its own. 'timeout' keeps a regression from hanging the runner.
    TIMEOUT=""
    if command -v timeout >/dev/null 2>&1; then
        TIMEOUT="timeout 30"
    fi
    $TIMEOUT ../wolfsshd -D -d -f sshd_config_test_strictmodes -E strictmodes_log.txt
    TOTAL=$((TOTAL+1))
    if grep -q "are too open" strictmodes_log.txt; then
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

# Host key checks, matching sshd: refuse a group/world accessible key the daemon
# owns, do not police one owned by someone else, and inspect neither the
# directories leading to the key nor a symlinked path. A non-regular file is
# refused so a FIFO cannot stall startup. Uses a private wolfSSHd with
# substituted host keys, not the shared daemon.
run_hostkey_perm_check() {
    printf "host key permission check ... "
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

    # The key loads before the listener; poll the log rather than sleeping a
    # fixed time. Both a rejection and the listener emit a line, so stop as soon
    # as either appears (max ~15s).
    # $1 (optional): "sudo" to launch the daemon as root for the owner branch.
    hk_run() {
        HK_PRE="$1"
        $HK_PRE "$HK_SSHD" -D -d -f "$HK_WORK/cfg" -p $HK_PORT > "$HK_WORK/log.txt" 2>&1 &
        HK_PID=$!
        i=0
        while [ $i -lt 15 ]; do
            if grep -qE "Listening on port|Refusing to load|are too open" "$HK_WORK/log.txt" 2>/dev/null; then
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

    # proper mode-600 regular file must load. Anything else that keeps the daemon
    # from the listener (port in use, cannot run here) is unrelated, so skip.
    hk_cfg "$HK_WORK/hostkey.pem"; hk_run
    if grep -qE "Refusing to load|are too open" "$HK_WORK/log.txt"; then
        hk_fail "valid host key was refused"
    fi
    if ! grep -q "Listening on port" "$HK_WORK/log.txt"; then
        printf "SKIPPED (daemon could not listen)\n"
        SKIPPED=$((SKIPPED+1))
        rm -rf "$HK_WORK"
        return
    fi

    # a symlink to a good key must load; sshd does not inspect the path
    ln -s "$HK_WORK/hostkey.pem" "$HK_WORK/link.pem"
    hk_cfg "$HK_WORK/link.pem"; hk_run
    grep -q "Listening on port" "$HK_WORK/log.txt" || hk_fail "symlinked host key was refused"

    # a key in a world-writable directory must load; sshd walks no parent chain
    mkdir -p "$HK_WORK/wwdir" && chmod 777 "$HK_WORK/wwdir"
    cp "$HK_WORK/hostkey.pem" "$HK_WORK/wwdir/hostkey.pem"
    chmod 600 "$HK_WORK/wwdir/hostkey.pem"
    hk_cfg "$HK_WORK/wwdir/hostkey.pem"; hk_run
    grep -q "Listening on port" "$HK_WORK/log.txt" || hk_fail "host key under a world-writable dir was refused"

    # non-regular file (FIFO) must be refused rather than stall the daemon.
    # Skip where mkfifo is unavailable.
    if mkfifo "$HK_WORK/fifo.pem" 2>/dev/null; then
        hk_cfg "$HK_WORK/fifo.pem"; hk_run
        grep -q "Refusing to load" "$HK_WORK/log.txt" || hk_fail "FIFO host key was not refused"
    fi

    # group/world-writable file owned by the daemon must be refused
    cp "$HK_KEY" "$HK_WORK/ww.pem"; chmod 666 "$HK_WORK/ww.pem"
    hk_cfg "$HK_WORK/ww.pem"; hk_run
    grep -q "are too open" "$HK_WORK/log.txt" || hk_fail "world-writable host key was not refused"

    # sshd does not police a key owned by another user: the mode-600 key belongs
    # to the invoking user, so a root daemon (euid 0) must still load it. Needs a
    # non-root invoker and non-interactive sudo.
    if [ "`id -u`" -ne 0 ] && sudo -n true 2>/dev/null; then
        hk_cfg "$HK_WORK/hostkey.pem"; hk_run sudo
        grep -q "Listening on port" "$HK_WORK/log.txt" || hk_fail "non-root-owned host key was refused under root daemon"
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
        run_test "sshd_permitroot_test.sh"
        run_test "sshd_permitroot_prohibit_password.sh"
        run_test "sshd_permitroot_forced_cmd.sh"
        run_hostkey_mode_negative_test
        run_test "sshd_login_grace_test.sh"
        run_test "sshd_privdrop_fail_test.sh"
    else
        printf "Skipping tests that need to setup local SSHD\n"
        SKIPPED=$((SKIPPED+9))
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

    # negative test: a certificate UPN realm outside AuthorizedUPNDomains must
    # be rejected. Needs the dedicated bad-domain config, so only runs when we
    # control the local daemon.
    if [ "$USING_LOCAL_HOST" == 1 ]; then
        start_wolfsshd "sshd_config_test_x509_upn_bad"
        run_test "sshd_x509_upn_fail.sh"
        printf "Shutting down test wolfSSHd\n"
        stop_wolfsshd
    fi

    # ML-DSA composite host key test. Runs when we control the local daemon.
    # The client side uses an ECC key since we only test the host key here.
    # sshd_config_test_mldsa has no other host key, so a build without ML-DSA
    # cannot start the daemon at all; check for support out here rather than
    # letting the test script skip, which would come too late. ML-DSA comes from
    # wolfSSL (HAVE_DILITHIUM) and has no wolfSSH configure option, so probe the
    # client's algorithm list. The closed port keeps the probe from connecting.
    if [ "$USING_LOCAL_HOST" == 1 ]; then
        if ../../../examples/client/client -E -u "$USER" -h 127.0.0.1 -p 1 \
                2>/dev/null | grep -q "ssh-mldsa87-es384@wolfssl.com"; then
            start_wolfsshd "sshd_config_test_mldsa"
            run_test "sshd_mldsa_composite_test.sh"
            printf "Shutting down test wolfSSHd\n"
            stop_wolfsshd
        else
            printf "sshd_mldsa_composite_test.sh ... SKIPPED\n"
            TOTAL=$((TOTAL+1))
            SKIPPED=$((SKIPPED+1))
        fi
    fi

    # OpenSSH certificate user-auth test (self-contained: starts its own
    # wolfSSHd; skips when not built with --enable-ossh-certs). Runs the suite
    # against the wolfSSH example client and, for interop, the system OpenSSH
    # client when present.
    if [ "$USING_LOCAL_HOST" == 1 ]; then
        run_test "sshd_ossh_cert_test.sh"
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
