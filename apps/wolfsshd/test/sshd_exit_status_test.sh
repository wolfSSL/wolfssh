#!/bin/bash

# Exit-status regression: the POSIX daemon used to end StartSSHD() with an
# unconditional "return 0", so a config check (-t) of a bad config, or any
# other startup failure, exited 0. Every case runs in -D -t mode, so nothing
# daemonizes or binds a port.

TESTDIR=`pwd`
ROOT="$TESTDIR/../../.."

SSHD_BIN="../wolfsshd"
if [ ! -x "$SSHD_BIN" ]; then
    echo "SKIP: $SSHD_BIN not built"
    exit 77
fi

cleanup() {
    rm -f sshd_config_test_exit exit_status_hostkey.pem
    return 0
}
trap cleanup EXIT

# The host key gate wants an owner-only file; the checked-in key is 0644.
cp "$ROOT/keys/server-key.pem" exit_status_hostkey.pem
chmod 600 exit_status_hostkey.pem

# $1: host key path
write_config() {
    cat <<EOF > sshd_config_test_exit
Protocol 2
UsePrivilegeSeparation no
UseDNS no
HostKey $1
EOF
}

# $1: expected status, "zero" or "nonzero"; $2: description; rest: arguments
expect_status() {
    local want="$1" what="$2" ret
    shift 2
    "$SSHD_BIN" -D -t -E /dev/null "$@" < /dev/null > /dev/null 2>&1
    ret=$?
    if [ "$want" = "zero" ] && [ "$ret" -ne 0 ]; then
        echo "FAIL: $what exited $ret, expected 0"
        exit 1
    fi
    if [ "$want" = "nonzero" ] && [ "$ret" -eq 0 ]; then
        echo "FAIL: $what exited 0"
        exit 1
    fi
    echo "ok: $what exited $ret"
}

write_config "$TESTDIR/exit_status_hostkey.pem"
expect_status zero "valid config" -f sshd_config_test_exit
expect_status nonzero "missing config file" -f "$TESTDIR/no_such_sshd_config"
expect_status nonzero "invalid -p" -f sshd_config_test_exit -p 70000

write_config "$TESTDIR/no_such_hostkey.pem"
expect_status nonzero "missing host key" -f sshd_config_test_exit

echo "PASS: wolfsshd exit status reflects startup failures"
exit 0
