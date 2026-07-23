#!/bin/bash

# OpenSSH certificate (user auth) test for wolfSSHd.
#
# Regenerates the OpenSSH user certificates for the login user via
# keys/renew-ossh-certs.sh (the certificate principal must match the login user,
# like the X.509 test which regenerates per-user via renewcerts.sh), starts
# wolfSSHd with TrustedUserCAKeys set to the signing CAs, and runs the same
# suite against two drivers:
#   * the wolfSSH example client (self-contained, always run when built), and
#   * the system OpenSSH "ssh" client (interop, run when ssh is present).
# Confirms a valid certificate is accepted and that an untrusted CA, a
# non-matching principal, an unknown critical option and a source-address
# mismatch are each rejected, and that force-command overrides the command.
#
# Requires: ssh-keygen and the wolfSSH client. Skips cleanly (77) when either is
# missing or wolfSSHd was not built with --enable-ossh-certs. The OpenSSH-client
# interop pass is skipped when "ssh" is unavailable.
#
# This is the gate for the CheckPublicKeyUnix OSSH orchestration (CA-trust ->
# principal -> validity -> source-address ordering); a deterministic unit-level
# test of that ordering is a deferred follow-up.
#
# On Windows, OpenSSH certificate auth is intentionally rejected outright
# (CheckPublicKeyWIN fails closed). That guard is compile-verified only (no
# Windows unit harness) and is a known untested edge; the cases here are Unix.

set +m  # quiet job-control "Terminated" notices when stopping the daemon

PWD0=$(pwd)
cd ../../..
ROOT=$(pwd)

skip() { echo "$1"; cd "$PWD0"; exit 77; }

# Only meaningful when wolfSSHd was built with OpenSSH certificate support.
grep -q "WOLFSSH_OSSH_CERTS" config.log 2>/dev/null || \
    skip "wolfSSHd not built with --enable-ossh-certs, skipping"

WOLFSSHD="$ROOT/apps/wolfsshd/wolfsshd"
CLIENT="$ROOT/examples/client/client"
PORT=${WOLFSSHD_TEST_PORT:-22226}
LOGINUSER=${SUDO_USER:-$(whoami)}

[ -x "$WOLFSSHD" ] || skip "wolfsshd not built, skipping OpenSSH cert test"
[ -x "$CLIENT" ]   || skip "wolfSSH client not built, skipping OpenSSH cert test"
command -v ssh-keygen >/dev/null 2>&1 || \
    skip "ssh-keygen not found, skipping OpenSSH cert test"

WORK=$(mktemp -d)
trap 'pkill -f "wolfsshd .*sshd_config_ossh" 2>/dev/null; rm -rf "$WORK"' EXIT

# Under sudo the daemon session runs as the login user: let it traverse $WORK
# and own the marker dir (not world-writable, so no other user can fake a PASS).
chmod 711 "$WORK"
MARKERDIR="$WORK/markers"
mkdir -p "$MARKERDIR"
chown "$LOGINUSER" "$MARKERDIR" 2>/dev/null
chmod 700 "$MARKERDIR"

# The host private key is a secret loaded through the secure gate, which refuses
# a group/world readable file. The committed key is 644, so use a 600 copy.
HOSTKEY="$WORK/hostkey.pem"
cp "$ROOT/keys/server-key.pem" "$HOSTKEY"
chmod 600 "$HOSTKEY"

# Issue certificates bound to the login user (and the negatives). The
# force-command marker is placed under the per-run work dir, not a fixed,
# world-readable /tmp path.
( cd "$ROOT/keys" && OSSH_FORCED_MARKER="$MARKERDIR/forced_marker" \
    ./renew-ossh-certs.sh "$LOGINUSER" )

# Trust all three signing CAs (Ed25519, RSA, ECDSA) but not ossh-bad-ca.
cat "$ROOT/keys/ossh-ca.pub" "$ROOT/keys/ossh-ca-rsa.pub" \
    "$ROOT/keys/ossh-ca-ecdsa.pub" > "$WORK/trusted-cas.pub"

cat > "$WORK/sshd_config_ossh" <<EOF
Port $PORT
Protocol 2
UsePrivilegeSeparation no
UseDNS no
PasswordAuthentication no
HostKey $HOSTKEY
TrustedUserCAKeys $WORK/trusted-cas.pub
EOF

FAIL=0
DRIVER=""

# Connect with the wolfSSH example client: -i private key, -j certificate.
connect_client() { # user-key  cert  remote-command
    "$CLIENT" -u "$LOGINUSER" -i "$1" -j "$2" \
        -h 127.0.0.1 -p $PORT -c "$3" >/dev/null 2>&1
}

# Connect with the system OpenSSH client.
connect_ssh() { # user-key  cert  remote-command
    ssh -p $PORT -i "$1" -o CertificateFile="$2" \
        -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=publickey \
        -o BatchMode=yes -o ConnectTimeout=5 \
        "$LOGINUSER@127.0.0.1" "$3" >/dev/null 2>&1
}

# (re)start the daemon, drive the selected client, return its exit code.
attempt() { # user-key  cert  [remote-command]
    pkill -f "wolfsshd .*sshd_config_ossh" 2>/dev/null
    sleep 1
    "$WOLFSSHD" -D -f "$WORK/sshd_config_ossh" -E "$WORK/sshd.log" &
    local wp=$!
    disown "$wp" 2>/dev/null
    sleep 1
    "connect_$DRIVER" "$1" "$2" "${3:-true}"
    local rc=$?
    kill $wp 2>/dev/null
    return $rc
}

check() { # label  user-key  cert  expect(0=accept,1=reject)
    attempt "$2" "$3"
    local rc=$?
    local got=1; [ $rc -eq 0 ] && got=0
    if [ $got -eq $4 ]; then
        printf "  %-20s %s\n" "$1" "PASS"
    else
        printf "  %-20s %s (rc=%d)\n" "$1" "*** FAIL" "$rc"
        FAIL=1
    fi
}

force_command_check() { # user-key  cert
    local forced="$MARKERDIR/forced_marker"
    local requested="$MARKERDIR/requested_marker"
    rm -f "$forced" "$requested"
    attempt "$1" "$2" "touch $requested"
    local rc=$?
    sleep 1
    if [ $rc -eq 0 ] && [ -f "$forced" ] && [ ! -f "$requested" ]; then
        printf "  %-20s %s\n" "force-command" "PASS"
    else
        printf "  %-20s %s (rc=%d forced=%s requested=%s)\n" "force-command" \
            "*** FAIL" "$rc" \
            "$([ -f "$forced" ] && echo yes || echo no)" \
            "$([ -f "$requested" ] && echo yes || echo no)"
        FAIL=1
    fi
    rm -f "$forced" "$requested"
}

ED="$ROOT/keys/ossh-user"
RSA="$ROOT/keys/ossh-user-rsa"
ECC="$ROOT/keys/ossh-user-ecdsa"
SFTP="$ROOT/examples/sftpclient/wolfsftp"
SCP="$ROOT/examples/scpclient/wolfscp"
SCPSRC="$WORK/scp_src.dat"
SCPDST="$WORK/scp_dst.dat"
echo "scp payload" > "$SCPSRC"

# (re)start the daemon, leaving its PID in DPID.
start_daemon() {
    pkill -f "wolfsshd .*sshd_config_ossh" 2>/dev/null
    sleep 1
    "$WOLFSSHD" -D -f "$WORK/sshd_config_ossh" -E "$WORK/sshd.log" &
    DPID=$!
    disown "$DPID" 2>/dev/null
    sleep 1
}

# Drive an SFTP session with the wolfSSH and system clients (echo a quit
# command so a granted session exits cleanly with no transfer). The clients
# report a non-zero exit code when the subsystem request is denied.
sftp_client() { # user-key  cert
    echo "exit" | "$SFTP" -u "$LOGINUSER" -i "$1" -j "$2" \
        -h 127.0.0.1 -p $PORT >/dev/null 2>&1
}
sftp_ssh() { # user-key  cert
    echo "bye" | sftp -P $PORT -i "$1" -o CertificateFile="$2" \
        -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
        -o PreferredAuthentications=publickey -o ConnectTimeout=5 \
        "$LOGINUSER@127.0.0.1" >/dev/null 2>&1
}

sftp_available() {
    if [ "$DRIVER" = client ]; then
        [ -x "$SFTP" ]
    else
        command -v sftp >/dev/null 2>&1
    fi
}

# Like check(), but drives an SFTP subsystem instead of a shell command.
sftp_check() { # label  user-key  cert  expect(0=accept,1=reject)
    start_daemon
    "sftp_$DRIVER" "$2" "$3"
    local rc=$?
    kill $DPID 2>/dev/null
    local got=1; [ $rc -eq 0 ] && got=0
    if [ $got -eq $4 ]; then
        printf "  %-20s %s\n" "$1" "PASS"
    else
        printf "  %-20s %s (rc=%d)\n" "$1" "*** FAIL" "$rc"
        FAIL=1
    fi
}

# Drive a native SCP upload with the wolfSSH client. wolfscp masks its exit
# code and the destination path resolves differently across platforms, so
# verify the server's enforcement decision from its log, not from a file.
scp_check() { # label  user-key  cert  expect(0=allowed,1=denied)
    [ -x "$SCP" ] || { echo "  ($1: wolfscp unavailable, skipping)"; return; }
    : > "$WORK/sshd.log"
    start_daemon
    "$SCP" -u "$LOGINUSER" -i "$2" -j "$3" \
        -S"$SCPSRC:$SCPDST" -H 127.0.0.1 -p $PORT >/dev/null 2>&1
    kill $DPID 2>/dev/null
    rm -f "$SCPDST"
    local got=0
    grep -q "denying SCP" "$WORK/sshd.log" 2>/dev/null && got=1
    if [ $got -eq $4 ]; then
        printf "  %-20s %s\n" "$1" "PASS"
    else
        printf "  %-20s %s\n" "$1" "*** FAIL"
        FAIL=1
    fi
}

run_suite() { # driver
    DRIVER=$1
    echo "OpenSSH cert test via $DRIVER client (user=$LOGINUSER, port=$PORT):"
    check "valid cert"        "$ED"  "$ROOT/keys/$LOGINUSER-ossh-cert.pub"                0
    check "RSA CA"            "$ED"  "$ROOT/keys/$LOGINUSER-ossh-rsaca-cert.pub"          0
    check "ECDSA CA"          "$ED"  "$ROOT/keys/$LOGINUSER-ossh-ecdsaca-cert.pub"        0
    check "RSA user key"      "$RSA" "$ROOT/keys/$LOGINUSER-ossh-rsauser-cert.pub"        0
    check "ECDSA user key"    "$ECC" "$ROOT/keys/$LOGINUSER-ossh-ecdsauser-cert.pub"      0
    check "untrusted CA"      "$ED"  "$ROOT/keys/$LOGINUSER-ossh-badca-cert.pub"          1
    check "wrong principal"   "$ED"  "$ROOT/keys/$LOGINUSER-ossh-wrongprincipal-cert.pub" 1
    check "empty principal"   "$ED"  "$ROOT/keys/$LOGINUSER-ossh-noprincipal-cert.pub"    1
    check "unknown crit opt"  "$ED"  "$ROOT/keys/$LOGINUSER-ossh-unkcrit-cert.pub"        1
    check "source-addr match" "$ED"  "$ROOT/keys/$LOGINUSER-ossh-srcok-cert.pub"         0
    check "source-addr deny"  "$ED"  "$ROOT/keys/$LOGINUSER-ossh-srcbad-cert.pub"        1
    check "expired cert"      "$ED"  "$ROOT/keys/$LOGINUSER-ossh-expired-cert.pub"       1
    force_command_check       "$ED"  "$ROOT/keys/$LOGINUSER-ossh-forcecmd-cert.pub"

    # A force-command must not be bypassed by requesting the SFTP subsystem.
    # "internal-sftp" still permits SFTP; any other force-command denies it.
    if sftp_available; then
        sftp_check "valid cert sftp"    "$ED" \
            "$ROOT/keys/$LOGINUSER-ossh-cert.pub"              0
        sftp_check "forcecmd sftp deny" "$ED" \
            "$ROOT/keys/$LOGINUSER-ossh-forcecmd-cert.pub"     1
        sftp_check "internal-sftp sftp" "$ED" \
            "$ROOT/keys/$LOGINUSER-ossh-internalsftp-cert.pub" 0
    else
        echo "  (sftp $DRIVER client unavailable, skipping sftp cases)"
    fi

    # Native SCP (an exec, not the SFTP subsystem) is denied under any
    # force-command, including "internal-sftp". Driven by the wolfSSH client
    # only; the system "scp" uses the SFTP protocol and is covered above.
    if [ "$DRIVER" = client ]; then
        scp_check "valid cert scp"      "$ED" \
            "$ROOT/keys/$LOGINUSER-ossh-cert.pub"              0
        scp_check "forcecmd scp deny"   "$ED" \
            "$ROOT/keys/$LOGINUSER-ossh-forcecmd-cert.pub"     1
        scp_check "internal-sftp scp"   "$ED" \
            "$ROOT/keys/$LOGINUSER-ossh-internalsftp-cert.pub" 1
    fi
}

# Primary, self-contained pass with the wolfSSH client.
run_suite client

# Interop pass with the OpenSSH client, when available.
if command -v ssh >/dev/null 2>&1; then
    run_suite ssh
else
    echo "ssh not found, skipping OpenSSH-client interop pass"
fi

cd "$PWD0"
if [ $FAIL -ne 0 ]; then
    echo "OpenSSH certificate test FAILED"
    exit 1
fi
echo "OpenSSH certificate test passed"
exit 0
