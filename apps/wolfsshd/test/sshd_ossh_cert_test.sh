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
. ./wolfssh_options.sh
cd ../../..
ROOT=$(pwd)

skip() { echo "$1"; cd "$PWD0"; exit 77; }

# Only meaningful when wolfSSHd was built with OpenSSH certificate support.
wolfssh_has OSSH_CERTS || \
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
# A failed mktemp would root every path below at "", the trap's "rm -rf" with
# them, so stop here rather than run the test against the filesystem root.
if [ -z "$WORK" ] || [ ! -d "$WORK" ]; then
    echo "FAIL: could not create a work directory for the OpenSSH cert test"
    exit 1
fi

# pid of the daemon this script started, and whether it was up for the whole of
# the last attempt. Every case checks DAEMON_UP: without it a daemon that never
# started scores each rejection case as a pass, since the client fails either
# way. Defined ahead of the trap below, which calls stop_daemon.
DPID=""
DAEMON_UP=0

daemon_alive() { # pid
    [ -n "$1" ] || return 1
    kill -0 "$1" 2>/dev/null || return 1
    # kill -0 alone is not enough. The daemon is disowned, so when it exits the
    # shell never reaps it and the pid lingers as a zombie that kill -0 reports
    # as alive.
    case "$(ps -o stat= -p "$1" 2>/dev/null)" in
        Z*) return 1 ;;
    esac
    return 0
}

# Is our daemon listening on the test port? The listening table is the readiness
# condition that matters, and unlike the daemon's log it does not depend on the
# daemon running with -d: wolfSSHDLoggingCb() writes only WS_LOG_ERROR lines
# otherwise, so the "Listening on port" line is absent here.
#
# Where the table names the owning pid, require it to be ours: something else
# already holding the port is why wolfsshd would fail to bind, and reading that
# listener as "ready" sends every client at it instead of reporting the real
# problem. Fall back to the port being bound at all when the owner is not
# visible (no -p support, or no permission to see it).
port_listening() {
    local rows=""

    if command -v ss >/dev/null 2>&1; then
        rows=$(ss -ltnp 2>/dev/null | grep ":$PORT[[:space:]]")
    elif command -v netstat >/dev/null 2>&1; then
        rows=$(netstat -ltnp 2>/dev/null | grep ":$PORT[[:space:]]")
    else
        # Last resort: a completed connect proves a listener. The daemon forks
        # a child for it that exits when the probe closes.
        (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null
        return $?
    fi

    # No usable rows is "owner unknown", not "not listening": BSD netstat
    # has no -p flag and spells the address 127.0.0.1.PORT, so the query
    # above yields nothing there. Fall through to the connect probe rather
    # than report the daemon down on every poll.
    if [ -z "$rows" ]; then
        (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null
        return $?
    fi
    case "$rows" in
        *"pid=$DPID,"*|*" $DPID/"*) return 0 ;;  # ss and netstat spellings
        *pid=*|*[0-9]/*)            return 1 ;;  # owner shown, and not ours
    esac
    return 0
}

# Stop the daemon and wait for the pid to go, so the next start does not race
# the port. Connections are served by forked children that close the listening
# socket, so they do not hold the port once the parent is gone.
stop_daemon() {
    local i=0

    [ -n "$DPID" ] || return 0
    kill "$DPID" 2>/dev/null
    while [ $i -lt 50 ] && daemon_alive "$DPID"; do
        sleep 0.1
        i=$((i+1))
    done
    # DPID is the only handle left now that the pattern-matched pkill is
    # gone, so a daemon that outlived SIGTERM must not be dropped here: it
    # would hold the port and the next start would report "never listened"
    # instead of the real cause.
    if daemon_alive "$DPID"; then
        kill -9 "$DPID" 2>/dev/null
        i=0
        while [ $i -lt 50 ] && daemon_alive "$DPID"; do
            sleep 0.1
            i=$((i+1))
        done
    fi
    DPID=""
}

# (re)start the daemon and wait until it is listening, leaving its pid in DPID.
# Returns non-zero, with DAEMON_UP still 0, when it never came up.
start_daemon() {
    local i=0

    stop_daemon
    # Cleared here rather than in stop_daemon: it has to outlive the daemon so
    # a case can still read it after its attempt has torn the daemon down.
    DAEMON_UP=0
    # Truncate: the poll below would otherwise be satisfied by the previous
    # daemon's line.
    : > "$WORK/sshd.log"
    "$WOLFSSHD" -D -f "$CONFIG" -E "$WORK/sshd.log" &
    DPID=$!
    disown "$DPID" 2>/dev/null

    # Poll for the listening socket instead of sleeping a fixed second, so a
    # client cannot race the bind and a daemon that never gets there is caught.
    # Liveness is checked first: if the daemon died on a bind failure, whatever
    # else holds the port must not be read as our daemon being ready.
    while [ $i -lt 100 ]; do
        daemon_alive "$DPID" || break
        if port_listening; then
            DAEMON_UP=1
            return 0
        fi
        sleep 0.1
        i=$((i+1))
    done

    printf "  %-20s %s\n" "daemon startup" "*** FAIL (never listened on $PORT)"
    tail -5 "$WORK/sshd.log" 2>/dev/null | sed 's/^/      /'
    stop_daemon
    FAIL=1
    return 1
}

# Stop by recorded pid rather than by command-line pattern: a pattern match can
# reach another user's wolfsshd on a shared host.
trap 'stop_daemon; rm -rf "$WORK"' EXIT

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

# Issue certificates bound to the login user (and the negatives), into this
# run's own directory. Written into keys/ they carried only the login user in
# their names, so two runs overwrote each other's: both principals matched,
# and the force-command certificate names the marker directory of whichever
# run issued it last, so a run could authenticate with the other's certificate
# and then fail its own marker assertion. Only the keypairs are shared, and
# those are committed. The force-command marker likewise goes under the
# per-run work dir, not a fixed, world-readable /tmp path.
CERTS="$WORK/certs"
mkdir -p "$CERTS"
chmod 755 "$CERTS"
( cd "$ROOT/keys" && OSSH_FORCED_MARKER="$MARKERDIR/forced_marker" \
    OSSH_CERT_DIR="$CERTS" ./renew-ossh-certs.sh "$LOGINUSER" )

# Trust all three signing CAs (Ed25519, RSA, ECDSA) but not ossh-bad-ca.
cat "$ROOT/keys/ossh-ca.pub" "$ROOT/keys/ossh-ca-rsa.pub" \
    "$ROOT/keys/ossh-ca-ecdsa.pub" > "$WORK/trusted-cas.pub"
# TrustedUserCAKeys is a trust anchor loaded through the secure gate, which
# refuses a group or world writable file. The redirection above leaves it at the
# process umask, so under the 002 default the daemon would refuse to start.
chmod 644 "$WORK/trusted-cas.pub"

cat > "$WORK/sshd_config_ossh" <<EOF
Port $PORT
Protocol 2
UsePrivilegeSeparation no
UseDNS no
PasswordAuthentication no
HostKey $HOSTKEY
TrustedUserCAKeys $WORK/trusted-cas.pub
EOF

# Second config, adding a ForceCommand that is not "internal-sftp". Used to
# separate the config-sourced command from the certificate's.
cat > "$WORK/sshd_config_ossh_fc" <<EOF
Port $PORT
Protocol 2
UsePrivilegeSeparation no
UseDNS no
PasswordAuthentication no
HostKey $HOSTKEY
TrustedUserCAKeys $WORK/trusted-cas.pub

Match User $LOGINUSER
	ForceCommand /bin/echo
EOF

CONFIG="$WORK/sshd_config_ossh"
FAIL=0
DRIVER=""

# The wolfSSH clients have no connect timeout of their own, so anything that
# accepts on the port but never speaks SSH would hang the suite. The OpenSSH
# driver below carries its own ConnectTimeout.
TIMEOUT=""
command -v timeout >/dev/null 2>&1 && TIMEOUT="timeout 30"

# timeout(1) exits 124 when it kills the client. Any nonzero status would
# otherwise score as a rejection, so a daemon that stalls on a negative case
# would pass it.
timed_out() { # label  rc
    [ -n "$TIMEOUT" ] && [ "$2" -eq 124 ] || return 1
    printf "  %-20s %s\n" "$1" "*** FAIL (client timed out)"
    FAIL=1
}

# Connect with the wolfSSH example client: -i private key, -j certificate.
connect_client() { # user-key  cert  remote-command
    $TIMEOUT "$CLIENT" -u "$LOGINUSER" -i "$1" -j "$2" \
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
    start_daemon || return 1
    "connect_$DRIVER" "$1" "$2" "${3:-true}"
    local rc=$?
    # A daemon that died while serving the connection would score a rejection
    # case as a pass, so only trust rc if it is still there.
    if ! daemon_alive "$DPID"; then
        printf "      wolfsshd exited while handling the connection\n"
        tail -5 "$WORK/sshd.log" 2>/dev/null | sed 's/^/      /'
        DAEMON_UP=0
    fi
    stop_daemon
    return $rc
}

check() { # label  user-key  cert  expect(0=accept,1=reject)
    attempt "$2" "$3"
    local rc=$?
    if [ $DAEMON_UP -ne 1 ]; then
        printf "  %-20s %s\n" "$1" "*** FAIL (no running daemon)"
        FAIL=1
        return
    fi
    timed_out "$1" $rc && return
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
    local i=0
    rm -f "$forced" "$requested"
    attempt "$1" "$2" "touch $requested"
    local rc=$?
    if [ $DAEMON_UP -ne 1 ]; then
        printf "  %-20s %s\n" "force-command" "*** FAIL (no running daemon)"
        FAIL=1
        return
    fi
    # The forced command runs server side, so poll for its marker rather than
    # sleeping a fixed second and deciding on whatever has landed by then.
    while [ $i -lt 50 ] && [ ! -f "$forced" ]; do
        sleep 0.1
        i=$((i+1))
    done
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

# Drive an SFTP session with the wolfSSH and system clients (echo a quit
# command so a granted session exits cleanly with no transfer). The clients
# report a non-zero exit code when the subsystem request is denied.
sftp_client() { # user-key  cert
    echo "exit" | $TIMEOUT "$SFTP" -u "$LOGINUSER" -i "$1" -j "$2" \
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
    start_daemon || { printf "  %-20s %s\n" "$1" "*** FAIL (no running daemon)"
        FAIL=1; return; }
    "sftp_$DRIVER" "$2" "$3"
    local rc=$?
    if ! daemon_alive "$DPID"; then
        printf "  %-20s %s\n" "$1" "*** FAIL (wolfsshd exited while serving)"
        tail -5 "$WORK/sshd.log" 2>/dev/null | sed 's/^/      /'
        FAIL=1
        stop_daemon
        return
    fi
    stop_daemon
    timed_out "$1" $rc && return
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
    start_daemon || { printf "  %-20s %s\n" "$1" "*** FAIL (no running daemon)"
        FAIL=1; return; }
    $TIMEOUT "$SCP" -u "$LOGINUSER" -i "$2" -j "$3" \
        -S"$SCPSRC:$SCPDST" -H 127.0.0.1 -p $PORT >/dev/null 2>&1
    if ! daemon_alive "$DPID"; then
        printf "  %-20s %s\n" "$1" "*** FAIL (wolfsshd exited while serving)"
        tail -5 "$WORK/sshd.log" 2>/dev/null | sed 's/^/      /'
        FAIL=1
        stop_daemon
        rm -f "$SCPDST"
        return
    fi
    stop_daemon
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
    check "valid cert"        "$ED"  "$CERTS/$LOGINUSER-ossh-cert.pub"                0
    check "RSA CA"            "$ED"  "$CERTS/$LOGINUSER-ossh-rsaca-cert.pub"          0
    check "ECDSA CA"          "$ED"  "$CERTS/$LOGINUSER-ossh-ecdsaca-cert.pub"        0
    check "RSA user key"      "$RSA" "$CERTS/$LOGINUSER-ossh-rsauser-cert.pub"        0
    check "ECDSA user key"    "$ECC" "$CERTS/$LOGINUSER-ossh-ecdsauser-cert.pub"      0
    check "untrusted CA"      "$ED"  "$CERTS/$LOGINUSER-ossh-badca-cert.pub"          1
    check "wrong principal"   "$ED"  "$CERTS/$LOGINUSER-ossh-wrongprincipal-cert.pub" 1
    check "empty principal"   "$ED"  "$CERTS/$LOGINUSER-ossh-noprincipal-cert.pub"    1
    check "unknown crit opt"  "$ED"  "$CERTS/$LOGINUSER-ossh-unkcrit-cert.pub"        1
    check "source-addr match" "$ED"  "$CERTS/$LOGINUSER-ossh-srcok-cert.pub"         0
    check "source-addr deny"  "$ED"  "$CERTS/$LOGINUSER-ossh-srcbad-cert.pub"        1
    check "expired cert"      "$ED"  "$CERTS/$LOGINUSER-ossh-expired-cert.pub"       1
    force_command_check       "$ED"  "$CERTS/$LOGINUSER-ossh-forcecmd-cert.pub"

    # A force-command must not be bypassed by requesting the SFTP subsystem.
    # "internal-sftp" still permits SFTP; any other force-command denies it.
    if sftp_available; then
        sftp_check "valid cert sftp"    "$ED" \
            "$CERTS/$LOGINUSER-ossh-cert.pub"              0
        sftp_check "forcecmd sftp deny" "$ED" \
            "$CERTS/$LOGINUSER-ossh-forcecmd-cert.pub"     1
        sftp_check "internal-sftp sftp" "$ED" \
            "$CERTS/$LOGINUSER-ossh-internalsftp-cert.pub" 0

        # A configured ForceCommand is not a certificate force-command: on its
        # own it must not deny SFTP, and it must not mask one carried by a
        # certificate.
        CONFIG="$WORK/sshd_config_ossh_fc"
        sftp_check "config forcecmd sftp" "$ED" \
            "$CERTS/$LOGINUSER-ossh-cert.pub"              0
        sftp_check "config+cert sftp deny" "$ED" \
            "$CERTS/$LOGINUSER-ossh-forcecmd-cert.pub"     1
        CONFIG="$WORK/sshd_config_ossh"
    else
        echo "  (sftp $DRIVER client unavailable, skipping sftp cases)"
    fi

    # Native SCP (an exec, not the SFTP subsystem) is denied under any
    # force-command, including "internal-sftp". Driven by the wolfSSH client
    # only; the system "scp" uses the SFTP protocol and is covered above.
    if [ "$DRIVER" = client ]; then
        scp_check "valid cert scp"      "$ED" \
            "$CERTS/$LOGINUSER-ossh-cert.pub"              0
        scp_check "forcecmd scp deny"   "$ED" \
            "$CERTS/$LOGINUSER-ossh-forcecmd-cert.pub"     1
        scp_check "internal-sftp scp"   "$ED" \
            "$CERTS/$LOGINUSER-ossh-internalsftp-cert.pub" 1
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
