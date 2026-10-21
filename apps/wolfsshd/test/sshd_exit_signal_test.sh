#!/bin/bash
# bash, unlike most of this directory: the option array below needs it.

# A remote command killed by a signal must not report success. wolfSSHd sends
# 128 plus the signal number as the exit status, as a shell reports it.
#
# Needs the OpenSSH client, which exits with the remote exit status.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_exit_signal_test.sh 127.0.0.1 22222"
    exit 1
fi

HOST="$1"
PORT="$2"
USER_NAME="${3:-`whoami`}"

command -v ssh >/dev/null 2>&1 || {
    echo "ssh not found, skipping"
    exit 77
}

command -v timeout >/dev/null 2>&1 || {
    echo "timeout not found, skipping"
    exit 77
}

# ssh refuses a group/world readable identity file.
KEYDIR=`mktemp -d 2>/dev/null` || KEYDIR=`mktemp -d -t sshdsig`
if [ -z "$KEYDIR" ] || [ ! -d "$KEYDIR" ]; then
    echo "could not create temp dir"
    exit 1
fi
trap 'rm -rf "$KEYDIR"' EXIT

cp ../../../keys/hansel-key-ecc.pem "$KEYDIR/id_ecdsa" || exit 1
chmod 600 "$KEYDIR/id_ecdsa"

SSH_OPTS=(-i "$KEYDIR/id_ecdsa" -p "$PORT"
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o PreferredAuthentications=publickey -o PasswordAuthentication=no
    -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR)

if ! timeout 20 ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" true >/dev/null 2>&1
then
    echo "no session with these options, skipping"
    exit 77
fi

# Control: a plain exit status comes through unchanged.
timeout 20 ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" 'exit 3' \
    > /dev/null 2> "$KEYDIR/exit.err"
RESULT=$?
if [ "$RESULT" != 3 ]; then
    echo "expected exit status 3, got $RESULT"
    cat "$KEYDIR/exit.err"
    exit 1
fi

# The shell running the command kills itself, so it is what the daemon reaps.
timeout 20 ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" 'kill -KILL $$' \
    > /dev/null 2> "$KEYDIR/kill.err"
RESULT=$?
if [ "$RESULT" != 137 ]; then
    echo "expected exit status 137 for SIGKILL, got $RESULT"
    cat "$KEYDIR/kill.err"
    exit 1
fi

exit 0
