#!/bin/sh

# sshd local test: a subsystem the daemon does not serve is refused at the
# request, so the client sees CHANNEL_FAILURE rather than a session that
# is accepted and then dropped. Uses the system OpenSSH client, since the
# in-tree clients only ask for sftp.

# Not named PWD: the shell rewrites that variable on every cd, so a saved
# copy would not survive the cd to the repository root below.
TESTDIR=`pwd`
cd ../../..

USER="$3"
if [ -z "$USER" ]; then
    USER=`whoami`
fi
PRIVATE_KEY="./keys/hansel-key-ecc.pem"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_bad_subsystem_test.sh 127.0.0.1 22222"
    exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
    echo "OpenSSH client not found, skipping"
    exit 77
fi

# The regression this test looks for is a request the daemon never answers,
# which leaves the client waiting. Bound every call so that hangs the test
# rather than the suite.
if ! command -v timeout >/dev/null 2>&1; then
    echo "timeout not found, skipping"
    exit 77
fi
TIMEOUT="timeout 20"

# OpenSSH refuses a key file other users can read.
KEY=`mktemp 2>/dev/null` || KEY=`mktemp -t sshdbadsubsys`
OUT=`mktemp 2>/dev/null` || OUT=`mktemp -t sshdbadsubsysout`
if [ -z "$KEY" ] || [ ! -f "$KEY" ] || [ -z "$OUT" ] || [ ! -f "$OUT" ]; then
    echo "could not create temp files"
    rm -f "$KEY" "$OUT"
    exit 1
fi
trap 'rm -f "$KEY" "$OUT"' EXIT

cat "$PRIVATE_KEY" > "$KEY" || exit 1
chmod 600 "$KEY"

ssh_to_sshd() {
    $TIMEOUT ssh -p "$2" -i "$KEY" -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=publickey \
        -o BatchMode=yes -o ConnectTimeout=5 "$USER@$1" "$3" "$4"
}

# Control: the same client and key can run a command.
ssh_to_sshd "$1" "$2" "echo ok" > "$OUT" 2>&1
RESULT=$?
if [ "$RESULT" != "0" ] || ! grep -q "^ok" "$OUT"; then
    echo "Control exec through OpenSSH failed ($RESULT):"
    cat "$OUT"
    exit 1
fi

# A subsystem nothing serves: the client reports the refusal and exits
# non-zero. Check the timeout first, its 124 is non-zero too but means the
# request went unanswered, the opposite of what this test wants.
ssh_to_sshd "$1" "$2" -s no-such-subsystem > "$OUT" 2>&1
RESULT=$?
if [ "$RESULT" = "124" ]; then
    echo "The unknown subsystem request went unanswered:"
    cat "$OUT"
    exit 1
fi
if [ "$RESULT" = "0" ]; then
    echo "Expecting the unknown subsystem request to fail"
    cat "$OUT"
    exit 1
fi
if ! grep -q "subsystem request failed" "$OUT"; then
    echo "Expecting the client to report the refused subsystem request:"
    cat "$OUT"
    exit 1
fi

cd "$TESTDIR"
exit 0
