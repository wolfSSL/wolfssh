#!/bin/sh

# sshd local test: a subsystem the daemon does not serve is refused at the
# request, so the client sees CHANNEL_FAILURE rather than a session that
# is accepted and then dropped. Uses the system OpenSSH client, since the
# in-tree clients only ask for sftp.

# Not named PWD: the shell rewrites that variable on every cd, so a saved
# copy would not survive the cd to the repository root below.
TESTDIR=`pwd`
cd ../../..

USER=`whoami`
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

# OpenSSH refuses a key file other users can read.
KEY=`mktemp`
cat "$PRIVATE_KEY" > "$KEY"
chmod 600 "$KEY"
OUT=`mktemp`

ssh_to_sshd() {
    ssh -p "$2" -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=publickey \
        -o BatchMode=yes -o ConnectTimeout=5 "$USER@$1" "$3" "$4"
}

# Control: the same client and key can run a command.
ssh_to_sshd "$1" "$2" "echo ok" > "$OUT" 2>&1
RESULT=$?
if [ "$RESULT" != "0" ] || ! grep -q "^ok" "$OUT"; then
    echo "Control exec through OpenSSH failed ($RESULT):"
    cat "$OUT"
    rm -f "$KEY" "$OUT"
    exit 1
fi

# A subsystem nothing serves: the client reports the refusal and exits
# non-zero.
ssh_to_sshd "$1" "$2" -s no-such-subsystem > "$OUT" 2>&1
RESULT=$?
if [ "$RESULT" = "0" ]; then
    echo "Expecting the unknown subsystem request to fail"
    cat "$OUT"
    rm -f "$KEY" "$OUT"
    exit 1
fi
if ! grep -q "subsystem request failed" "$OUT"; then
    echo "Expecting the client to report the refused subsystem request:"
    cat "$OUT"
    rm -f "$KEY" "$OUT"
    exit 1
fi

rm -f "$KEY" "$OUT"
cd "$TESTDIR"
exit 0
