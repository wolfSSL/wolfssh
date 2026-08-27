#!/bin/bash
# bash, unlike the rest of this directory: the option array and PIPESTATUS
# below both need it.

# A client that half-closes its stdin sends SSH_MSG_CHANNEL_EOF and waits for
# the command to finish. wolfSSHd must close the write end of the child's stdin
# pipe so a command reading to end-of-input returns, and it must hand over
# everything the peer sent before it does.
#
# Needs the OpenSSH client; the wolfSSH example client does not half-close.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_stdin_eof_test.sh 127.0.0.1 22222"
    exit 1
fi

HOST="$1"
PORT="$2"
USER_NAME="${3:-`whoami`}"

command -v ssh >/dev/null 2>&1 || {
    echo "ssh not found, skipping"
    exit 77
}

# The RESULT==124 assertions below are the point of the test.
command -v timeout >/dev/null 2>&1 || {
    echo "timeout not found, skipping"
    exit 77
}

# ssh refuses a group/world readable identity file.
KEYDIR=`mktemp -d 2>/dev/null` || KEYDIR=`mktemp -d -t sshdeof`
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

# An identity the client cannot load, or a host it cannot reach, is not this
# test's subject. sshd_exec_test.sh runs ahead of this one and owns a server
# that cannot run commands at all.
if ! timeout 20 ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" true >/dev/null 2>&1
then
    echo "no session with these options, skipping"
    exit 77
fi

# Case 1: a small input through 'sort'. 'sort' emits nothing until
# end-of-input, so a missed EOF is the timeout and a killed or hung child is
# empty output -- neither can pass by winning a race the way a streaming 'cat'
# can. The input is unsorted so the comparison also proves the remote command
# ran rather than the input being echoed back.
printf 'charlie\nalpha\nbravo\n' > "$KEYDIR/in.txt"

# wolfsshd runs the user's login shell, so its startup files can print on
# either stream: stderr goes to a file, and stdout is filtered to the lines
# the command itself produced.
OUT=`timeout 20 ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" 'sort' \
        < "$KEYDIR/in.txt" 2> "$KEYDIR/in.err" \
    | grep -E '^(alpha|bravo|charlie)$'`
RESULT=${PIPESTATUS[0]}

if [ "$RESULT" == 124 ]; then
    echo "session did not end after the client half-closed its stdin"
    cat "$KEYDIR/in.err"
    exit 1
fi

if [ "$RESULT" != 0 ]; then
    echo "ssh failed with $RESULT"
    cat "$KEYDIR/in.err"
    exit 1
fi

if [ "$OUT" != "`sort "$KEYDIR/in.txt"`" ]; then
    echo "unexpected output from the remote command"
    echo "$OUT"
    cat "$KEYDIR/in.err"
    exit 1
fi

# Case 2: the same half-close with the send window full. The reader below
# stalls, so the client stops draining, the server's window to the peer fills
# while the client is still sending, and the EOF arrives with channel data
# still buffered on the server. Data held back that way has to be handed to
# the child before its stdin closes: dropping it truncates the output, and
# never handing it over leaves 'cat' waiting on a stdin that never closes.
awk 'BEGIN { for (i = 0; i < 200000; i++)
        printf "%08d one two three four five six seven\n", (i * 48271) % 99991
    }' > "$KEYDIR/big.txt"

timeout 90 ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" 'cat' \
        < "$KEYDIR/big.txt" 2> "$KEYDIR/big.err" \
    | { sleep 5; cat; } > "$KEYDIR/big.out"
RESULT=${PIPESTATUS[0]}

if [ "$RESULT" == 124 ]; then
    echo "session did not end after a half-close with the window full"
    cat "$KEYDIR/big.err"
    exit 1
fi

if [ "$RESULT" != 0 ]; then
    echo "ssh failed with $RESULT"
    cat "$KEYDIR/big.err"
    exit 1
fi

SENT=`wc -c < "$KEYDIR/big.txt"`
GOT=`wc -c < "$KEYDIR/big.out"`

if [ "$GOT" -lt "$SENT" ] \
        || ! tail -c "$SENT" "$KEYDIR/big.out" | cmp -s - "$KEYDIR/big.txt"
then
    echo "the remote command did not see all of the input"
    echo "sent $SENT bytes, got $GOT bytes"
    cat "$KEYDIR/big.err"
    exit 1
fi

exit 0
