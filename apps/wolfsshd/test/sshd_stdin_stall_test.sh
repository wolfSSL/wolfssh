#!/bin/bash
# A child that is not reading its stdin must not make the shell loop spin.
# Once the stdin pipe fills, the write returns EAGAIN and the unwritten tail
# is carried to the next pass; nothing can come off the channel until it
# drains, so a pass with data still in hand must wait on the descriptors
# rather than poll. A correct loop uses no measurable CPU while the child
# sleeps on a full pipe and a spinning one saturates a core, so the bound is
# set well below a partial spin rather than just below a full one.
#
# Needs the OpenSSH client: the wolfSSH example client sends its input and
# then reads, so it never fills the pipe.
HOST="$1"
PORT="$2"
USER_NAME="${3:-`whoami`}"

command -v ssh >/dev/null 2>&1 || exit 77
command -v timeout >/dev/null 2>&1 || exit 77

KEYDIR=`mktemp -d` || exit 1
trap 'rm -rf "$KEYDIR"' EXIT
cp ../../../keys/hansel-key-ecc.pem "$KEYDIR/id_ecdsa" || exit 1
chmod 600 "$KEYDIR/id_ecdsa"

SSH_OPTS=(-i "$KEYDIR/id_ecdsa" -p "$PORT"
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o PreferredAuthentications=publickey -o PasswordAuthentication=no
    -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR)

timeout 20 ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" true >/dev/null 2>&1 || exit 77

dd if=/dev/zero of="$KEYDIR/big" bs=1M count=8 2>/dev/null

cpu_ticks() {
    local t=0 p f
    for p in `pgrep -x wolfsshd`; do
        read -r -a f < /proc/$p/stat 2>/dev/null || continue
        t=$(( t + ${f[13]} + ${f[14]} ))
    done
    echo $t
}

# Let the transfer reach the stall before measuring, and leave the child
# asleep past the end of the window. Contention can only push the reading
# down, so a loaded machine misses a regression rather than failing a good
# build.
SETTLE=3
WINDOW=3
CHILD_SLEEP=9
LIMIT=10

timeout 40 ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "sleep $CHILD_SLEEP" \
    < "$KEYDIR/big" >/dev/null 2>&1 &
SSHPID=$!
sleep "$SETTLE"
A=`cpu_ticks`
sleep "$WINDOW"
B=`cpu_ticks`
wait $SSHPID

HZ=`getconf CLK_TCK`
PCT=$(( (B - A) * 100 / (WINDOW * HZ) ))
echo "wolfsshd CPU over the ${WINDOW}s window: ${PCT}% ($((B - A)) ticks)"
[ "$PCT" -lt "$LIMIT" ]
