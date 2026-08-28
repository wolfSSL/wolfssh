#!/bin/bash
# A child that is not reading its stdin must not make the shell loop spin.
# Once the stdin pipe fills, the write returns EAGAIN and the unwritten tail
# is carried to the next pass; nothing can come off the channel until it
# drains, so a pass with data still in hand must wait on the descriptors
# rather than poll. Fails if wolfsshd burns half a core or more while the
# child sleeps on a full pipe.
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

timeout 40 ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" 'sleep 12' \
    < "$KEYDIR/big" >/dev/null 2>&1 &
SSHPID=$!
sleep 3
A=`cpu_ticks`
sleep 6
B=`cpu_ticks`
wait $SSHPID

HZ=`getconf CLK_TCK`
PCT=$(( (B - A) * 100 / (6 * HZ) ))
echo "wolfsshd CPU over the 6s window: ${PCT}% ($((B - A)) ticks)"
[ "$PCT" -lt 50 ]
