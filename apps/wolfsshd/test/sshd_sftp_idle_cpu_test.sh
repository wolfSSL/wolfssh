#!/bin/sh

# An idle SFTP session must not keep the server busy. wolfSSHd's SFTP loop
# polls at the select() floor whenever wolfSSH_stream_peek() reports an empty
# channel, so before the timeout was raised on that path a connected client
# that simply sat there cost most of a core for as long as it stayed open.

ROOT_PWD=$(pwd)
. ./wolfssh_options.sh
cd ../../..

TEST_SFTP_CLIENT="./examples/sftpclient/wolfsftp"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

SAMPLE_SECONDS=10
# Ticks of CPU the connection process may use while idle.
# The poll this guards against measured 16 per 10 seconds; a server that
# waits properly measures 0.
MAX_TICKS=5

FIFO="/tmp/wolfssh_idle_stdin_$$"
HOLDER=""
CLIENT=""

cleanup() {
    [ -n "$CLIENT" ] && kill "$CLIENT" 2>/dev/null
    [ -n "$HOLDER" ] && kill "$HOLDER" 2>/dev/null
    rm -f "$FIFO"
}

# tear down on every exit path, including an interrupt during the ten second
# measurement, so no FIFO or client is left behind
trap cleanup EXIT

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "expecting host, port and user as arguments"
    echo "$0 127.0.0.1 22222 $USER"
    exit 1
fi

if ! wolfssh_has SFTP || [ ! -x "$TEST_SFTP_CLIENT" ]; then
    echo "SFTP client not available in this build, skipping"
    exit 77
fi

# The measurement reads the server's CPU time out of /proc, so it only works
# against a local daemon on a system that has one.
if [ ! -r /proc/self/stat ]; then
    echo "no /proc on this system, skipping"
    exit 77
fi

PIDS_BEFORE=$(pgrep wolfsshd | tr '\n' ' ')
if [ -z "$PIDS_BEFORE" ]; then
    echo "no local wolfsshd to measure, skipping"
    exit 77
fi

# Echoes the first wolfsshd that did not exist before this connection. The
# difference has to be one-way: a pid that LEFT during the window is not a
# candidate, and a symmetric difference offers it as readily as the child
# that arrived, leaving an unreadable /proc entry to measure.
new_wolfsshd_pid() {
    for P in $(pgrep wolfsshd); do
        case " $PIDS_BEFORE " in
            *" $P "*) ;;
            *) echo "$P"; return 0 ;;
        esac
    done
    return 1
}

# Hold a session open without sending a single request. The client takes its
# commands from this pipe, and nothing ever writes one; the sleep bounds how
# long the pipe stays open so no part of this outlives the test.
mkfifo "$FIFO" || exit 1
sleep $((SAMPLE_SECONDS + 30)) > "$FIFO" &
HOLDER=$!
"$TEST_SFTP_CLIENT" -u "$3" -i "$PRIVATE_KEY" -j "$PUBLIC_KEY" \
    -h "$1" -p "$2" < "$FIFO" > /dev/null 2>&1 &
CLIENT=$!

# Poll for the child rather than sampling a fixed second in. NewConnection()
# forks right after accept(), so it appears long before the five seconds the
# old sample waited.
WAITED=0
CHILD=$(new_wolfsshd_pid)
while [ -z "$CHILD" ] && [ "$WAITED" -lt 50 ]; do
    sleep 0.1
    WAITED=$((WAITED + 1))
    CHILD=$(new_wolfsshd_pid)
done

if [ -z "$CHILD" ]; then
    echo "Expecting another wolfSSHd pid after connection"
    echo "  before: $PIDS_BEFORE"
    echo "  after:  $(pgrep wolfsshd | tr '\n' ' ')"
    exit 1
fi

# Let the handshake, authentication and SFTP setup finish, so the ticks they
# cost land before the baseline rather than inside the measurement.
sleep 5

if [ ! -r "/proc/$CHILD/stat" ]; then
    echo "Connection process $CHILD exited before the measurement"
    exit 1
fi

# Fields 14 and 15 of /proc/<pid>/stat are utime and stime, in clock ticks.
BEFORE=$(awk '{print $14+$15}' "/proc/$CHILD/stat")
sleep "$SAMPLE_SECONDS"
if [ ! -r "/proc/$CHILD/stat" ]; then
    echo "Connection process $CHILD exited while idle"
    exit 1
fi
AFTER=$(awk '{print $14+$15}' "/proc/$CHILD/stat")
USED=$((AFTER-BEFORE))

echo "idle connection used $USED ticks over $SAMPLE_SECONDS seconds"
if [ "$USED" -ge "$MAX_TICKS" ]; then
    echo "Expecting an idle SFTP session to cost under $MAX_TICKS ticks"
    exit 1
fi

cd "$ROOT_PWD"
exit 0
