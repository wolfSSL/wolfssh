#!/bin/bash

# sshd local test

pushd ../../..

TEST_CLIENT="./examples/client/client"
USER=`whoami`
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_exec_test.sh 127.0.0.1 22222"
    exit 1
fi

# Check if tmux is available
which tmux
RESULT=$?
if [ ${RESULT} = 1 ]; then
    echo "tmux is not installed!!"
    exit 1
fi

# tear down the tmux session on any exit, so a timeout failure does not
# leave a stale session that breaks the next run with "duplicate session"
trap 'tmux kill-session -t test 2>/dev/null || true' EXIT

# Wait until the remote shell produces some output (i.e. a prompt), so the
# SSH session is known to be up before keys are sent to it. CI runners can
# take several seconds to get through key exchange and login.
wait_for_session() {
    for _ in $(seq 1 10); do
        if tmux capture-pane -p -t test | grep -q '[^[:space:]]'; then
            return 0
        fi
        sleep 1
    done
    echo "Timed out waiting for SSH session output"
    tmux capture-pane -p -t test
    return 1
}

# Ask the remote shell for its size and poll the pane until a line of the
# form "<columns> <rows>" shows up. The result is left in SIZE_LINE.
get_size_line() {
    SIZE_LINE=""
    tmux send-keys -t test 'echo;echo $COLUMNS $LINES;echo'
    tmux send-keys -t test 'ENTER'
    for _ in $(seq 1 10); do
        sleep 1
        SIZE_LINE=$(tmux capture-pane -p -t test | grep -E '^[0-9]+ [0-9]+$' | tail -n 1)
        if [ -n "$SIZE_LINE" ]; then
            return 0
        fi
    done
    echo "Timed out waiting for terminal size output"
    tmux capture-pane -p -t test
    return 1
}

echo "Creating tmux session at $PWD with command :"
echo "tmux new-session -d -s test \"$TEST_CLIENT -q -t -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\"\""
tmux new-session -d -s test "$TEST_CLIENT -q -t -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\""
echo "Result of tmux new-session = $?"

wait_for_session || exit 1

COL=`tmux display -p -t test '#{pane_width}'`
ROW=`tmux display -p -t test '#{pane_height}'`
echo "tmux 'test' session has COL = ${COL} and ROW = ${ROW}"

# get the terminals columns and lines
get_size_line || exit 1
echo "Captured terminal size line: '$SIZE_LINE'"

read -r COL_FOUND ROW_FOUND <<< "$SIZE_LINE"

if [ "$COL" != "$COL_FOUND" ]; then
    echo "Col found was $COL_FOUND which does not match expected $COL"
    exit 1
fi

if [ "$ROW" != "$ROW_FOUND" ]; then
    echo "Row found was $ROW_FOUND which does not match expected $ROW"
    exit 1
fi

# resize tmux after connection is open is not working @TODO
#tmux set-window-option -g aggressive-resize
#printf '\e[8;50;100t'
#tmux resize-pane -x 50 -y 10 -t test

# close down the SSH session
tmux send-keys -t test 'exit'
tmux send-keys -t test 'ENTER'

# kill off the session if it's still running, but don't error out if the session
# has already closed down
tmux kill-session -t test
set -e

echo "Starting another session with a smaller window size"
echo "tmux new-session -d -x 50 -y 10 -s test \"$TEST_CLIENT -q -t -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\"\""
tmux new-session -d -x 50 -y 10 -s test "$TEST_CLIENT -q -t -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\""

wait_for_session || exit 1

echo "Sending keys to tmux session for displaying column/rows"
get_size_line || exit 1
echo "Captured terminal size line: '$SIZE_LINE'"

read -r COL_FOUND ROW_FOUND <<< "$SIZE_LINE"

if [ "50" != "$COL_FOUND" ]; then
    echo "Col found was $COL_FOUND which does not match expected 50"
    exit 1
fi

if [ "10" != "$ROW_FOUND" ]; then
    echo "Row found was $ROW_FOUND which does not match expected 10"
    exit 1
fi

# close down the SSH session
tmux send-keys -t test 'exit'
tmux send-keys -t test 'ENTER'
set +e
tmux kill-session -t test

popd
exit 0

