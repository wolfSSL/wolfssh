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

echo "Creating tmux session at $PWD with command :"
echo "tmux new-session -d -s test \"$TEST_CLIENT -q -t -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\"\""
tmux new-session -d -s test "$TEST_CLIENT -q -t -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\""
echo "Result of tmux new-session = $?"

# give the command a second to establish SSH connection
sleep 1

COL=`tmux display -p -t test '#{pane_width}'`
ROW=`tmux display -p -t test '#{pane_height}'`
echo "tmux 'test' session has COL = ${COL} and ROW = ${ROW}"

# get the terminals columns and lines
tmux send-keys -t test 'echo;echo $COLUMNS $LINES;echo'
tmux send-keys -t test 'ENTER'

# give the command a second to run
sleep 1

tmux capture-pane -t test
RESULT=$(tmux show-buffer | grep '^[0-9]* [0-9]*$')
tmux show-buffer

echo "$RESULT"
echo ""
echo ""
ROW_FOUND=$(echo "$RESULT" | sed -e 's/[0-9]* \([0-9]*\)/\1/')
COL_FOUND=$(echo "$RESULT" | sed -e 's/\([0-9]*\) [0-9]*/\1/')

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

# give the command a second to establish SSH connection
sleep 1

echo "Sending keys to tmux session for displaying column/rows"
tmux send-keys -t test 'echo;echo $COLUMNS $LINES;echo'
tmux send-keys -t test 'ENTER'
tmux capture-pane -t test
RESULT=$(tmux show-buffer | grep '^[0-9]* [0-9]*$')

ROW_FOUND=$( echo "$RESULT" | sed -e 's/[0-9]* \([0-9]*\)/\1/' )
COL_FOUND=$( echo "$RESULT" | sed -e 's/\([0-9]*\) [0-9]*/\1/' )

#remove any newlines, tabs, or returns
ROW_FOUND=$( tr -d '\n\t\r ' <<<"$ROW_FOUND" )
COL_FOUND=$( tr -d '\n\t\r ' <<<"$COL_FOUND" )


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

