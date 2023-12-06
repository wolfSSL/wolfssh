#!/bin/bash

echo "Running all wolfSSHd tests"

TEST_HOST=$1
TEST_PORT=$2
TOTAL=0
SKIPPED=0

# setup
set -e
./create_authorized_test_file.sh
./create_sshd_config.sh
set +e

if [ ! -z "$TEST_HOST" ] && [ ! -z "$TEST_PORT" ]; then
    USING_LOCAL_HOST=0
    echo "Connecting to external host $TEST_HOST:$TEST_PORT"
else
    USING_LOCAL_HOST=1
    source ./start_sshd.sh
    echo "Starting up local wolfSSHd for tests on 127.0.0.1:22222"
    TEST_HOST="127.0.0.1"
    TEST_PORT="22222"
    start_wolfsshd "sshd_config_test"
    if [ -z "$PID" ]; then
        echo "Issue starting up wolfSSHd"
        exit 1
    fi
fi

run_test() {
    printf "$1 ... "
    ./"$1" "$TEST_HOST" "$TEST_PORT" &> stdout.txt
    RESULT=$?
    TOTAL=$((TOTAL+1))
    if [ "$RESULT" == 77 ]; then
        printf "SKIPPED\n"
        SKIPPED=$((SKIPPED+1))
    elif [ "$RESULT" == 0 ]; then
        printf "PASSED\n"
    else
        printf "FAILED!\n"
        cat stdout.txt
        if [ "$USING_LOCAL_HOST" == 1 ]; then
            printf "Shutting down test wolfSSHd\n"
            stop_wolfsshd
        fi
        exit 1
    fi
}

run_test "sshd_exec_test.sh"
run_test "sshd_term_size_test.sh"

# add aditional tests here, check on var USING_LOCAL_HOST if can make sshd
# server start/restart with changes

if [ "$USING_LOCAL_HOST" == 1 ]; then
    printf "Shutting down test wolfSSHd\n"
    stop_wolfsshd
fi

# these tests require setting up an sshd
if [ "$USING_LOCAL_HOST" == 1 ]; then
    run_test "sshd_forcedcmd_test.sh"
else
    printf "Skipping tests that need to setup local SSHD\n"
    SKIPPED=$((SKIPPED+1))
fi

printf "All tests ran, $TOTAL passed, $SKIPPED skipped\n"

exit 0
