#!/bin/bash

echo "Running all wolfSSHd tests"

if [ -z "$1" ]; then
    USER=$USER
else
    USER=$1
fi

TEST_HOST=$2
TEST_PORT=$3

TOTAL=0
SKIPPED=0

# setup
set -e
./create_authorized_test_file.sh
./create_sshd_config.sh $USER
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
    ./"$1" "$TEST_HOST" "$TEST_PORT" "$USER" &> stdout.txt
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
run_test "sshd_large_sftp_test.sh"

#Github actions needs resolved for these test cases
#run_test "error_return.sh"
#run_test "sshd_login_grace_test.sh"

# add aditional tests here, check on var USING_LOCAL_HOST if can make sshd
# server start/restart with changes

if [ "$USING_LOCAL_HOST" == 1 ]; then
    printf "Shutting down test wolfSSHd\n"
    stop_wolfsshd
fi

# these tests require setting up an sshd
if [ "$USING_LOCAL_HOST" == 1 ]; then
    run_test "sshd_forcedcmd_test.sh"
    run_test "sshd_window_full_test.sh"
else
    printf "Skipping tests that need to setup local SSHD\n"
    SKIPPED=$((SKIPPED+2))
fi

# these tests run with X509 sshd-config loaded
if [ "$USING_LOCAL_HOST" == 1 ]; then
    start_wolfsshd "sshd_config_test_x509"
fi
run_test "sshd_x509_test.sh"
if [ "$USING_LOCAL_HOST" == 1 ]; then
    printf "Shutting down test wolfSSHd\n"
    stop_wolfsshd
fi

printf "All tests ran, $TOTAL passed, $SKIPPED skipped\n"

exit 0
