#!/bin/bash

echo "Running all wolfSSHd tests"

# Define an array of test cases
test_cases=(
 "sshd_exec_test.sh"
 "sshd_term_size_test.sh"
 "sshd_large_sftp_test.sh"
 "sshd_bad_sftp_test.sh"
 "sshd_scp_fail.sh"
 "sshd_term_close_test.sh"
 "ssh_kex_algos.sh"
)

# Set defaults
USER=$USER

# Parse arguments
MATCH=""
EXCLUDE=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --match)
            MATCH="$2"
            shift 2
            ;;

        --exclude)
            EXCLUDE="$2"
            shift 2
            ;;

        --user)
            USER="$2"
            shift 2
            ;;

        --host)
            TEST_HOST="$2"
            shift 2
            ;;

        --port)
            TEST_PORT="$2"
            shift 2
            ;;

        *)
            echo "Unknown option: $1"
            echo "Expecting --host <host> | --port <port> | --user <user> | --match <test case> | --exclude <test case>"
            echo "All test cases:"
            for test in "${test_cases[@]}"; do
                echo "    $test"
            done
            exit 1
            ;;
    esac
done

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

# Run the tests
if [[ -n "$MATCH" ]]; then
    if [[ " ${test_cases[*]} " =~ " $MATCH " ]]; then
        echo "Running test: $MATCH"
        run_test "$MATCH"
    else
        echo "Error: Test '$MATCH' not found."
        exit 1
    fi

    if [ "$USING_LOCAL_HOST" == 1 ]; then
        printf "Shutting down test wolfSSHd\n"
        stop_wolfsshd
    fi
else
    echo "Running all tests..."
    for test in "${test_cases[@]}"; do
        if [[ "$test" != "$EXCLUDE" ]]; then
            echo "Running test: $test"
            run_test "$test"
        else
            echo "Test '$test' is excluded. Skipping."
            SKIPPED=$((SKIPPED+1))
        fi
    done

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
fi

printf "All tests ran, $TOTAL passed, $SKIPPED skipped\n"

exit 0
