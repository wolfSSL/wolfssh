#!/bin/sh

# sshd local test

ROOT_PWD=$(pwd)
cd ../../..

TEST_CLIENT="./apps/wolfssh/wolfssh"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222 $USER"
    exit 1
fi
HOST_IP="$1"
HOST_PORT="$2"
USER_SET="$3"

# check if wolfssh app was compiled
OUTPUT=$("$TEST_CLIENT" -V)
RESULT=$?
if [ "$RESULT" != 0 ]; then
    echo "wolfSSH app not compiled in";
    exit 77
fi

# Debug mode needs to be on to inspect the debug output
printf "$OUTPUT" | grep "DEBUG"
RESULT=$?
if [ "$RESULT" != 0 ]; then
    echo "wolfSSH app not compiled with debug mode";
    exit 77
fi

# returns variable SUPPORTED as 1 or 0
test_if_supported() {
    SUPPORTED=0
    TEXT=$(./examples/client/client -E -u $USER_SET | grep "$1")
    if [ $? = 0 ]; then
        SUPPORTED=1
    fi
    printf "$1 , $SUPPORTED\n"
}

# test which algo's are supported
printf "Algo , Supported?\n"
test_if_supported "p256"
HAVE_P256=$SUPPORTED
test_if_supported "p384"
HAVE_P384=$SUPPORTED
test_if_supported "p521"
HAVE_P521=$SUPPORTED
printf "\n"


# Looks through the variable OUTPUT for the block of text containg the server
# host key algorithms sent.
find_substring_of_algos() {
    # Extract the substring between start and end lines
    SUBSTRING=$(printf "$OUTPUT" | grep -A20 "Server Host Key Algorithms")
    SUBSTRING=$(printf "$SUBSTRING" | grep -v -A15 "DKI: Enc Algorithms")
}

# take input argument $1 and checks if it is in the SUBSTRING
test_for_algo_name() {
    #printf "substring found = $substring"
    if echo "$SUBSTRING" | grep -q "$1"; then
        printf "Found $1\n"
        EXISTS=1
    else
        printf "Did not find $1\n"
        EXISTS=0
    fi
}

# Expecting to find the algo name $1
test_for_algo_name_success() {
    test_for_algo_name "$1"
    if [ $EXISTS != 1 ]; then
        printf "Error finding algo name $1\n"
        exit 1
    fi
}

# Expecting to not find the algo name $1
test_for_algo_name_fail() {
    test_for_algo_name "$1"
    if [ $EXISTS = 1 ]; then
        printf "Error expected to not find algo name $1\n"
        exit 1
    fi
}

echo "$TEST_CLIENT -p $HOST_PORT $USER_SET@$HOST_IP"
OUTPUT=$(timeout 1 "$TEST_CLIENT" -p "$HOST_PORT" "$USER_SET"@"$HOST_IP" 2>&1)
find_substring_of_algos

if [ $HAVE_P256 = 1 ]; then
    test_for_algo_name_success "ecdsa-sha2-nistp256"
else
    test_for_algo_name_fail "ecdsa-sha2-nistp256"
fi

if [ $HAVE_P384 = 1 ]; then
    test_for_algo_name_success "ecdsa-sha2-nistp384"
else
    test_for_algo_name_fail "ecdsa-sha2-nistp384"
fi

if [ $HAVE_P521 = 1 ]; then
    test_for_algo_name_success "ecdsa-sha2-nistp521"
else
    test_for_algo_name_fail "ecdsa-sha2-nistp521"
fi

exit 0

