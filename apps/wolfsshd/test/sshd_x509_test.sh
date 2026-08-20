#!/bin/sh

# sshd local test

# Not named PWD: the shell rewrites that variable on every cd, so a saved
# copy would not survive the cd to the repository root below.
TESTDIR=`pwd`
. ./wolfssh_options.sh

# No FPKI profiles exist in keys/, so skip this test which would fail.
# Drop this skip once conforming certificates are added.
if wolfssh_has FPKI_PROFILE; then
    echo "wolfSSHd enforces FPKI profiles; test certs meet none, skipping"
    exit 77
fi

cd ../../..

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "expecting host, port and user as arguments"
    echo "$0 127.0.0.1 22222 user"
    exit 1
fi

TEST_CLIENT="./examples/client/client"
PRIVATE_KEY="./keys/$3-key.der"
PUBLIC_KEY="./keys/$3-cert.der"
CA_CERT="./keys/ca-cert-ecc.der"

set -e
echo "$TEST_CLIENT -X -c 'pwd' -u $3 -i $PRIVATE_KEY -J $PUBLIC_KEY -A $CA_CERT -h \"$1\" -p \"$2\""
$TEST_CLIENT -X -c 'pwd' -u $3 -i "$PRIVATE_KEY" -J "$PUBLIC_KEY" -A "$CA_CERT" -h "$1" -p "$2"
set +e

rm -f error.txt
echo "$TEST_CLIENT -X -c 'ls error' -u $3 -i $PRIVATE_KEY -J $PUBLIC_KEY -A $CA_CERT -h \"$1\" -p \"$2\" 2> error.txt"
$TEST_CLIENT -X -c 'ls error' -u $3 -i "$PRIVATE_KEY" -J "$PUBLIC_KEY" -A "$CA_CERT" -h "$1" -p "$2" 2> error.txt

# check stderr output was caught
if [ ! -s error.txt ]; then
    echo "No stderr data was found when expected!!"
    cd "$TESTDIR"
    exit 1
fi
rm -f error.txt

cd "$TESTDIR"
exit 0

