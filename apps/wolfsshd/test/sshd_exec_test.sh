#!/bin/sh

# sshd local test

PWD=`pwd`
cd ../../..

TEST_CLIENT="./examples/client/client"
USER=`whoami`
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_exec_test.sh 127.0.0.1 22222"
    exit 1
fi

set -e
echo "$TEST_CLIENT -c 'ls' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\""
$TEST_CLIENT -c 'ls' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h "$1" -p "$2"

set +e

cd $PWD
exit 0

