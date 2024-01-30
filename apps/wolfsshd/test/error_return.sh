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
    echo "./error_return.sh 127.0.0.1 22222"
    exit 1
fi

echo "$TEST_CLIENT -c 'bash -c \"(exit 2)\"' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\""
$TEST_CLIENT -c 'bash -c "(exit 2)"' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h "$1" -p "$2"
RESULT=$?
if [ "$RESULT" != 2 ]; then
    echo "Expecting error return value of 2 for failed ls command, found $RESULT"
    cd $PWD
    exit 1
fi

cd $PWD
exit 0


