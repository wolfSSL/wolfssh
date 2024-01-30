#!/bin/sh

# sshd local test

PWD=`pwd`
cd ../../..

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "expecting host, port and user as arguments"
    echo "./sshd_x509_text.sh 127.0.0.1 22222 user"
    exit 1
fi

TEST_CLIENT="./examples/client/client"
PRIVATE_KEY="./keys/$3-key.der"
PUBLIC_KEY="./keys/$3-cert.der"
CA_CERT="./keys/ca-cert-ecc.der"

set -e
echo "$TEST_CLIENT -c 'pwd' -u $3 -i $PRIVATE_KEY -J $PUBLIC_KEY -A $CA_CERT -h \"$1\" -p \"$2\""
$TEST_CLIENT -c 'pwd' -u $3 -i "$PRIVATE_KEY" -J "$PUBLIC_KEY" -A "$CA_CERT" -h "$1" -p "$2"
set +e

rm -f error.txt
echo "$TEST_CLIENT -c 'ls error' -u $3 -i $PRIVATE_KEY -J $PUBLIC_KEY -A $CA_CERT -h \"$1\" -p \"$2\" 2> error.txt"
$TEST_CLIENT -c 'ls error' -u $3 -i "$PRIVATE_KEY" -J "$PUBLIC_KEY" -A "$CA_CERT" -h "$1" -p "$2" 2> error.txt

# check stderr output was caught
if [ ! -s error.txt ]; then
    echo "No stderr data was found when expected!!"
    cd $PWD
    exit 1
fi
rm -f error.txt

cd $PWD
exit 0


