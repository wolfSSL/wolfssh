#!/bin/sh

# sshd local test

PWD=`pwd`
cd ../../..

TEST_SFTP_CLIENT="./examples/sftpclient/wolfsftp"
USER=`whoami`
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_exec_test.sh 127.0.0.1 22222"
    exit 1
fi


# create a large file with random data (larger than word32 max value)
head -c 4400000010 < /dev/random > large-random.txt

set -e
echo "$TEST_SFTP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -g -l large-random.txt -r `pwd`/large-random-2.txt -h \"$1\" -p \"$2\""
$TEST_SFTP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -g -l large-random.txt -r `pwd`/large-random-2.txt -h "$1" -p "$2"

cmp large-random.txt large-random-2.txt
RESULT=$?
if [ "$RESULT" != "0" ]; then
    echo "files did not match when compared"
    exit 1
fi
rm -f large-random.txt
rm -f large-random-2.txt

set +e

cd $PWD
exit 0

