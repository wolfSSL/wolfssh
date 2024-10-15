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

mkdir test-$$
mkdir test-$$/subfolder

echo "$TEST_SFTP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -g -l configure -r `pwd`/test-$$/subfolder/ -h \"$1\" -p \"$2\""
"$TEST_SFTP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -g -l configure -r `pwd`/test-$$/subfolder/ -h $1 -p $2"

RESULT=$?
if [ "$RESULT" = "0" ]; then
    echo "Expecting to fail transfer to folder"
    exit 1
fi
rm -rf test-$$

cd $PWD
exit 0

