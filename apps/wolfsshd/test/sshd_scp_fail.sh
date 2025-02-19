#!/bin/sh

# sshd local test

PWD=`pwd`
cd ../../..

TEST_SCP_CLIENT="./examples/scpclient/wolfscp"
USER=`whoami`
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_exec_test.sh 127.0.0.1 22222"
    exit 1
fi

mkdir test-$$

OUTDIR="`pwd`/test-$$"

dd if=/dev/random of=$OUTDIR/test.dat bs=1024 count=512

echo "$TEST_SCP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -S$OUTDIR/test.dat:. -H $1 -p $2"
$TEST_SCP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -S$OUTDIR/test.dat:. -H $1 -p $2

RESULT=$?
if [ "$RESULT" != "0" ]; then
    echo "Expecting to pass transfer"
    exit 1
fi

MD5SOURCE=`md5sum $OUTDIR/test.dat | awk '{ print $1 }'`
MD5DEST=`md5sum test.dat | awk '{ print $1 }'`

if [ "$MD5SOURCE" != "$MD5DEST" ]; then
    echo "Files do not match $MD5SOURCE != $MD5DEST"
    exit 1
fi

rm -rf test-$$
rm testout.dat

cd $PWD
exit 0

