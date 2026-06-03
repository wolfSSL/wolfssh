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

# wolfSSHd confines SFTP access to the user's home directory, so the remote
# file must live under it.  Resolve the same home directory wolfSSHd uses
# (the passwd entry), falling back to $HOME.
HOME_DIR=`getent passwd "$USER" 2>/dev/null | cut -d: -f6`
if [ -z "$HOME_DIR" ]; then
    HOME_DIR="$HOME"
fi
# Fail fast with a clear message rather than silently targeting "/" (which the
# now-active SFTP confinement would reject with a non-obvious error) if neither
# the passwd entry nor $HOME yields a usable home directory.
if [ -z "$HOME_DIR" ] || [ "$HOME_DIR" = "/" ]; then
    echo "could not resolve a usable home directory for user '$USER'"
    exit 1
fi
REMOTE_FILE="$HOME_DIR/large-random-2.txt"

# create a large file with random data (larger than word32 max value)
head -c 4400000010 < /dev/random > large-random.txt

set -e
echo "$TEST_SFTP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -g -l large-random.txt -r $REMOTE_FILE -h \"$1\" -p \"$2\""
$TEST_SFTP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -g -l large-random.txt -r "$REMOTE_FILE" -h "$1" -p "$2"

cmp large-random.txt "$REMOTE_FILE"
RESULT=$?
if [ "$RESULT" != "0" ]; then
    echo "files did not match when compared"
    exit 1
fi
rm -f large-random.txt
rm -f "$REMOTE_FILE"

set +e

cd $PWD
exit 0

