#!/bin/sh

# sshd local test

# Not named PWD: the shell rewrites that variable on every cd, so a saved
# copy would not survive the cd to the repository root below.
TESTDIR=`pwd`
. ./wolfssh_options.sh
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

if ! wolfssh_has SFTP || [ ! -x "$TEST_SFTP_CLIENT" ]; then
    echo "SFTP client not available in this build, skipping"
    exit 77
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
# Both names carry this test's pid. The remote one has to: it lands in the
# daemon user's home, which is one directory for the whole host however many
# checkouts are running, so two runs uploaded to the same path and each then
# compared its own local file against the other's upload -- "differ: byte 1"
# on a pair of files that were both transferred correctly. The local name
# follows for the same reason one checkout down.
LOCAL_FILE="`pwd`/large-random.$$.txt"
REMOTE_FILE="$HOME_DIR/large-random-2.$$.txt"

# 4.4G apiece, so do not leave them behind on the paths that do not reach the
# removals below: the transfer runs under "set -e" and the comparison can fail.
trap 'rm -f "$LOCAL_FILE" "$REMOTE_FILE"' EXIT

# create a large file with random data (larger than word32 max value)
head -c 4400000010 < /dev/random > "$LOCAL_FILE"

set -e
echo "$TEST_SFTP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -g -l $LOCAL_FILE -r $REMOTE_FILE -h \"$1\" -p \"$2\""
$TEST_SFTP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -g -l "$LOCAL_FILE" -r "$REMOTE_FILE" -h "$1" -p "$2"

cmp "$LOCAL_FILE" "$REMOTE_FILE"
RESULT=$?
if [ "$RESULT" != "0" ]; then
    echo "files did not match when compared"
    exit 1
fi

set +e

cd "$TESTDIR"
exit 0

