#!/bin/sh

# An SCP transfer with a relative remote path resolves it from the user's home
# directory, not from the daemon's working directory.

# Not named PWD: the shell rewrites that variable on every cd, so a saved
# copy would not survive the cd to the repository root below.
TESTDIR=`pwd`
. ./wolfssh_options.sh
cd ../../..

TEST_SCP_CLIENT="./examples/scpclient/wolfscp"
USER="${3:-`whoami`}"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_scp_home_test.sh 127.0.0.1 22222"
    exit 1
fi

if ! wolfssh_has SCP || [ ! -x "$TEST_SCP_CLIENT" ]; then
    echo "SCP client not available in this build, skipping"
    exit 77
fi

# The check reads the file back from the home directory directly.
case "$1" in
    127.0.0.1|localhost) ;;
    *) echo "remote host, skipping"; exit 77 ;;
esac

HOMEDIR=`getent passwd "$USER" 2>/dev/null | cut -d: -f6`
[ -n "$HOMEDIR" ] || HOMEDIR=`eval echo "~$USER"`
if [ -z "$HOMEDIR" ] || [ ! -d "$HOMEDIR" ]; then
    echo "no home directory for $USER, skipping"
    exit 77
fi

NAME="scp-home-$$.dat"
OUTDIR="`pwd`/test-$$"
mkdir "$OUTDIR" || exit 1
trap 'rm -rf "$OUTDIR"; rm -f "$HOMEDIR/$NAME"' EXIT

if ! dd if=/dev/urandom of="$OUTDIR/$NAME" bs=1024 count=64 2>/dev/null; then
    echo "Could not create the test file $OUTDIR/$NAME"
    exit 1
fi

echo "$TEST_SCP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -L$OUTDIR/$NAME:. -H $1 -p $2"
$TEST_SCP_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -L"$OUTDIR/$NAME":. \
    -H $1 -p $2
if [ "$?" != "0" ]; then
    echo "Expecting to pass transfer"
    exit 1
fi

if ! cmp -s "$OUTDIR/$NAME" "$HOMEDIR/$NAME"; then
    echo "File did not land in $HOMEDIR"
    exit 1
fi

cd "$TESTDIR"
exit 0
