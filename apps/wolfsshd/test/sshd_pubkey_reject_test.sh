#!/bin/sh

# Negative test for public-key authorization: a well-formed keypair whose
# public key is not listed in the AuthorizedKeysFile must be rejected. Gates
# the "no line matched -> WSSHD_AUTH_FAILURE" fail-closed path in
# SearchKeysFile()/SearchForPubKey() (apps/wolfsshd/auth.c). The rest of the
# wolfsshd suite only ever authenticates with a hansel key, which
# create_authorized_test_file.sh puts in authorized_keys_test, so without this
# the reject direction is never driven through the daemon.
#
# run_all_sshd_tests.sh starts the shared daemon with sshd_config_test, whose
# AuthorizedKeysFile is ./authorized_keys_test (hansel keys only), so gretel is
# a valid keypair that is not authorized.
#
# The Windows CheckPublicKeyWIN() path is not covered here. It needs a
# provisioned Windows account and an authorized_keys file in that account's
# home directory before the key search is even reached, the same reason
# sshd_login_grace_test.ps1 leaves its authenticated path uncovered.

# Not named PWD: the shell overwrites that variable on every cd, so a saved
# copy would not survive the cd to the repository root below.
TESTDIR=`pwd`

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "expecting host, port and user as arguments"
    echo "$0 127.0.0.1 22222 user"
    exit 1
fi

TEST_HOST="$1"
TEST_PORT="$2"
TEST_USER="$3"

TEST_CLIENT="./examples/client/client"
GOOD_PRIVATE_KEY="./keys/hansel-key-ecc.der"
GOOD_PUBLIC_KEY="./keys/hansel-key-ecc.pub"
BAD_PRIVATE_KEY="./keys/gretel-key-ecc.der"
BAD_PUBLIC_KEY="./keys/gretel-key-ecc.pub"

# Guard against a vacuous pass: if the key under test is authorized after all,
# the rejection below would be testing nothing. Compare the base64 blob, which
# is what the daemon matches on, not the trailing comment.
BAD_KEY_BLOB=`awk '{print $2}' "$TESTDIR/../../../keys/gretel-key-ecc.pub"`
if [ -z "$BAD_KEY_BLOB" ]; then
    echo "ERROR: could not read the test key from keys/gretel-key-ecc.pub"
    exit 1
fi
if grep -qF "$BAD_KEY_BLOB" "$TESTDIR/authorized_keys_test"; then
    echo "ERROR: gretel's key is in authorized_keys_test; setup issue"
    exit 1
fi

# Count existing rejection lines first. start_sshd.sh runs 'wolfsshd -E
# ./log.txt', which appends and never truncates, so a stale match from an
# earlier test must not be read as this run's rejection. The log is owned by
# root because the daemon was started with sudo.
BEFORE=`sudo grep -c "Public key not authorized" "$TESTDIR/log.txt" 2>/dev/null`
BEFORE=${BEFORE:-0}

cd ../../..

# Positive control: the authorized key must work against this daemon, so the
# failure below can be attributed to the key not being authorized rather than
# to an unrelated connection or client problem.
timeout 10 $TEST_CLIENT -c 'exit' -u "$TEST_USER" \
    -i "$GOOD_PRIVATE_KEY" -j "$GOOD_PUBLIC_KEY" \
    -h "$TEST_HOST" -p "$TEST_PORT" > /dev/null 2>&1
GOOD_RESULT=$?

if [ "$GOOD_RESULT" != 0 ]; then
    cd "$TESTDIR"
    echo "ERROR: public-key auth failed with an authorized key; setup issue"
    exit 1
fi

echo "$TEST_CLIENT -c 'exit' -u $TEST_USER -i $BAD_PRIVATE_KEY" \
     "-j $BAD_PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT (expecting rejection)"
timeout 10 $TEST_CLIENT -c 'exit' -u "$TEST_USER" \
    -i "$BAD_PRIVATE_KEY" -j "$BAD_PUBLIC_KEY" \
    -h "$TEST_HOST" -p "$TEST_PORT" > /dev/null 2>&1
BAD_RESULT=$?

cd "$TESTDIR"

# The connection child writes the rejection through buffered stdio, so poll
# for it rather than sampling once. Nothing to wait for if auth succeeded.
AFTER=$BEFORE
i=0
while [ "$BAD_RESULT" -ne 0 ] && [ $i -lt 50 ]; do
    AFTER=`sudo grep -c "Public key not authorized" "$TESTDIR/log.txt" \
        2>/dev/null`
    AFTER=${AFTER:-0}
    if [ "$AFTER" -gt "$BEFORE" ]; then
        break
    fi
    sleep 0.2
    i=$((i + 1))
done

if [ "$BAD_RESULT" -ne 0 ] && [ "$AFTER" -gt "$BEFORE" ]; then
    echo "unauthorized public key correctly rejected"
    exit 0
fi

if [ "$BAD_RESULT" -eq 0 ]; then
    echo "ERROR: authentication succeeded with a key absent from authorized_keys"
else
    echo "ERROR: client failed but daemon did not log a public key rejection"
fi
echo "----- log.txt -----"
sudo cat "$TESTDIR/log.txt"
exit 1
