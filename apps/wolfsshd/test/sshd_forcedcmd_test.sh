#!/bin/bash

# sshd local test

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222"
    exit 1
fi

# Not named PWD: the shell rewrites that variable on every cd, so a saved copy
# would not survive the cd to the repository root below.
TESTDIR=`pwd`
USER=`whoami`
TEST_PORT="$2"
TEST_HOST="$1"
source ./start_sshd.sh

# Stop the daemon on every exit path. From the "set -e" below onward an aborted
# client run would otherwise leave a root daemon holding the shared test port,
# and every later test in the suite would talk to this config.
cleanup() {
    if [ -n "$PID" ]; then
        stop_wolfsshd
        PID=""
    fi
    return 0
}
trap cleanup EXIT

cat <<EOF > sshd_config_test_forcedcmd
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $TESTDIR/../../../keys/server-key.pem
AuthorizedKeysFile $TESTDIR/authorized_keys_test

Match User $USER
	ForceCommand internal-sftp
EOF

start_wolfsshd "sshd_config_test_forcedcmd"
cd ../../..

TEST_CLIENT="./examples/client/client"
TEST_SFTP="./examples/sftpclient/wolfsftp"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

RESULT=$( $TEST_CLIENT -c 'echo bob' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT )
echo $RESULT
echo $RESULT | grep bob
RESULT=$?
if [ "$RESULT" == 0 ]; then
    echo "Shell login should fail with forced command"
    exit 1
fi

set -e
echo exit | $TEST_SFTP -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT

cd "$TESTDIR"
stop_wolfsshd
PID=""

# A configured ForceCommand that is not "internal-sftp" must still permit the
# SFTP subsystem. Only a certificate force-command denies file transfer, so a
# long-standing ForceCommand config keeps working.
cat <<EOF > sshd_config_test_forcedcmd_sftp
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $TESTDIR/../../../keys/server-key.pem
AuthorizedKeysFile $TESTDIR/authorized_keys_test

Match User $USER
	ForceCommand /bin/echo
EOF

start_wolfsshd "sshd_config_test_forcedcmd_sftp"
cd ../../..

echo exit | $TEST_SFTP -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT

cd "$TESTDIR"
stop_wolfsshd
PID=""
exit 0


