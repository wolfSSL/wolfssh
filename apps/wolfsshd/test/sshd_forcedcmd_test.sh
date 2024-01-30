#!/bin/bash

# sshd local test

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_exec_test.sh 127.0.0.1 22222"
    exit 1
fi

PWD=`pwd`
USER=`whoami`
TEST_PORT="$2"
TEST_HOST="$1"
source ./start_sshd.sh
cat <<EOF > sshd_config_test_forcedcmd
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
AuthorizedKeysFile $PWD/authorized_keys_test

Match User $USER
	ForceCommand internal-sftp
EOF

start_wolfsshd "sshd_config_test_forcedcmd"
cd ../../..

TEST_CLIENT="./examples/client/client"
TEST_SFTP="./examples/sftpclient/wolfsftp"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

RESULT=`$TEST_CLIENT -c 'echo bob' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT`
cat $RESULT | grep bob
RESULT=$?
if [ "$RESULT" == 0 ]; then
    echo "Shell login should fail with forced command"
    exit 1
fi

set -e
echo exit | $TEST_SFTP -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT

cd $PWD
stop_wolfsshd
exit 0


