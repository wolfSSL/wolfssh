#!/bin/bash

# sshd local test

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_exec_test.sh 127.0.0.1 22222"
    exit 1
fi

PWD=`pwd`

if [ ! -z "$3" ]; then
    USER="$3"
else
    USER=`whoami`
fi
TEST_PORT="$2"
TEST_HOST="$1"
source ./start_sshd.sh
cat <<EOF > sshd_config_test_window
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
EOF

start_wolfsshd "sshd_config_test_window"
cd ../../..

TEST_CLIENT="./examples/client/client"
TEST_SFTP="./examples/sftpclient/wolfsftp"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

head -c 1G /dev/urandom > random-test.txt

PWD=`pwd`
$TEST_CLIENT -c "cd $PWD; $TEST_CLIENT -c \"cat $PWD/random-test.txt\" -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT" -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT > random-test-result.txt

diff random-test.txt random-test-result.txt
RESULT=$?
if [ "$RESULT" != 0 ]; then
    echo "cat did not pass through all expected data"
    ls -la random-test.txt
    ls -la random-test-result.txt
    exit 1
fi

stop_wolfsshd
exit 0

