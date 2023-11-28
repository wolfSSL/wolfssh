#!/bin/bash

# sshd local test

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_exec_test.sh 127.0.0.1 22222"
    exit -1
fi

PWD=`pwd`
USER=`whoami`
TEST_PORT="$2"
TEST_HOST="$1"

sudo rm log.txt
touch log.txt

source ./start_sshd.sh
cat <<EOF > sshd_config_test_login_grace
Port $TEST_PORT
Protocol 2
LoginGraceTime 5
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
AuthorizedKeysFile $PWD/authorized_keys_test
EOF

start_wolfsshd "sshd_config_test_login_grace"
cd ../../..

TEST_CLIENT="./examples/client/client"
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"

RESULT=`$TEST_CLIENT -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT -c 'sleep 6 && echo still connected && exit'`
echo $RESULT | grep "still connected"
RESULT=$?
if [ "$RESULT" != 0 ]; then
    echo "Connection was not held open"
    exit -1
fi

# test grace login timeout by stalling on password prompt
timeout 7 $TEST_CLIENT -u $USER -h $TEST_HOST -p $TEST_PORT -t
cat ./log.txt | grep "Failed login within grace period"
RESULT=$?
if [ "$RESULT" != 0 ]; then
    echo "Grace period not hit"
    exit -1
fi

cd $PWD
#stop_wolfsshd
exit 0


