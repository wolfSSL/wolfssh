#!/bin/bash

# Test for empty-password handling.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222"
    exit 1
fi

TEST_HOST="$1"
TEST_PORT="$2"
if [ ! -z "$3" ]; then
    USER="$3"
else
    USER=`whoami`
fi
PWD=`pwd`

source ./start_sshd.sh

cat <<EOF > sshd_config_test_emptypw
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
EOF

# Fresh log so we only see this run's output.
sudo rm -f ./log.txt

start_wolfsshd "sshd_config_test_emptypw"
if [ -z "$PID" ]; then
    echo "Failed to start wolfsshd"
    exit 1
fi

TEST_CLIENT="../../../examples/client/client"

# Send an empty password
timeout 10 $TEST_CLIENT -u "$USER" -P "" -c 'true' \
    -h "$TEST_HOST" -p "$TEST_PORT" > /dev/null 2>&1

# Let wolfsshd flush the log before we stop it.
sleep 1
stop_wolfsshd

# log.txt is owned by root (wolfsshd ran via sudo); use sudo to read it.
if sudo grep -q "No compiled in password check" ./log.txt; then
    echo "SKIP: wolfsshd built without libcrypt/liblogin support"
    exit 77
fi

if sudo grep -q "Error checking password" ./log.txt; then
    echo "FAIL: empty-password NULL-guard regression detected"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi

if ! sudo grep -q "Password incorrect" ./log.txt; then
    echo "FAIL: empty-password code path was not exercised"
    echo "(expected '[SSHD] Password incorrect.' in log)"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi

exit 0
