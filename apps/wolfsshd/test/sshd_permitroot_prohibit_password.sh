#!/bin/bash

# Test for PermitRootLogin prohibit-password enforcement.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222"
    exit 1
fi

TEST_HOST="$1"
TEST_PORT="$2"
USER="root"
PWD=`pwd`

source ./start_sshd.sh

# Build an authorized_keys file for "root" so we can confirm root public-key
# auth is still permitted under prohibit-password, while root password auth
# is rejected.
cat ../../../keys/hansel-*.pub > authorized_keys_test_prohibit_pw
sed -i.bak "s/hansel/root/" ./authorized_keys_test_prohibit_pw

cat <<EOF > sshd_config_test_prohibit_pw
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin prohibit-password
PasswordAuthentication yes
AuthorizedKeysFile $PWD/authorized_keys_test_prohibit_pw
StrictModes no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
EOF

# Fresh log so we only see this run's output.
sudo rm -f ./log.txt

cleanup() {
    stop_wolfsshd
    rm -f authorized_keys_test_prohibit_pw authorized_keys_test_prohibit_pw.bak \
        sshd_config_test_prohibit_pw
}
trap cleanup EXIT

start_wolfsshd "sshd_config_test_prohibit_pw"
if [ -z "$PID" ]; then
    echo "Failed to start wolfsshd"
    exit 1
fi

TEST_CLIENT="../../../examples/client/client"

# Attempt password login as root, which should be rejected
timeout 10 $TEST_CLIENT -u "$USER" -P "somepassword" -c 'true' \
    -h "$TEST_HOST" -p "$TEST_PORT" > /dev/null 2>&1
PASS_RESULT=$?

if [ "$PASS_RESULT" = 0 ]; then
    echo "FAIL: root password login unexpectedly succeeded"
    exit 1
fi

# Attempt public-key login as root, which should still be permitted under
# prohibit-password (only password auth is restricted for root).
timeout 10 $TEST_CLIENT -u "$USER" -c 'true' \
    -i ../../../keys/hansel-key-ecc.der -j ../../../keys/hansel-key-ecc.pub \
    -h "$TEST_HOST" -p "$TEST_PORT" > /dev/null 2>&1
PUBKEY_RESULT=$?

# Let wolfsshd flush the log before we stop it.
sleep 1

# log.txt is owned by root (wolfsshd ran via sudo); use sudo to read it.
if ! sudo grep -q "Password authentication for root not allowed by configuration!" ./log.txt; then
    echo "FAIL: PermitRootLogin prohibit-password bypass detected or message changed"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi

if [ "$PUBKEY_RESULT" != 0 ]; then
    echo "FAIL: root public-key login was rejected under PermitRootLogin prohibit-password"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi

exit 0
