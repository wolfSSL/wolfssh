#!/bin/bash

# Test for PermitRootLogin forced-commands-only enforcement.

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

# Build an authorized_keys file for "root" so we can test root public-key
# auth both with and without a ForceCommand configured.
cat ../../../keys/hansel-*.pub > authorized_keys_test_forced_cmd
sed -i.bak "s/hansel/root/" ./authorized_keys_test_forced_cmd

TEST_CLIENT="../../../examples/client/client"

cleanup() {
    stop_wolfsshd
    rm -f authorized_keys_test_forced_cmd authorized_keys_test_forced_cmd.bak \
        sshd_config_test_forced_cmd sshd_config_test_forced_cmd_with_cmd
}
trap cleanup EXIT

### Scenario 1: forced-commands-only with no ForceCommand configured -- both
### root password auth and root pubkey auth must be rejected.
cat <<EOF > sshd_config_test_forced_cmd
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin forced-commands-only
PasswordAuthentication yes
AuthorizedKeysFile $PWD/authorized_keys_test_forced_cmd
StrictModes no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
EOF

sudo rm -f ./log.txt

start_wolfsshd "sshd_config_test_forced_cmd"
if [ -z "$PID" ]; then
    echo "Failed to start wolfsshd"
    exit 1
fi

timeout 10 $TEST_CLIENT -u "$USER" -P "somepassword" -c 'true' \
    -h "$TEST_HOST" -p "$TEST_PORT" > /dev/null 2>&1
PASS_RESULT=$?

if [ "$PASS_RESULT" = 0 ]; then
    echo "FAIL: root password login unexpectedly succeeded under forced-commands-only"
    exit 1
fi

timeout 10 $TEST_CLIENT -u "$USER" -c 'true' \
    -i ../../../keys/hansel-key-ecc.der -j ../../../keys/hansel-key-ecc.pub \
    -h "$TEST_HOST" -p "$TEST_PORT" > /dev/null 2>&1
NOCMD_PUBKEY_RESULT=$?

if [ "$NOCMD_PUBKEY_RESULT" = 0 ]; then
    echo "FAIL: root pubkey login without a ForceCommand unexpectedly succeeded"
    exit 1
fi

# Let wolfsshd flush the log before we stop it.
sleep 1

if ! sudo grep -q "Password authentication for root not allowed by configuration!" ./log.txt; then
    echo "FAIL: forced-commands-only did not reject root password login as expected"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi

if ! sudo grep -q "Public key login for root requires a forced command by configuration!" ./log.txt; then
    echo "FAIL: forced-commands-only did not reject root pubkey login without a ForceCommand"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi

stop_wolfsshd

### Scenario 2: forced-commands-only WITH a ForceCommand configured -- root
### pubkey login must now be permitted.
cat <<EOF > sshd_config_test_forced_cmd_with_cmd
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin forced-commands-only
ForceCommand true
PasswordAuthentication yes
AuthorizedKeysFile $PWD/authorized_keys_test_forced_cmd
StrictModes no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
EOF

sudo rm -f ./log.txt

start_wolfsshd "sshd_config_test_forced_cmd_with_cmd"
if [ -z "$PID" ]; then
    echo "Failed to start wolfsshd"
    exit 1
fi

timeout 10 $TEST_CLIENT -u "$USER" -c 'true' \
    -i ../../../keys/hansel-key-ecc.der -j ../../../keys/hansel-key-ecc.pub \
    -h "$TEST_HOST" -p "$TEST_PORT" > /dev/null 2>&1
WITHCMD_PUBKEY_RESULT=$?

if [ "$WITHCMD_PUBKEY_RESULT" != 0 ]; then
    echo "FAIL: root pubkey login with a ForceCommand configured was rejected"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi

exit 0
