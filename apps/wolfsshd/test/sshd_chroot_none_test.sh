#!/bin/bash

# sshd local test
#
# "ChrootDirectory none" means no chroot, as it does in OpenSSH. The usual use
# is a Match block that exempts a user from a global ChrootDirectory. Taken as
# a path, "none" is a chdir() target that does not exist and the session dies.
#
# The global chroot here is a directory with no shell in it, so a session that
# is chrooted cannot run the command either. The command running shows the
# Match block's "none" took effect. A global "none" is checked the same way.
#
# Expects ./authorized_keys_test to exist, as the other tests here do. Create it
# with ./create_authorized_test_file.sh when running this script on its own.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222"
    exit 1
fi

TESTDIR=`pwd`
USER=`whoami`
TEST_PORT="$2"
TEST_HOST="$1"
source ./start_sshd.sh

# chroot(2) needs root, and start_sshd.sh gets there with sudo
if [ "`id -u`" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    echo "SKIP: chroot test needs root or non-interactive sudo"
    exit 77
fi

CHROOT_DIR="$TESTDIR/chroot_none_target"

cleanup() {
    stop_wolfsshd
    rm -f sshd_config_test_chroot_none_*
    rmdir "$CHROOT_DIR" 2>/dev/null
    return 0
}
trap cleanup EXIT

if [ ! -f authorized_keys_test ]; then
    ./create_authorized_test_file.sh || exit 1
fi
mkdir -p "$CHROOT_DIR"

TEST_CLIENT="$TESTDIR/../../../examples/client/client"
PRIVATE_KEY="$TESTDIR/../../../keys/hansel-key-ecc.der"
PUBLIC_KEY="$TESTDIR/../../../keys/hansel-key-ecc.pub"

# writes the global section of a config to $1, with $2 as ChrootDirectory
write_config() {
    cat <<EOF > "$1"
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication no
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $TESTDIR/../../../keys/server-key.pem
AuthorizedKeysFile $TESTDIR/authorized_keys_test
ChrootDirectory $2
EOF
}

# starts the daemon with config $1 and runs a key login. Returns 0 when the
# remote command ran. The marker is split so the command sent and the output
# returned differ, see sshd_match_overlap_test.sh.
try_login() {
    start_wolfsshd "$1"
    if [ -z "$PID" ]; then
        echo "FAIL: daemon did not start with $1"
        exit 1
    fi
    RESULT=$( timeout 10 $TEST_CLIENT -c 'echo chroot""_none_ran' \
        -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT \
        2>&1 )
    echo "$RESULT"
    stop_wolfsshd
    echo "$RESULT" | grep -q chroot_none_ran
}

# control: the global chroot alone leaves no shell to run the command
CFG=sshd_config_test_chroot_none_control
write_config $CFG "$CHROOT_DIR"
if try_login $CFG; then
    echo "FAIL: command ran inside an empty chroot; setup issue"
    exit 1
fi

CFG=sshd_config_test_chroot_none_global
write_config $CFG "none"
if ! try_login $CFG; then
    echo "FAIL: ChrootDirectory none still tried to chroot"
    exit 1
fi

CFG=sshd_config_test_chroot_none_match
write_config $CFG "$CHROOT_DIR"
cat <<EOF >> $CFG

Match User $USER
	ChrootDirectory none
EOF
if ! try_login $CFG; then
    echo "FAIL: Match ChrootDirectory none did not exempt the user"
    exit 1
fi

exit 0
