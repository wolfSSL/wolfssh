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

# Stop the daemon on every exit path: the shell-login check below exits
# non-zero, and from the "set -e" onward an aborted client run would leave a
# root daemon holding the shared test port, so every later test in the suite
# would talk to this config. stop_wolfsshd clears PID, so this is a no-op after
# each explicit stop below.
cleanup() {
    stop_wolfsshd
    rm -f "$TESTDIR/scp_src.dat" "$TESTDIR/scp_dst.dat"
    rm -f "$TESTDIR/sshd_config_test_forcedcmd_args"
    rm -f "$TESTDIR/sshd_config_test_forcedcmd_prefix"
}
trap cleanup EXIT

# The daemon's decisions are read from log.txt, which the whole run shares:
# log_mark notes its length and log_since prints what came after.
log_mark() {
    sudo cat "$TESTDIR/log.txt" | wc -l
}

log_since() {
    sudo cat "$TESTDIR/log.txt" | tail -n +`expr $1 + 1`
}

# Native SCP is an exec, a path of its own. wolfscp masks its exit code, so
# the decision is read from the log. Fails the test unless SCP is denied.
check_scp_denied() {
    if [ ! -x "$TEST_SCP" ]; then
        return 0
    fi
    MARK=`log_mark`
    rm -f "$TESTDIR/scp_dst.dat"
    echo "scp payload" > "$TESTDIR/scp_src.dat"
    $TEST_SCP -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY \
        -S"$TESTDIR/scp_src.dat:$TESTDIR/scp_dst.dat" \
        -H $TEST_HOST -p $TEST_PORT > /dev/null 2>&1 || true
    if ! log_since $MARK | grep -q "denying SCP"; then
        echo "SCP should be denied with $1"
        exit 1
    fi
    if [ -f "$TESTDIR/scp_dst.dat" ]; then
        echo "SCP wrote its destination despite $1"
        exit 1
    fi
}

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
TEST_SCP="./examples/scpclient/wolfscp"
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

check_scp_denied "ForceCommand internal-sftp"

cd "$TESTDIR"
stop_wolfsshd

# sshd_config(5) permits options after "internal-sftp", but none is
# applied: shell is still refused and SFTP is refused too.
cat <<EOF > sshd_config_test_forcedcmd_args
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
	ForceCommand internal-sftp -u 0002
EOF

start_wolfsshd "sshd_config_test_forcedcmd_args"
cd ../../..

# The refused login exits non-zero and this runs under the "set -e" above.
# Running "internal-sftp -u 0002" as a command would print no "bob" either,
# so the refusal is read from the log.
MARK=`log_mark`
RESULT=$( $TEST_CLIENT -c 'echo bob' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT ) || true
if echo $RESULT | grep bob ||
        ! log_since $MARK | grep -q "Only SFTP connections allowed"; then
    echo "Shell login should fail with internal-sftp and options"
    exit 1
fi

MARK=`log_mark`
if echo exit | $TEST_SFTP -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY \
        -h $TEST_HOST -p $TEST_PORT; then
    echo "SFTP should fail with internal-sftp and options"
    exit 1
fi
if ! log_since $MARK | grep -q "internal-sftp options are not supported"; then
    echo "SFTP should be refused for its internal-sftp options"
    exit 1
fi

cd "$TESTDIR"
stop_wolfsshd

# A name that only starts with "internal-sftp" is some other command.
sed 's/ForceCommand internal-sftp -u 0002/ForceCommand internal-sftpd/' \
    sshd_config_test_forcedcmd_args > sshd_config_test_forcedcmd_prefix

start_wolfsshd "sshd_config_test_forcedcmd_prefix"
cd ../../..

# Refused as a forced command, not as internal-sftp with an option "d".
MARK=`log_mark`
if echo exit | $TEST_SFTP -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY \
        -h $TEST_HOST -p $TEST_PORT; then
    echo "SFTP should fail with a command named like internal-sftp"
    exit 1
fi
if ! log_since $MARK | grep -q "denying subsystem request" ||
        log_since $MARK | grep -q "options are not supported"; then
    echo "internal-sftpd was taken for internal-sftp"
    exit 1
fi

# The shell runs it as the forced command, without the internal-sftp refusal.
MARK=`log_mark`
$TEST_CLIENT -c 'echo bob' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY \
    -h $TEST_HOST -p $TEST_PORT > /dev/null 2>&1 || true
if log_since $MARK | grep -q "Only SFTP connections allowed"; then
    echo "Shell refused internal-sftpd as internal-sftp"
    exit 1
fi

cd "$TESTDIR"
stop_wolfsshd

# A ForceCommand other than "internal-sftp" denies the SFTP subsystem and
# native SCP: the client may only run the forced command.
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

if echo exit | $TEST_SFTP -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY \
        -h $TEST_HOST -p $TEST_PORT; then
    echo "SFTP should fail with a forced command other than internal-sftp"
    exit 1
fi

check_scp_denied "a forced command"

cd "$TESTDIR"
stop_wolfsshd
exit 0


