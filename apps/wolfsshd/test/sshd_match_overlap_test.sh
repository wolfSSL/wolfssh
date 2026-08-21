#!/bin/bash

# sshd local test
#
# OpenSSH resolves sshd_config one keyword at a time: "For each keyword, the
# first obtained value will be used", scanning every Match block that applies to
# the connection. A user who matches both a Match User block and a Match Group
# block therefore gets the settings from both, and the outcome does not depend
# on which block is written first.
#
# This test writes the same two blocks in both orders. Only the group block sets
# ForceCommand, so a shell exec must be refused either way. Resolving the whole
# first matching block instead of composing per keyword would drop the forced
# command in the user-first order and let the exec through.
#
# Expects ./authorized_keys_test to exist, as the other tests here do. Create it
# with ./create_authorized_test_file.sh when running this script on its own.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222"
    exit 1
fi

# Not named PWD: the shell rewrites that variable on every cd, so a saved copy
# would not survive a cd made here or by anything this script sources.
TESTDIR=`pwd`
USER=`whoami`
GROUP=`id -gn $USER`
TEST_PORT="$2"
TEST_HOST="$1"
source ./start_sshd.sh

# Stop the daemon on every exit path: a failed scenario exits non-zero straight
# out of the script, and a root daemon left holding the shared test port would
# answer for every later test in the suite. stop_wolfsshd clears PID, so this is
# a no-op after each explicit stop below.
trap stop_wolfsshd EXIT

# The client chdir's to the wolfSSH root before it parses its arguments, so the
# key paths have to be absolute rather than relative to this directory.
TEST_CLIENT="$TESTDIR/../../../examples/client/client"
PRIVATE_KEY="$TESTDIR/../../../keys/hansel-key-ecc.der"
PUBLIC_KEY="$TESTDIR/../../../keys/hansel-key-ecc.pub"

# writes a config named $1 holding the two overlapping blocks. $2 selects which
# block is written first, "user" or "group". Both orders name the same two
# blocks with the same settings.
write_config() {
    cat <<EOF > "$1"
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
EOF

    if [ "$2" == "user" ]; then
        cat <<EOF >> "$1"

Match User $USER
	PermitEmptyPasswords no

Match Group $GROUP
	ForceCommand internal-sftp
EOF
    else
        cat <<EOF >> "$1"

Match Group $GROUP
	ForceCommand internal-sftp

Match User $USER
	PermitEmptyPasswords no
EOF
    fi
}

# runs a shell exec against the daemon started from config $1 and fails when the
# command runs, which means the group block's ForceCommand was not applied
#
# The marker is split with an empty quoted string so the command the client
# sends and the output the remote shell produces are not the same text. A debug
# build logs the command it sends, and grepping for a marker that appears
# verbatim in that log reports a shell that never ran as one that did.
check_forced_cmd() {
    start_wolfsshd "$1"

    RESULT=$( $TEST_CLIENT -c 'echo overlap""_shell_ran' -u $USER \
        -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT )
    echo $RESULT
    echo $RESULT | grep overlap_shell_ran
    FOUND=$?

    stop_wolfsshd

    if [ "$FOUND" == 0 ]; then
        echo "$2: shell login should fail, the Match Group block sets"
        echo "ForceCommand internal-sftp and the user is in that group"
        return 1
    fi
    return 0
}

write_config sshd_config_test_match_overlap_user "user"
check_forced_cmd sshd_config_test_match_overlap_user "user block first" || exit 1

write_config sshd_config_test_match_overlap_group "group"
check_forced_cmd sshd_config_test_match_overlap_group "group block first" || exit 1

exit 0
