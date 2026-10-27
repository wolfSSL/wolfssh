#!/bin/bash

# sshd local test
#
# "AuthorizedKeysFile none" turns off the authorized keys file, as it does in
# OpenSSH. It is not a file name: a relative "none" would resolve to ~/none,
# a file the user controls, and any key placed there would log in.
#
# This test puts an authorized key in the login user's ~/none and checks a
# public key login is refused, both with "none" set globally and with it set
# in a Match block over a global file that does hold the key. Two controls
# come first: the global file alone shows the key and client work, and
# "./none", which names the same file without the keyword, shows the daemon
# can read ~/none, so a refusal below is the keyword's doing.
#
# On an X.509 build with FPKI it then checks "none" does not trip the
# wolfSSH_TrustedSystemCAKeys startup gate, and that "none" refuses a CA-issued
# client certificate, which with no AuthorizedKeysFile at all logs in on the CA
# and its UPN binding alone. Without FPKI the daemon cannot bind a certificate
# to a user, so it refuses a CA-only login with or without "none".
#
# Expects ./authorized_keys_test to exist, as the other tests here do. Create it
# with ./create_authorized_test_file.sh when running this script on its own.
# The X.509 cases expect keys/<user>-cert.der from create_sshd_config.sh.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222"
    exit 1
fi

TESTDIR=`pwd`
USER=`whoami`
. ./wolfssh_options.sh
TEST_PORT="$2"
TEST_HOST="$1"
source ./start_sshd.sh

# The daemon resolves a relative AuthorizedKeysFile under the passwd entry's
# home directory, which need not be $HOME under sudo.
HOME_DIR=`getent passwd "$USER" | cut -d: -f6`
if [ -z "$HOME_DIR" ] || [ ! -d "$HOME_DIR" ]; then
    echo "SKIP: no home directory for $USER"
    exit 77
fi
NONE_FILE="$HOME_DIR/none"
if [ -e "$NONE_FILE" ]; then
    echo "SKIP: $NONE_FILE already exists"
    exit 77
fi
# StrictModes refuses a key file under a group or world writable home, which
# would fail the ./none control for a reason that is not wolfsshd's
if [ -n "`find "$HOME_DIR" -maxdepth 0 -perm /022`" ]; then
    echo "SKIP: $HOME_DIR is group or world writable"
    exit 77
fi

cleanup() {
    stop_wolfsshd
    rm -f "$NONE_FILE"
    rm -f sshd_config_test_authkeys_none_*
    return 0
}
trap cleanup EXIT

if [ ! -f authorized_keys_test ]; then
    ./create_authorized_test_file.sh || exit 1
fi
# 0644 for the StrictModes check, as create_authorized_test_file.sh does
if ! cp authorized_keys_test "$NONE_FILE"; then
    echo "SKIP: cannot write $NONE_FILE"
    exit 77
fi
chmod 0644 "$NONE_FILE"

TEST_CLIENT="$TESTDIR/../../../examples/client/client"
PRIVATE_KEY="$TESTDIR/../../../keys/hansel-key-ecc.der"
PUBLIC_KEY="$TESTDIR/../../../keys/hansel-key-ecc.pub"

# writes the global section of a config to $1, with $2 as AuthorizedKeysFile
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
AuthorizedKeysFile $2
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
    RESULT=$( timeout 10 $TEST_CLIENT -c 'echo authkeys""_none_ran' \
        -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h $TEST_HOST -p $TEST_PORT \
        2>&1 )
    echo "$RESULT"
    stop_wolfsshd
    echo "$RESULT" | grep -q authkeys_none_ran
}

CFG=sshd_config_test_authkeys_none_control
write_config $CFG "$TESTDIR/authorized_keys_test"
if ! try_login $CFG; then
    echo "FAIL: control login with the global file failed; setup issue"
    exit 1
fi

CFG=sshd_config_test_authkeys_none_dotnone
write_config $CFG "./none"
if ! try_login $CFG; then
    echo "FAIL: control login through ./none failed; $NONE_FILE is not readable"
    exit 1
fi

CFG=sshd_config_test_authkeys_none_global
write_config $CFG "none"
if try_login $CFG; then
    echo "FAIL: AuthorizedKeysFile none read keys from $NONE_FILE"
    exit 1
fi

CFG=sshd_config_test_authkeys_none_match
write_config $CFG "$TESTDIR/authorized_keys_test"
cat <<EOF >> $CFG

Match User $USER
	AuthorizedKeysFile none
EOF
if try_login $CFG; then
    echo "FAIL: Match AuthorizedKeysFile none did not disable the key file"
    exit 1
fi

# starts the daemon with config $1 and returns 0 when it came up
try_start() {
    start_wolfsshd "$1"
    if [ -z "$PID" ]; then
        return 1
    fi
    stop_wolfsshd
    return 0
}

# wolfSSH_TrustedSystemCAKeys on an FPKI build refuses to start unless every
# config node binds certificates with AuthorizedUPNDomains or a per-user
# AuthorizedKeysFile. A node with "none" takes no certificate login at all,
# so it must not stop the daemon. The shared-file case shows the gate is live.
if wolfssh_has CERTS && wolfssh_has FPKI; then
    CFG=sshd_config_test_authkeys_none_sysca_control
    write_config $CFG ".ssh/authorized_keys"
    echo "wolfSSH_TrustedSystemCAKeys yes" >> $CFG
    if ! try_start $CFG; then
        echo "system CA cases skipped: daemon cannot load the system CAs"
    else
        CFG=sshd_config_test_authkeys_none_sysca_shared
        write_config $CFG "$TESTDIR/authorized_keys_test"
        echo "wolfSSH_TrustedSystemCAKeys yes" >> $CFG
        if try_start $CFG; then
            echo "FAIL: system CA gate accepted a shared AuthorizedKeysFile"
            exit 1
        fi

        CFG=sshd_config_test_authkeys_none_sysca_global
        write_config $CFG "none"
        echo "wolfSSH_TrustedSystemCAKeys yes" >> $CFG
        if ! try_start $CFG; then
            echo "FAIL: system CA gate refused AuthorizedKeysFile none"
            exit 1
        fi

        CFG=sshd_config_test_authkeys_none_sysca_match
        write_config $CFG ".ssh/authorized_keys"
        cat <<EOF >> $CFG
wolfSSH_TrustedSystemCAKeys yes

Match User $USER
	AuthorizedKeysFile none
EOF
        if ! try_start $CFG; then
            echo "FAIL: system CA gate refused Match AuthorizedKeysFile none"
            exit 1
        fi
    fi
fi

# X.509: the daemon setup of sshd_x509_test.sh, which needs a build without
# FPKI profile enforcement since the test certificates meet none. A CA-only
# login needs FPKI for the UPN binding; without it the daemon refuses one.
CERT_KEY="$TESTDIR/../../../keys/$USER-key.der"
CERT="$TESTDIR/../../../keys/$USER-cert.der"
CA_CERT="$TESTDIR/../../../keys/ca-cert-ecc.der"
if ! wolfssh_has CERTS || ! wolfssh_has FPKI || wolfssh_has FPKI_PROFILE; then
    echo "X.509 cases skipped: no certificates, no FPKI, or FPKI profiles on"
    exit 0
fi
if [ ! -f "$CERT" ] || [ ! -f "$CERT_KEY" ]; then
    echo "X.509 cases skipped: no $CERT, run create_sshd_config.sh"
    exit 0
fi

# writes an X.509 config to $1 with no AuthorizedKeysFile, so a certificate
# logs in on the CA and UPN alone unless "none" stops it; the realm matches the
# test certificates, as create_sshd_config.sh writes it
write_x509_config() {
    cat <<EOF > "$1"
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication no
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
TrustedUserCAKeys $TESTDIR/../../../keys/ca-cert-ecc.pem
HostKey $TESTDIR/../../../keys/server-key.pem
HostCertificate $TESTDIR/../../../keys/server-cert.pem
AuthorizedUPNDomains example
EOF
}

# as try_login, with the client offering an X.509 certificate
try_cert_login() {
    start_wolfsshd "$1"
    if [ -z "$PID" ]; then
        echo "FAIL: daemon did not start with $1"
        exit 1
    fi
    RESULT=$( timeout 10 $TEST_CLIENT -X -c 'echo authkeys""_none_ran' \
        -u $USER -i $CERT_KEY -J $CERT -A $CA_CERT \
        -h $TEST_HOST -p $TEST_PORT 2>&1 )
    echo "$RESULT"
    stop_wolfsshd
    echo "$RESULT" | grep -q authkeys_none_ran
}

CFG=sshd_config_test_authkeys_none_x509_control
write_x509_config $CFG
if ! try_cert_login $CFG; then
    echo "FAIL: control certificate login on the CA alone failed; setup issue"
    exit 1
fi

CFG=sshd_config_test_authkeys_none_x509_global
write_x509_config $CFG
echo "AuthorizedKeysFile none" >> $CFG
if try_cert_login $CFG; then
    echo "FAIL: AuthorizedKeysFile none let a certificate in on the CA alone"
    exit 1
fi

CFG=sshd_config_test_authkeys_none_x509_match
write_x509_config $CFG
cat <<EOF >> $CFG

Match User $USER
	AuthorizedKeysFile none
EOF
if try_cert_login $CFG; then
    echo "FAIL: Match AuthorizedKeysFile none let a certificate in on the CA"
    exit 1
fi

exit 0
