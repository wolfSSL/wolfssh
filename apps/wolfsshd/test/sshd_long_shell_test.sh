#!/bin/bash

# A login shell path longer than wolfsshd's old 80-byte command buffer must be
# executed whole. The first 79 bytes of the path name a different executable,
# so a truncated copy would run that one instead. The shell also has to see
# "-" plus its own basename as argv[0], not "-sh". Creates a throwaway account,
# so it only runs on Linux with useradd/userdel and passwordless sudo.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222"
    exit 1
fi

TEST_HOST="$1"
TEST_PORT="$2"
PWD=`pwd`

if [ "$(uname -s)" != "Linux" ] || ! command -v useradd >/dev/null 2>&1 || \
   ! command -v userdel >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
    echo "SKIP: needs root on Linux with useradd/userdel"
    exit 77
fi

source ./start_sshd.sh

TEST_CLIENT="../../../examples/client/client"
PRIVATE_KEY="$PWD/../../../keys/hansel-key-ecc.der"
PUBLIC_KEY="$PWD/../../../keys/hansel-key-ecc.pub"
LONG_USER="wolfsshdlsh$$"
USER_CREATED=""
SHELL_DIR=""

cleanup() {
    stop_wolfsshd
    if [ -n "$USER_CREATED" ]; then
        sudo userdel "$LONG_USER" 2>/dev/null
    fi
    if [ -n "$SHELL_DIR" ]; then
        sudo rm -rf "$SHELL_DIR"
    fi
    rm -f sshd_config_test_long_shell authorized_keys_test_long_shell
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

# Fixed short prefix under the world-traversable /tmp, whatever $TMPDIR is, so
# the 79-byte decoy lands inside SHELL_DIR and the new account can reach it.
SHELL_DIR=$(mktemp -d /tmp/wolfsshd_lsh.XXXXXX)
chmod 755 "$SHELL_DIR"
LONG_DIR="$SHELL_DIR/$(printf 'd%.0s' $(seq 1 60))"
mkdir "$LONG_DIR"
chmod 755 "$LONG_DIR"
LONG_SHELL="$LONG_DIR/long_shell_real"
SHORT_SHELL="${LONG_SHELL:0:79}"
if [ ${#LONG_SHELL} -le 80 ] || [ "$SHORT_SHELL" = "$LONG_SHELL" ]; then
    echo "FAIL: shell path is only ${#LONG_SHELL} bytes"
    exit 1
fi
# A link, not a wrapper script, so sh's $0 is the argv[0] wolfsshd passed.
ln -s /bin/sh "$LONG_SHELL"
printf '#!/bin/sh\necho TRUNCATED SHELL RAN\n' > "$SHORT_SHELL"
chmod 755 "$SHORT_SHELL"

if ! sudo useradd -M -s "$LONG_SHELL" "$LONG_USER"; then
    echo "SKIP: could not create $LONG_USER"
    exit 77
fi
USER_CREATED=1

sed "s/hansel/$LONG_USER/" $PUBLIC_KEY > authorized_keys_test_long_shell

cat <<EOF > sshd_config_test_long_shell
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin no
PasswordAuthentication no
StrictModes no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
AuthorizedKeysFile $PWD/authorized_keys_test_long_shell
EOF

start_wolfsshd "sshd_config_test_long_shell"
if [ -z "$PID" ]; then
    echo "FAIL: could not start wolfsshd"
    exit 1
fi

# -q keeps a debug build's log, which echoes the command text, out of RESULT.
# The expected line only exists once the shell has expanded $0.
RESULT=$(timeout 10 $TEST_CLIENT -q -c 'echo LONG SHELL RAN as $0' \
    -u "$LONG_USER" -i $PRIVATE_KEY -j $PUBLIC_KEY \
    -h "$TEST_HOST" -p "$TEST_PORT" 2>&1)
CLIENT_RESULT=$?
echo "$RESULT"
if echo "$RESULT" | grep -q "TRUNCATED SHELL RAN"; then
    echo "FAIL: wolfsshd ran the truncated shell path"
    exit 1
fi
if [ "$CLIENT_RESULT" != 0 ]; then
    echo "FAIL: client exited $CLIENT_RESULT"
    exit 1
fi
if ! echo "$RESULT" | grep -qx "LONG SHELL RAN as -long_shell_real"; then
    echo "FAIL: the long shell did not run as -long_shell_real"
    exit 1
fi

exit 0
