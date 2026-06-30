#!/bin/bash

# Test for PermitRootLogin enforcement.
#
# DoCheckUser rejects a uid 0 login before any credential check, so these checks
# only need to connect and inspect the daemon log; no valid password is needed.
# Two layers are exercised:
#   1. the always-present "root" account (negative + positive control), and
#   2. a duplicate uid 0 alias account, which proves the check is uid based
#      rather than name based. The alias layer creates a second uid 0 account so
#      it only runs as root on Linux with useradd/userdel and is skipped
#      otherwise.

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "$0 127.0.0.1 22222"
    exit 1
fi

TEST_HOST="$1"
TEST_PORT="$2"
PWD=`pwd`

source ./start_sshd.sh

TEST_CLIENT="../../../examples/client/client"
REJECT_MSG="Login as root not permitted"
ALIAS_USER=""
ALIAS_CREATED=""

cleanup() {
    if [ -n "$ALIAS_CREATED" ]; then
        sudo userdel "$ALIAS_USER" 2>/dev/null
    fi
    rm -f sshd_config_test_permitroot_no sshd_config_test_permitroot_yes
}
trap cleanup EXIT
# On a signal, exit so the EXIT trap above removes the uid 0 alias. SIGKILL
# cannot be trapped and is the one case a leftover account is possible.
trap 'exit 1' INT TERM HUP

write_config() {
    # $1 = destination file, $2 = PermitRootLogin value
    cat <<EOF > "$1"
Port $TEST_PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin $2
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
AuthorizedKeysFile $PWD/authorized_keys_test
EOF
}

# Start the daemon with the given config, attempt a login as the given user with
# a dummy password, then stop the daemon. Leaves the run output in ./log.txt.
attempt_login() {
    # $1 = config file, $2 = username
    sudo rm -f ./log.txt
    start_wolfsshd "$1"
    if [ -z "$PID" ]; then
        echo "FAIL: could not start wolfsshd"
        exit 1
    fi
    timeout 10 $TEST_CLIENT -u "$2" -P "wolfsshd-dummy-pw" -c 'true' \
        -h "$TEST_HOST" -p "$TEST_PORT" > /dev/null 2>&1
    # Let wolfsshd flush the log before we stop it.
    sleep 1
    stop_wolfsshd
}

write_config sshd_config_test_permitroot_no  no
write_config sshd_config_test_permitroot_yes yes

# Layer 1a (negative): root must be rejected when PermitRootLogin is no.
attempt_login sshd_config_test_permitroot_no root
if ! sudo grep -q "$REJECT_MSG" ./log.txt; then
    echo "FAIL: root login was not rejected under PermitRootLogin no"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi

# Layer 1b (positive control): with PermitRootLogin yes the gate must not fire,
# so the rejection message must be absent while the request still reached
# DoCheckUser.
attempt_login sshd_config_test_permitroot_yes root
if sudo grep -q "$REJECT_MSG" ./log.txt; then
    echo "FAIL: root rejected even though PermitRootLogin is yes"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi
if ! sudo grep -q "Checking user name root" ./log.txt; then
    echo "FAIL: positive control did not reach the user check"
    echo "----- log.txt -----"
    sudo cat ./log.txt
    exit 1
fi

# Layer 2 (alias): only when a duplicate uid 0 account can be created and torn
# down safely. This is the case the fix targets: a non-"root" name that resolves
# to uid 0 must still be subject to PermitRootLogin.
if [ "$(uname -s)" = "Linux" ] && command -v useradd >/dev/null 2>&1 && \
   command -v userdel >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    ALIAS_USER="wolfsshduid0$$"
    if sudo useradd -o -u 0 -g 0 -M -s /usr/sbin/nologin "$ALIAS_USER" \
            2>/dev/null; then
        ALIAS_CREATED=1
        attempt_login sshd_config_test_permitroot_no "$ALIAS_USER"
        if ! sudo grep -q "$REJECT_MSG" ./log.txt; then
            echo "FAIL: uid 0 alias '$ALIAS_USER' bypassed PermitRootLogin no"
            echo "----- log.txt -----"
            sudo cat ./log.txt
            exit 1
        fi
    else
        echo "SKIP alias layer: could not create uid 0 alias account"
    fi
else
    echo "SKIP alias layer: needs root on Linux with useradd/userdel"
fi

exit 0
