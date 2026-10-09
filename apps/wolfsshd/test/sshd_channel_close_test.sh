#!/bin/bash
# Closing a session channel while wolfsshd holds its output must not leave the
# connection process waiting on the command. The exec command traps INT and
# HUP, so only the reap's SIGKILL ends it; a pty shell must exit on the hangup.
# The exit status must still reach the client, from an exec and from a shell.
#
# Needs paramiko: the OpenSSH client never closes the channel early; it keeps
# reading and discards what it cannot write.
HOST="$1"
PORT="$2"
USER_NAME="${3:-`whoami`}"

command -v python3 >/dev/null 2>&1 || exit 77
python3 -c "import paramiko" >/dev/null 2>&1 || exit 77
command -v timeout >/dev/null 2>&1 || exit 77

# The command's pid is checked on this machine.
case "$HOST" in
    127.0.0.1|localhost|::1) ;;
    *) exit 77 ;;
esac

KEYDIR=`mktemp -d` || exit 1
MARKDIR=`mktemp -d` || exit 1
trap 'rm -rf "$KEYDIR" "$MARKDIR"' EXIT
# Private to the login user, who writes the marker.
chown "$USER_NAME" "$MARKDIR" || exit 77
cp ../../../keys/hansel-key-ecc.pem "$KEYDIR/id_ecdsa" || exit 1
chmod 600 "$KEYDIR/id_ecdsa"

timeout 60 python3 -u - "$HOST" "$PORT" "$USER_NAME" "$KEYDIR/id_ecdsa" \
    "$MARKDIR/exited" <<'EOF'
import os
import re
import sys
import time

import paramiko

host, port, user, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
marker = sys.argv[5]
LIMIT = 5
WAIT = 20  # for any one read or exit status


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


def connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=user,
                   pkey=paramiko.ECDSAKey.from_private_key_file(key),
                   look_for_keys=False, allow_agent=False, timeout=10)
    return client


def run_case(name, shell):
    client = connect()
    chan = client.get_transport().open_session()
    chan.settimeout(WAIT)
    if shell:
        chan.get_pty()
        chan.invoke_shell()
        # The marker is a builtin redirection on the exit path only.
        chan.send("trap 'exit' HUP; trap ': > %s' EXIT; echo PID=$$\n"
                  % marker)
    else:
        chan.exec_command('echo PID=$$; trap "" INT HUP; '
                          'seq 1 10000000; sleep 30')

    # The pty echoes the typed line with a literal $$, which does not match,
    # and the newline keeps a pid split across two reads from matching.
    out = b""
    match = None
    while match is None:
        data = chan.recv(4096)
        if not data:
            break
        out += data
        match = re.search(rb"PID=(\d+)\r?\n", out)
    if match is None:
        print("%s: no pid from the command" % name)
        client.close()
        return False
    pid = int(match.group(1))
    if shell:
        chan.send("seq 1 10000000\n")

    # Stop reading until the window fills and wolfsshd holds output, then
    # close the channel with the transport still up.
    time.sleep(1)
    chan.close()

    start = time.time()
    while alive(pid) and time.time() - start < LIMIT:
        time.sleep(0.1)
    # The connection process ends too, and closes the connection.
    transport = client.get_transport()
    while transport.is_active() and time.time() - start < LIMIT:
        time.sleep(0.1)
    closed = not transport.is_active()
    client.close()

    if alive(pid):
        print("%s: command %d still running %ds after the channel close" %
              (name, pid, LIMIT))
        return False
    print("%s: command %d gone %.1fs after the channel close" %
          (name, pid, time.time() - start))
    if not closed:
        print("%s: connection still open %ds after the channel close" %
              (name, LIMIT))
        return False
    # SIGKILL cannot run the trap, so the marker means the shell exited itself.
    if shell and not os.path.exists(marker):
        print("%s: killed instead of exiting on the hangup" % name)
        return False
    return True


def run_status(name, shell):
    client = connect()
    chan = client.get_transport().open_session()
    if shell:
        # An exec takes the pipe path even with a pty; a shell reads the pty.
        chan.get_pty()
        chan.invoke_shell()
        chan.send("exit 3\n")
    else:
        chan.exec_command("exit 3")
    start = time.time()
    while not chan.exit_status_ready() and time.time() - start < WAIT:
        time.sleep(0.05)
    if not chan.exit_status_ready():
        print("%s: no exit status within %ds" % (name, WAIT))
        client.close()
        return False
    status = chan.recv_exit_status()
    client.close()
    print("%s: exit status %d, expected 3" % (name, status))
    return status == 3


try:
    connect().close()
except (paramiko.SSHException, OSError) as e:
    print("cannot connect with paramiko: %s" % e)
    sys.exit(77)

ok = run_case("exec", False)
ok = run_case("pty shell", True) and ok
ok = run_status("exec status", False) and ok
ok = run_status("shell status", True) and ok
sys.exit(0 if ok else 1)
EOF
