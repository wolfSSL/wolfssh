#!/bin/bash

# Holds the per-daemon temp dir used for root-owned trust-anchor copies, so
# stop_wolfsshd can remove it. Empty when no copies were made.
SSHD_KEYDIR=""

# starts up a sshd session, takes in the sshd_config file as an argument
start_wolfsshd() {
    CURRENT_PIDS=`ps -e | grep wolfsshd | grep -oE "[0-9]+"`

    ORIGCFG="$1"
    CONFIG="$ORIGCFG"
    # Reset so each invocation is self-contained regardless of call ordering.
    SSHD_KEYDIR=""

    # wolfSSHd loads each trust anchor (host key, host cert, user CA) through the
    # secure gate, which refuses a file not owned by the daemon's user or root
    # and, for the secret host key, a group/world readable one. This shared
    # daemon is launched with sudo (euid 0) while the repository key files are
    # owned by the checkout user, so copy each configured trust anchor into a
    # private dir, make the copies root-owned and mode 0600, and emit a temp
    # config pointing at them. The version-controlled files are left untouched so
    # the suite stays re-runnable.
    if grep -qE '^[[:space:]]*(HostKey|HostCertificate|TrustedUserCAKeys)[[:space:]]' "$ORIGCFG"; then
        SSHD_KEYDIR=$(mktemp -d 2>/dev/null) || SSHD_KEYDIR=$(mktemp -d -t sshdkeys)
        if [ -z "$SSHD_KEYDIR" ] || [ ! -d "$SSHD_KEYDIR" ]; then
            printf "WARNING: could not create temp dir for trust-anchor copies; using original config\n" >&2
            SSHD_KEYDIR=""
        else
            CONFIG="$SSHD_KEYDIR/sshd_config"
            : > "$CONFIG" || { printf "WARNING: could not write %s; using original config\n" "$CONFIG" >&2; CONFIG="$ORIGCFG"; rm -rf "$SSHD_KEYDIR"; SSHD_KEYDIR=""; }
        fi
        # Only rewrite when the temp config was set up. On any fallback above
        # SSHD_KEYDIR is empty and CONFIG still points at ORIGCFG; running the
        # loop then would read from and append to the same file, never reaching
        # EOF (runaway append) and would also operate on "/anchorN.pem" at the
        # filesystem root. Skipping it leaves the original config untouched.
        if [ -n "$SSHD_KEYDIR" ]; then
            n=0
            # Rewrite the config line by line. For each trust-anchor directive
            # copy the file to a counter-named destination (so distinct
            # directories with the same basename do not collide) and emit the
            # directive pointing at the copy. Paths are built by string assembly,
            # not sed, so a checkout path containing regex or glob metacharacters
            # cannot corrupt the rewrite. The directive keyword is the first
            # field and the path is the remainder, so a path containing spaces is
            # preserved. The "|| [ -n "$line" ]" keeps a final line lacking a
            # trailing newline from being dropped.
            while IFS= read -r line || [ -n "$line" ]; do
                read -r key src <<EOF
$line
EOF
                case "$key" in
                HostKey|HostCertificate|TrustedUserCAKeys)
                    if [ -n "$src" ] && [ -e "$src" ]; then
                        n=`expr $n + 1`
                        dst="$SSHD_KEYDIR/anchor$n.pem"
                        if ! cp "$src" "$dst"; then
                            printf "WARNING: could not copy %s; using original path\n" "$src" >&2
                            printf '%s\n' "$line" >> "$CONFIG"
                            continue
                        fi
                        # Owner-only: satisfies the writable check for every
                        # trust anchor and the no-group/world-readable check for
                        # the secret host key. The daemon runs as root and reads
                        # via the owner bits.
                        chmod 600 "$dst"
                        if ! sudo chown 0 "$dst"; then
                            printf "WARNING: could not chown %s to root; daemon may refuse to load it\n" "$src" >&2
                        fi
                        printf '%s %s\n' "$key" "$dst" >> "$CONFIG"
                    else
                        printf '%s\n' "$line" >> "$CONFIG"
                    fi
                    ;;
                *)
                    printf '%s\n' "$line" >> "$CONFIG"
                    ;;
                esac
            done < "$ORIGCFG"
        fi
    fi

    # find a port
    sudo ../wolfsshd -d -E ./log.txt -f "$CONFIG"

    # set the PID of started sshd
    NEW_PID=`ps -e | grep wolfsshd | grep -oE "[0-9]+"`
    PID=`diff <(echo "$CURRENT_PIDS") <(echo "$NEW_PID") | grep '>' | grep -oE "[0-9]+" | head -n1`
    printf "SSHD running on PID $PID\n"
}

# closes down the sshd session taking argument $1 as the PID of the session
stop_wolfsshd() {
    printf "Stopping SSHD, killing pid $PID\n"
    sudo kill $PID

    # The temp dir is owned by the invoking user, so its root-owned key copies
    # can be removed without sudo.
    if [ -n "$SSHD_KEYDIR" ]; then
        rm -rf "$SSHD_KEYDIR"
        SSHD_KEYDIR=""
    fi
}
