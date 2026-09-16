#!/bin/bash

# Holds the per-daemon temp dir used for the rewritten config, the root-owned
# trust-anchor copies and the daemon's PID file, so stop_wolfsshd can remove it.
# Empty only when the temp dir could not be created.
SSHD_KEYDIR=""

# The PID file named by the rewritten config. It is what makes a start
# identifiable: the daemon writes its own pid there after it has finished
# daemonizing, so the pid does not have to be inferred from what appeared in
# the process table, which cannot tell this run's daemon from a concurrent
# run's.
SSHD_PIDFILE=""

# starts up a sshd session, takes in the sshd_config file as an argument
start_wolfsshd() {
    # Snapshot the PIDs of any daemon already running so the new one can be
    # picked out below. PIDs only: "ps -e" also prints TIME, and scraping
    # every digit run off that line mixes clock digits in with the PID.
    # Sorted so both snapshots order the same way. No daemon running is the
    # normal case and pgrep exits 1 on no match, which would end a caller
    # running under "set -e".
    CURRENT_PIDS=`pgrep -x wolfsshd | sort -n` || true

    ORIGCFG="$1"
    CONFIG="$ORIGCFG"
    # Reset so each invocation is self-contained regardless of call ordering.
    SSHD_KEYDIR=""
    SSHD_PIDFILE=""

    # wolfSSHd loads each trust anchor (host key, host cert, user CA) through the
    # secure gate, which refuses a file not owned by the daemon's user or root
    # and, for the secret host key, a group/world readable one. This shared
    # daemon is launched with sudo (euid 0) while the repository key files are
    # owned by the checkout user, so copy each configured trust anchor into a
    # private dir, make the copies root-owned and mode 0600, and emit a temp
    # config pointing at them. The version-controlled files are left untouched so
    # the suite stays re-runnable.
    #
    # The rewrite runs for every start, not only for a config naming a trust
    # anchor: the temp config also carries the PidFile the pid is read from,
    # and a config with no anchor directives just copies through unchanged.
    SSHD_KEYDIR=$(mktemp -d 2>/dev/null) || SSHD_KEYDIR=$(mktemp -d -t sshdkeys)
    if [ -z "$SSHD_KEYDIR" ] || [ ! -d "$SSHD_KEYDIR" ]; then
        printf "WARNING: could not create temp dir for the daemon config; using original config\n" >&2
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
        # PidFile goes in first, before any line is copied over. It has to land
        # in the global section: several of the suite's configs end in a Match
        # block, and a directive appended after one is parsed as part of that
        # block, where a PidFile is never applied -- the daemon then writes no
        # pid file, the start reports no pid, and stop_wolfsshd leaves it
        # running on the shared port for the rest of the suite to trip over.
        # Absolute, because wolfSSHd chdir()s to "/" while it daemonizes and a
        # relative path would land at the filesystem root. None of the suite's
        # configs set PidFile themselves, so this cannot conflict with one
        # already in the file.
        SSHD_PIDFILE="$SSHD_KEYDIR/wolfsshd.pid"
        printf 'PidFile %s\n' "$SSHD_PIDFILE" > "$CONFIG"

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

    # SSHD_BIN picks the binary; SSHD_ENV passes env (e.g. LD_PRELOAD) that plain
    # sudo would strip. SSHD_ENV is unquoted to split NAME=VALUE, so no spaces.
    SSHD_BIN="${SSHD_BIN:-../wolfsshd}"
    sudo env $SSHD_ENV "$SSHD_BIN" -d -E ./log.txt -f "$CONFIG"

    # The daemon writes its own pid to the PID file once it has finished
    # daemonizing and before it listens, so read it from there. The pid is not
    # inferred from what is new in the process table any more: that could not
    # tell this daemon from one a concurrent run started at the same moment,
    # and the wait for a single new pid then never settled -- both runs
    # reported "Issue starting up wolfSSHd" while both daemons were listening.
    # The daemon can also die after sudo returns, so leave PID empty in that
    # case and let the caller's empty-PID check report it.
    PID=""
    if [ -n "$SSHD_PIDFILE" ]; then
        for i in $(seq 1 50); do
            if [ -s "$SSHD_PIDFILE" ]; then
                PID=`cat "$SSHD_PIDFILE"`
                break
            fi
            sleep 0.1
        done
        # A pid file left by a daemon that has since died is worse than none:
        # stop_wolfsshd would kill whatever has been given that pid since. Ask
        # what the process is, not merely whether it exists: "kill -0" answers
        # the second question only, and the pid may have been recycled.
        if [ -n "$PID" ] && ! pgrep -x wolfsshd | grep -qx -- "$PID"; then
            PID=""
        fi
    else
        # No temp config, so no PID file: fall back to picking the pid that
        # was not in the process table before. wolfSSHd forks twice while
        # daemonizing, so for a moment its two short lived parents are listed
        # as well; wait for the new pids to settle on the single survivor.
        # Recording a parent instead would leave stop_wolfsshd killing a pid
        # that is already gone while the real daemon keeps the port.
        for i in $(seq 1 50); do
            NEW_PIDS=`pgrep -x wolfsshd | sort -n` || true
            NEW=`diff <(echo "$CURRENT_PIDS") <(echo "$NEW_PIDS") \
                | sed -n 's/^> *//p'`
            NEW_COUNT=`printf '%s\n' $NEW | grep -c .` || NEW_COUNT=0
            if [ "$NEW_COUNT" -eq 1 ]; then
                PID="$NEW"
                break
            fi
            sleep 0.1
        done
    fi
    # wolfSSHd writes its PID file in StartSSHD() immediately before
    # tcp_listen(), so the pid appearing does not mean the socket accepts yet.
    # A caller that connects the moment this returns -- several do, with no
    # sleep -- would be refused, and the daemon's log would show no connection
    # at all. Wait for the daemon's own listening line, matched on its pid so
    # that a previous daemon's line in this appended log cannot satisfy it.
    LISTENING=0
    if [ -n "$PID" ]; then
        for i in $(seq 1 100); do
            if sudo grep -qF "[PID $PID]: [SSHD] Listening on port" \
                    ./log.txt 2>/dev/null; then
                LISTENING=1
                break
            fi
            sleep 0.1
        done
    fi

    # Record the daemon in the run's registry, if the runner set one up. Test
    # scripts run as children of run_all_sshd_tests.sh, so a variable cannot
    # carry their pids back; a file can, which is what lets the runner's exit
    # teardown be specific to this run instead of killing every wolfsshd on
    # the machine. Registered before the check below so a daemon that came up
    # but never listened is still reaped by the runner's teardown.
    if [ -n "$PID" ] && [ -n "$WOLFSSHD_TEST_PIDFILE" ]; then
        printf '%s\n' "$PID" >> "$WOLFSSHD_TEST_PIDFILE" 2>/dev/null || true
    fi

    # Ten seconds and no listening line: report it here rather than return a
    # pid the caller will trust. Falling through left the caller's empty-PID
    # check satisfied and the test connecting to a daemon that never bound,
    # so the run failed as a refused connection somewhere later instead of as
    # a daemon that did not come up. Clearing PID puts it through the check
    # every caller already has.
    if [ -n "$PID" ] && [ "$LISTENING" -eq 0 ]; then
        printf "wolfSSHd pid %s never logged a listening port\n" "$PID" >&2
        sudo kill $PID 2>/dev/null || true
        PID=""
    fi

    printf "SSHD running on PID $PID\n"
}

# closes down the sshd session started by start_wolfsshd, using $PID.
# Idempotent and safe to call from an EXIT trap: with no daemon recorded there
# is nothing to kill, and neither an already-exited daemon nor a missing temp
# dir may become the caller's exit status under "set -e".
stop_wolfsshd() {
    if [ -n "$PID" ]; then
        printf "Stopping SSHD, killing pid $PID\n"
        sudo kill $PID || true

        # Wait for the process to actually exit so a subsequent start_wolfsshd on
        # the same port doesn't race the listening socket's release (EADDRINUSE).
        for i in $(seq 1 50); do
            sudo kill -0 $PID 2>/dev/null || break
            sleep 0.1
        done

        # Drop it from the run registry now that it is stopped. Left there, it
        # would still be a candidate for the end-of-run sweep, which can only
        # ask whether some wolfsshd holds that pid today -- and a concurrent
        # run forks one per connection, so a recycled pid would be that run's
        # daemon. A run accumulates about nine of these, all dead but one.
        if [ -n "$WOLFSSHD_TEST_PIDFILE" ] && [ -f "$WOLFSSHD_TEST_PIDFILE" ]; then
            grep -vx -- "$PID" "$WOLFSSHD_TEST_PIDFILE" \
                > "$WOLFSSHD_TEST_PIDFILE.new" 2>/dev/null || true
            mv -f "$WOLFSSHD_TEST_PIDFILE.new" "$WOLFSSHD_TEST_PIDFILE" \
                2>/dev/null || rm -f "$WOLFSSHD_TEST_PIDFILE.new"
        fi

        # Cleared so a second call -- an EXIT trap after an explicit stop -- is
        # a no-op rather than a kill of whatever pid has since been recycled.
        PID=""
    fi

    # The temp dir is owned by the invoking user, so its root-owned key copies
    # can be removed without sudo. Done even when no daemon was recorded, so a
    # daemon that failed to start does not leak it.
    if [ -n "$SSHD_KEYDIR" ]; then
        rm -rf "$SSHD_KEYDIR"
        SSHD_KEYDIR=""
        # Lived in the dir just removed, so it must not look readable to a
        # second start that fails before writing a new one.
        SSHD_PIDFILE=""
    fi
    return 0
}

# End-of-run safety net: kill any daemon this run started that is still alive.
# Only the pids in the registry are considered, so a concurrent run's daemon is
# left alone. Safe to call when no registry was set up or nothing was started.
stop_all_wolfsshd() {
    local alive p
    if [ -z "$WOLFSSHD_TEST_PIDFILE" ] || [ ! -f "$WOLFSSHD_TEST_PIDFILE" ]; then
        return 0
    fi

    # Match the recorded pids against the live wolfsshd pids rather than
    # killing them blind: a pid recorded early in the run may since have
    # exited and been recycled by an unrelated process.
    alive=`pgrep -x wolfsshd` || true
    while read -r p; do
        [ -n "$p" ] || continue
        if printf '%s\n' $alive | grep -qx -- "$p"; then
            printf "Stopping leftover SSHD, killing pid %s\n" "$p"
            sudo kill "$p" 2>/dev/null || true
        fi
    done < "$WOLFSSHD_TEST_PIDFILE"

    : > "$WOLFSSHD_TEST_PIDFILE" 2>/dev/null || true
    return 0
}
