#!/bin/bash

# Port-block leases for one run of the wolfSSHd test suite.
#
# Sourced by run_all_sshd_tests.sh, which takes a block for its run, and by
# sshd_port_lease_test.sh, which races several processes through these
# functions to check that a block is never handed to two runs at once. Kept
# apart from the runner so that test can load the allocator without running
# the suite.

: "${PORT_BLOCK_FIRST:=28000}"
: "${PORT_BLOCK_SIZE:=8}"
: "${PORT_BLOCK_COUNT:=64}"

# True when something is already listening. A shell built without /dev/tcp
# fails here exactly as a refused connection does, which degrades to taking
# the pid-derived block unprobed -- still per run, just unverified.
port_in_use() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# Where blocks are claimed. A port is host wide, so its lease has to be too:
# under $TMPDIR this was not, because TMPDIR is per user on macOS
# (/var/folders/...) and sudo's env_reset drops it, so an invoking-user run and
# a sudo run kept private pools and could lease the same block while each
# believed it held it alone. A fixed path in /tmp is the one namespace both
# see. Sticky and world writable like /tmp itself so both can create in it.
# The sticky bit is not what keeps the two apart -- it still lets the pool's
# own owner unlink another user's entry, and the first run to arrive creates
# the pool -- so what keeps a live lease safe is the liveness test below.
# Overridable only so sshd_port_lease_test.sh can race against a scratch pool.
: "${PORT_LOCK_ROOT:=/tmp/wolfssh-sshd-ports}"

port_lease_init() {
    mkdir -p "$PORT_LOCK_ROOT" 2>/dev/null
    chmod 1777 "$PORT_LOCK_ROOT" 2>/dev/null || true
    if [ ! -d "$PORT_LOCK_ROOT" ]; then
        echo "Error: cannot create the port lease directory $PORT_LOCK_ROOT."
        return 1
    fi
    return 0
}

# A lease on a block is a directory named for the block and for the pid that
# holds it. A run creates and removes only its own, so no run can delete a
# lease another still believes it holds. Reclaiming a stale lease in place
# could not manage that: whether it removed the directory or renamed it aside,
# the act was authorized by an earlier read of the owner, so a second runner
# that had read the same dead owner went on to displace the live claim the
# first had just made, and both used the block. A lease whose owner is gone is
# simply ignored instead, which costs a run killed before its teardown nothing
# but a directory entry -- and any run may delete those, since a dead owner's
# lease is one nothing is relying on.
claim_port_block() {
    local base mine d owner
    base=$1
    mine="$PORT_LOCK_ROOT/$base.$$"
    mkdir "$mine" 2>/dev/null || return 1
    # The block is ours only if no other live lease on it exists. Two runners
    # that reach this at once each see the other and both stand down, which
    # costs a block rather than handing one to both; the caller moves on to
    # the next. Neither can see the other as absent: each creates its lease
    # before it looks, so the later look always finds the earlier lease.
    for d in "$PORT_LOCK_ROOT/$base".*; do
        [ -d "$d" ] || continue
        [ "$d" = "$mine" ] && continue
        owner=${d##*.}
        # "ps -p", not "kill -0": kill reports failure both for a pid that is
        # gone and for one the caller may not signal, and those are opposite
        # answers here. A non-root run reading a lease held by a live root run
        # -- which is CI, where sshd-test.yml runs the suite under sudo and
        # code-coverage.yml does not -- took the EPERM for "owner gone", swept
        # the lease and took a block that run was using. ps -p selects by pid
        # whatever owns it.
        if ps -p "$owner" >/dev/null 2>&1; then
            rmdir "$mine" 2>/dev/null
            return 1
        fi
        rmdir "$d" 2>/dev/null
    done
    return 0
}

release_port_block() {
    [ -n "$1" ] && rmdir "$PORT_LOCK_ROOT/$1.$$" 2>/dev/null
    return 0
}

find_port_block() {
    local start i n base busy
    # Pid-derived so two runs rarely probe the same candidate first.
    # PORT_BLOCK_START pins it for the self-test, which has to be able to aim
    # the scan at a chosen block to exercise the --port skip below.
    start=${PORT_BLOCK_START:-$(( $$ % PORT_BLOCK_COUNT ))}
    for (( i = 0; i < PORT_BLOCK_COUNT; i++ )); do
        base=$(( PORT_BLOCK_FIRST \
            + ((start + i) % PORT_BLOCK_COUNT) * PORT_BLOCK_SIZE ))
        # A --port inside the block would be handed to the shared daemon while
        # the private offsets are still assigned from the same block, so the
        # caller's own port could be one of them: --port 22303 against base
        # 22300 put the host key test on the port the shared daemon had. Skip
        # any block the requested port falls in and the two never overlap.
        if [ -n "$TEST_PORT" ] \
                && [ "$TEST_PORT" -ge "$base" ] 2>/dev/null \
                && [ "$TEST_PORT" -lt $(( base + PORT_BLOCK_SIZE )) ]; then
            continue
        fi
        claim_port_block "$base" || continue
        busy=0
        for (( n = 0; n < PORT_BLOCK_SIZE; n++ )); do
            if port_in_use $(( base + n )); then
                busy=1
                break
            fi
        done
        if [ "$busy" -eq 0 ]; then
            printf '%s' "$base"
            return 0
        fi
        # Claimed but unusable: something outside the suite holds a port in
        # it. Give the lease back rather than sit on a block we cannot use.
        release_port_block "$base"
    done
    return 1
}

