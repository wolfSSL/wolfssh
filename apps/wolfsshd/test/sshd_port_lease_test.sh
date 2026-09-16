#!/bin/bash

# Self-test for the port-block allocator in port_lease.sh.
#
# The allocator is what keeps two runs of this suite on one machine off each
# other's ports, and its failure mode is a race: nothing goes wrong until two
# runners reach the same code at the same moment, and what goes wrong then is
# a bind collision in some unrelated test much later. Reasoning about it is
# not enough -- an earlier attempt at the stale-lease path looked correct and
# handed one block to eleven runners at once. So each case here forks real
# processes and contends for real leases.
#
# No daemon, no root and no network listener: the pool is a scratch directory
# and the workers only claim and hold. Takes a few seconds.

TESTDIR=`pwd`
cd "$TESTDIR" || exit 1

# Worker modes, re-entered by the racing processes below. A winner holds its
# lease until the parent releases it, as a real run holds one for its whole
# life. Holding matters: a worker that exited the moment it won would leave a
# lease whose owner is dead, which every later worker is then entitled to
# ignore, and the test would pass no matter how broken the allocator was.
#
# Released by the parent rather than after a fixed sleep. A sleep is a guess
# about how far apart forty forked shells reach the claim, and on a loaded
# runner the stragglers arrived after it expired, correctly found a dead owner
# and correctly took the block -- counted as a second winner and reported as a
# failure of the allocator. $4 is the sentinel, $5 the file every worker
# reports to whether it won or lost.
if [ "$1" = "--claim-and-hold" ] || [ "$1" = "--find-and-hold" ]; then
    . ./port_lease.sh
    won=""
    if [ "$1" = "--claim-and-hold" ]; then
        claim_port_block "$2" && won="$2"
    else
        won=`find_port_block` || won=""
    fi
    [ -n "$won" ] && printf '%s\n' "$won" >> "$3"
    printf 'x\n' >> "$5"
    while [ -n "$won" ] && [ -e "$4" ]; do
        sleep 0.2
    done
    exit 0
fi
if [ "$1" = "--claim-once" ]; then
    . ./port_lease.sh
    claim_port_block "$2"
    exit $?
fi

PASS=0
FAIL=0

ok()   { printf "  %-44s PASS\n" "$1"; PASS=$((PASS + 1)); }
bad()  { printf "  %-44s *** FAIL (%s)\n" "$1" "$2"; FAIL=$((FAIL + 1)); }

POOL=`mktemp -d 2>/dev/null` || POOL=`mktemp -d -t portlease`
if [ -z "$POOL" ] || [ ! -d "$POOL" ]; then
    echo "could not create a scratch pool directory"
    exit 1
fi
trap 'rm -rf "$POOL"' EXIT
chmod 1777 "$POOL"
export PORT_LOCK_ROOT="$POOL"

# find_port_block probes each candidate port for real, and this test runs with
# the suite's own daemon up. Left on the live range the probes connected to it,
# making it fork a child and log a line per worker. Contend over a range
# nothing in the tree binds instead -- and below 32768, out of the ephemeral
# range Linux allocates source ports from, where a passing connection of the
# host's own could answer a probe and move the result.
export PORT_BLOCK_FIRST=29000

WON="$POOL/won.txt"
SENTINEL="$POOL/hold"
DONE="$POOL/done.txt"

# A pid that is certainly not running: fork one and reap it. Used to plant a
# lease whose owner is gone, the state a run killed before its teardown leaves.
dead_pid() {
    ( exit 0 ) &
    dp=$!
    wait "$dp" 2>/dev/null
    printf '%s' "$dp"
}

race() { # mode  arg  workers
    : > "$WON"
    : > "$DONE"
    : > "$SENTINEL"
    i=0
    while [ "$i" -lt "$3" ]; do
        ./sshd_port_lease_test.sh "$1" "$2" "$WON" "$SENTINEL" "$DONE" &
        i=$((i + 1))
    done
    # Let the winners go only once every worker has had its turn, so a lease
    # is never released while another is still starting up. Bounded so a
    # worker that died without reporting cannot hang the suite.
    i=0
    while [ "`grep -c . "$DONE" 2>/dev/null`" -lt "$3" ] && [ "$i" -lt 300 ]; do
        sleep 0.2
        i=$((i + 1))
    done
    rm -f "$SENTINEL"
    wait
}

echo "Port lease allocator test:"

# The race the lease scheme exists to lose safely: many runners arrive at one
# block whose recorded owner is gone. Reclaiming it in place let several of
# them each conclude they had taken it. The bound is an upper one on purpose:
# with forty contenders all standing down for each other, nobody taking the
# block is the documented outcome, not a defect. Progress is asserted by the
# parallel trial below, where a loser moves on to the next block.
T=0
while [ "$T" -lt 5 ]; do
    T=$((T + 1))
    rm -rf "$POOL"/*
    mkdir -p "$POOL/22400.`dead_pid`"
    race --claim-and-hold 22400 40
    n=`grep -c . "$WON"`
    if [ "$n" -le 1 ]; then
        ok "contended stale block, trial $T ($n winner)"
    else
        bad "contended stale block, trial $T" "$n runners hold one block"
    fi
done

# Whole allocations in parallel, the way several suites starting at once do
# it. Every runner must come away with a block of its own.
T=0
while [ "$T" -lt 3 ]; do
    T=$((T + 1))
    rm -rf "$POOL"/*
    race --find-and-hold "" 20
    n=`grep -c . "$WON"`
    u=`sort -u "$WON" | grep -c .`
    # Distinct is the safety property, every worker getting one is the
    # progress property, and only the pair means anything: an allocator that
    # refused everyone satisfies "all distinct" on an empty set. 64 free
    # blocks for 20 workers, so anything short of 20 is a defect.
    if [ "$n" -eq 20 ] && [ "$n" -eq "$u" ]; then
        ok "parallel allocation, trial $T ($n blocks, all distinct)"
    else
        bad "parallel allocation, trial $T" "$n of 20 allocated, $u distinct"
    fi
done

# A block whose owner is gone has to come back into circulation, or a run that
# was killed would retire one permanently.
rm -rf "$POOL"/*
STALE=`dead_pid`
mkdir -p "$POOL/22400.$STALE"
( . ./port_lease.sh; claim_port_block 22400 ) && R=0 || R=1
if [ "$R" -eq 0 ] && [ ! -d "$POOL/22400.$STALE" ]; then
    ok "stale lease reclaimed, not retired"
else
    bad "stale lease reclaimed, not retired" "claim rc=$R"
fi

# A live lease is never taken, however many ask for it.
rm -rf "$POOL"/*
: > "$DONE"
: > "$SENTINEL"
./sshd_port_lease_test.sh --claim-and-hold 22400 "$WON" "$SENTINEL" "$DONE" &
HOLDER=$!
i=0
while [ "`grep -c . "$DONE" 2>/dev/null`" -lt 1 ] && [ "$i" -lt 300 ]; do
    sleep 0.2
    i=$((i + 1))
done
( . ./port_lease.sh; claim_port_block 22400 ) && R=0 || R=1
if [ "$R" -eq 1 ]; then
    ok "live lease not stolen"
else
    bad "live lease not stolen" "second claim succeeded"
fi
rm -f "$SENTINEL"
wait "$HOLDER" 2>/dev/null

# A lease held by a live process of another user must read as live. This is
# the case the pool exists for -- CI runs the suite under sudo in one workflow
# and as the invoking user in another -- and the one a same-user test cannot
# reach: only a caller that may not signal the owner sees the difference
# between "gone" and "not mine". pid 1 always runs and never takes a signal
# from a non-root caller, so it stands in for the other run's pid.
#
# Under sudo, which is how the suite runs, the claim has to drop back to the
# invoking user or the check is vacuous -- root can signal anything.
LEASE_AS=""
if [ "`id -u`" -eq 0 ]; then
    [ -n "$SUDO_USER" ] && LEASE_AS="$SUDO_USER"
fi
if [ "`id -u`" -ne 0 ] || [ -n "$LEASE_AS" ]; then
    rm -rf "$POOL"/*
    mkdir -p "$POOL/22400.1"
    if [ -n "$LEASE_AS" ]; then
        sudo -u "$LEASE_AS" env PORT_LOCK_ROOT="$POOL" \
            PORT_BLOCK_FIRST="$PORT_BLOCK_FIRST" \
            ./sshd_port_lease_test.sh --claim-once 22400 && R=0 || R=1
    else
        ./sshd_port_lease_test.sh --claim-once 22400 && R=0 || R=1
    fi
    if [ "$R" -eq 1 ] && [ -d "$POOL/22400.1" ]; then
        ok "live owner this run cannot signal is kept"
    else
        [ -d "$POOL/22400.1" ] && swept=no || swept=yes
        bad "live owner this run cannot signal is kept" \
            "claim rc=$R, lease swept=$swept"
    fi
else
    printf "  %-44s SKIPPED (root, no SUDO_USER)\n" \
        "live owner this run cannot signal is kept"
fi

# A released block is immediately reusable, so a run that gives back a block it
# cannot use does not burn it.
rm -rf "$POOL"/*
( . ./port_lease.sh
  claim_port_block 22400 || exit 1
  release_port_block 22400
  claim_port_block 22400 || exit 1 ) && R=0 || R=1
if [ "$R" -eq 0 ]; then
    ok "released block is reusable"
else
    bad "released block is reusable" "reclaim after release failed"
fi

# --port has to land outside the block the private daemons are assigned from:
# the requested port is the shared daemon's, and the offsets come from the
# block, so a block containing it would put two daemons on one port.
# The scan is aimed at the first block so the skip is the branch under test.
# Left to the pid-derived origin the scan almost never reached the block
# holding the port, and the cases passed without executing the skip at all.
# The assertion is the contract -- the block does not contain the port -- not
# a particular base. With the scan pinned to the block holding the port, the
# skip is the only way past it, so this still fails if the skip goes; naming
# 29008 instead would also fail whenever a busy port moved the scan one block
# further, on a test that aborts the whole suite.
for p in 29000 29003 29007; do
    rm -rf "$POOL"/*
    base=`( . ./port_lease.sh; PORT_BLOCK_START=0 TEST_PORT=$p find_port_block )`
    if [ -z "$base" ]; then
        bad "--port $p skips its block" "no block allocated"
    elif [ "$p" -ge "$base" ] && [ "$p" -lt $((base + 8)) ]; then
        bad "--port $p skips its block" "block $base contains it"
    else
        ok "--port $p skips its block (got $base)"
    fi
done

printf "Port lease allocator test: %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
