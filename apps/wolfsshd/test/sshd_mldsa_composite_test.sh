#!/bin/sh

# ML-DSA composite host key test.
#
# The daemon under test is started with sshd_config_test_mldsa, whose only host
# key is keys/server-key-mldsa87es384, an OpenSSH-format ML-DSA-87 + ECDSA-P384
# composite key. Pinning the client's host key algorithm list is what makes this
# an actual assertion about the negotiated algorithm: only the composite name
# may succeed, and any other name must fail to find a common host key algorithm.
#
# ML-DSA support comes from wolfSSL (HAVE_DILITHIUM) and has no wolfSSH
# configure option, so probe the client's algorithm list and skip (77) when the
# composite is not built in.

PWD0=`pwd`
cd ../../..

TEST_CLIENT="./examples/client/client"
USER=`whoami`
PRIVATE_KEY="./keys/hansel-key-ecc.der"
PUBLIC_KEY="./keys/hansel-key-ecc.pub"
ALGO="ssh-mldsa87-es384@wolfssl.com"
OTHER_ALGO="ecdsa-sha2-nistp256"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "expecting host and port as arguments"
    echo "./sshd_mldsa_composite_test.sh 127.0.0.1 22222"
    exit 1
fi

skip() { echo "$1"; cd $PWD0; exit 77; }

[ -x "$TEST_CLIENT" ] || skip "wolfSSH example client not built, skipping"

# -E lists the compiled-in algorithms before connecting, so point it at a closed
# port to keep the probe from opening a session.
ALGOS=`$TEST_CLIENT -E -u $USER -h 127.0.0.1 -p 1 2>/dev/null`
echo "$ALGOS" | grep -q "$ALGO" || skip "no $ALGO support in this build, skipping"

# Positive: with only the composite offered, a successful login means it is what
# was negotiated.
set -e
echo "$TEST_CLIENT -k $ALGO -c 'ls' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\""
$TEST_CLIENT -k "$ALGO" -c 'ls' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h "$1" -p "$2"
set +e

# Negative control: offering only ECDSA must fail, proving the pass above was
# not some other host key the daemon happened to have loaded.
if echo "$ALGOS" | grep -q "$OTHER_ALGO"; then
    echo "$TEST_CLIENT -k $OTHER_ALGO -c 'ls' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY -h \"$1\" -p \"$2\""
    $TEST_CLIENT -k "$OTHER_ALGO" -c 'ls' -u $USER -i $PRIVATE_KEY -j $PUBLIC_KEY \
        -h "$1" -p "$2"
    if [ $? -eq 0 ]; then
        echo "expected $OTHER_ALGO to fail against the composite host key"
        cd $PWD0
        exit 1
    fi
fi

cd $PWD0
exit 0
