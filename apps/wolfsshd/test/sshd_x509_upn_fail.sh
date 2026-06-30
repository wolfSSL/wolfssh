#!/bin/sh

# Negative test for AuthorizedUPNDomains. run_all_sshd_tests.sh starts the
# daemon with sshd_config_test_x509_upn_bad, whose AuthorizedUPNDomains is
# "other.example", while the client certificate carries the UPN realm
# "example". The wolfSSHd UPN domain check must therefore reject the cert.

PWD=`pwd`

# The UPN domain check is compiled only when wolfSSL is built with FPKI. Probe
# the daemon binary's help output, which prints an FPKI marker under the same
# build guard, and skip when the check is not present.
if ! ../wolfsshd "-?" 2>&1 | grep -q "FPKI"; then
    echo "wolfSSHd built without FPKI; UPN domain check not compiled in, skipping"
    exit 77
fi

# Count existing rejection lines first so a stale match left in the appended
# log (start_sshd.sh uses 'wolfsshd -E ./log.txt', which never truncates) is
# not mistaken for this run's rejection.
BEFORE=`sudo grep -c "incorrect user cert sent" ./log.txt 2>/dev/null`
BEFORE=${BEFORE:-0}

cd ../../..

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "expecting host, port and user as arguments"
    echo "$0 127.0.0.1 22222 user"
    exit 1
fi

TEST_CLIENT="./examples/client/client"
PRIVATE_KEY="./keys/$3-key.der"
PUBLIC_KEY="./keys/$3-cert.der"
CA_CERT="./keys/ca-cert-ecc.der"

echo "$TEST_CLIENT -X -c 'pwd' -u $3 -i $PRIVATE_KEY -J $PUBLIC_KEY -A $CA_CERT -h \"$1\" -p \"$2\" (expecting rejection)"
$TEST_CLIENT -X -c 'pwd' -u "$3" -i "$PRIVATE_KEY" -J "$PUBLIC_KEY" -A "$CA_CERT" -h "$1" -p "$2"
RESULT=$?

cd "$PWD"

# Give the daemon child a moment to flush its rejection to the log.
sleep 1

# FPKI is confirmed compiled in, so a disallowed realm must be rejected for the
# UPN reason. The daemon logs "incorrect user cert sent" in that case; log.txt
# is root-owned (daemon ran via sudo), so read it with sudo. Require both a
# non-zero client exit and a NEW rejection line (after > before) so neither a
# stale log line nor an unrelated client failure can produce a false pass.
AFTER=`sudo grep -c "incorrect user cert sent" ./log.txt 2>/dev/null`
AFTER=${AFTER:-0}
if [ "$RESULT" -ne 0 ] && [ "$AFTER" -gt "$BEFORE" ]; then
    echo "authentication correctly rejected for disallowed UPN realm"
    exit 0
fi

if [ "$RESULT" -eq 0 ]; then
    echo "ERROR: authentication succeeded for a UPN realm outside AuthorizedUPNDomains"
    exit 1
fi

echo "ERROR: client failed but daemon did not log a UPN realm rejection"
exit 1
