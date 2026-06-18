#!/bin/bash

# Regenerate the OpenSSH ("*-cert-v01@openssh.com") user certificates used by
# the wolfSSHd OpenSSH certificate test. Mirrors renewcerts.sh: the signing CA,
# an untrusted CA, and the user key are committed and reused; only the
# certificates are (re)issued, bound to the requested principal (default fred).
#
# The certificate principal must match the login user at test time, so the test
# harness calls this with the current user. Certificates are issued
# non-expiring (-V always:forever) so committed baselines do not go stale.
#
# Usage: ./renew-ossh-certs.sh [user]

set -e

USER_NAME=${1:-fred}

# Path the force-command certificate's command writes to. Overridable so the
# test can point it at a per-run temp dir instead of a fixed, shared location;
# the committed baseline uses a stable default.
OSSH_FORCED_MARKER="${OSSH_FORCED_MARKER:-/tmp/wolfsshd_ossh_forced_marker}"

if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "ssh-keygen not found, cannot renew OpenSSH certificates"
    exit 1
fi

# Committed key material (created on first run, reused afterwards). A CA is
# generated per algorithm so every verification path (Ed25519/RSA/ECDSA) is
# exercised; ossh-bad-ca is an untrusted CA for the negative test.
[ -f ossh-ca ]       || ssh-keygen -q -t ed25519 -f ossh-ca -N "" \
    -C "wolfssh-ossh-test-ca"
[ -f ossh-ca-rsa ]   || ssh-keygen -q -t rsa -b 2048 -f ossh-ca-rsa -N "" \
    -C "wolfssh-ossh-test-ca-rsa"
[ -f ossh-ca-ecdsa ] || ssh-keygen -q -t ecdsa -b 384 -f ossh-ca-ecdsa -N "" \
    -C "wolfssh-ossh-test-ca-ecdsa"
[ -f ossh-bad-ca ]   || ssh-keygen -q -t ed25519 -f ossh-bad-ca -N "" \
    -C "wolfssh-ossh-untrusted-ca"
[ -f ossh-user ]     || ssh-keygen -q -t ed25519 -f ossh-user -N "" \
    -C "wolfssh-ossh-test-user"
[ -f ossh-user-rsa ] || ssh-keygen -q -t rsa -b 2048 -f ossh-user-rsa -N "" \
    -C "wolfssh-ossh-test-user-rsa"
[ -f ossh-user-ecdsa ] || ssh-keygen -q -t ecdsa -b 256 -f ossh-user-ecdsa \
    -N "" -C "wolfssh-ossh-test-user-ecdsa"

# ssh-keygen (signing below) and the OpenSSH client (-i at test time) both
# refuse private keys with group/world-readable permissions. git does not track
# the rw bits, so committed keys can check out as 0644; tighten them.
chmod 600 ossh-ca ossh-ca-rsa ossh-ca-ecdsa ossh-bad-ca \
    ossh-user ossh-user-rsa ossh-user-ecdsa

# gen_cert_u <out-base> <user-pub> <ca-key> <key-id> <principal> [opts...]
# ssh-keygen writes <out-base>-cert.pub from a copy of the user public key.
gen_cert_u() {
    out_base=$1; user_pub=$2; ca=$3; key_id=$4; principal=$5
    shift 5
    cp "$user_pub" "$out_base.pub"
    ssh-keygen -q -s "$ca" -I "$key_id" -n "$principal" -V always:forever \
        "$@" "$out_base.pub"
    rm -f "$out_base.pub"
}

# gen_cert <out-base> <ca-key> <key-id> <principal> [opts...] (Ed25519 user key)
gen_cert() {
    out_base=$1; ca=$2; key_id=$3; principal=$4
    shift 4
    gen_cert_u "$out_base" ossh-user.pub "$ca" "$key_id" "$principal" "$@"
}

gen_cert "$USER_NAME-ossh"                ossh-ca     "ossh-$USER_NAME" \
    "$USER_NAME"
gen_cert "$USER_NAME-ossh-badca"          ossh-bad-ca "ossh-badca" \
    "$USER_NAME"
gen_cert "$USER_NAME-ossh-wrongprincipal" ossh-ca     "ossh-wrongprincipal" \
    "other-$USER_NAME"
# A certificate with no principals (signed without -n). OpenSSH sshd, and now
# wolfSSHd, reject a principal-less user certificate, so this must not log in.
cp ossh-user.pub "$USER_NAME-ossh-noprincipal.pub"
ssh-keygen -q -s ossh-ca -I "ossh-noprincipal" -V always:forever \
    "$USER_NAME-ossh-noprincipal.pub"
rm -f "$USER_NAME-ossh-noprincipal.pub"
# Certificates signed by an RSA and an ECDSA (P-384) CA exercise the RSA and
# ECDSA CA-signature verification paths. The user key stays Ed25519, so the
# ECDSA case also covers selecting the digest from the CA curve, not the user
# key type.
gen_cert "$USER_NAME-ossh-rsaca"          ossh-ca-rsa   "ossh-rsaca" \
    "$USER_NAME"
gen_cert "$USER_NAME-ossh-ecdsaca"        ossh-ca-ecdsa "ossh-ecdsaca" \
    "$USER_NAME"
# Critical options: an unrecognized one must be rejected; force-command and
# source-address are recognized and enforced.
gen_cert "$USER_NAME-ossh-unkcrit"        ossh-ca     "ossh-unkcrit" \
    "$USER_NAME" -O critical:made-up-option=x
gen_cert "$USER_NAME-ossh-forcecmd"       ossh-ca     "ossh-forcecmd" \
    "$USER_NAME" -O force-command="touch $OSSH_FORCED_MARKER"
# force-command "internal-sftp" restricts the session to SFTP: shell/exec/SCP
# are denied, but an SFTP subsystem request is still served.
gen_cert "$USER_NAME-ossh-internalsftp"   ossh-ca     "ossh-internalsftp" \
    "$USER_NAME" -O force-command="internal-sftp"
gen_cert "$USER_NAME-ossh-srcok"          ossh-ca     "ossh-srcok" \
    "$USER_NAME" -O source-address="127.0.0.0/8,::1/128"
gen_cert "$USER_NAME-ossh-srcbad"         ossh-ca     "ossh-srcbad" \
    "$USER_NAME" -O source-address="10.0.0.0/8"
# A fixed validity window entirely in the past is permanently expired (so the
# committed baseline does not go stale), exercising the daemon's validity check
# end-to-end through parse -> reconstruct -> CheckPublicKeyUnix.
gen_cert "$USER_NAME-ossh-expired"        ossh-ca     "ossh-expired" \
    "$USER_NAME" -V 20200101:20200102
# Certificates over RSA and ECDSA user keys, to exercise a client offering
# those user-key types (the client signs with the certified RSA/ECDSA key).
gen_cert_u "$USER_NAME-ossh-rsauser"   ossh-user-rsa.pub   ossh-ca \
    "ossh-rsauser"   "$USER_NAME"
gen_cert_u "$USER_NAME-ossh-ecdsauser" ossh-user-ecdsa.pub ossh-ca \
    "ossh-ecdsauser" "$USER_NAME"

exit 0
