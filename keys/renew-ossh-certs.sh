#!/bin/bash

# Regenerate the OpenSSH ("*-cert-v01@openssh.com") user certificates used by
# the wolfSSHd certificate test. The keypairs are committed and reused; the
# certificates are not, since the principal must match the login user.
#
# Usage: ./renew-ossh-certs.sh [user]

set -e

USER_NAME=${1:-fred}

# Where the force-command certificate writes. The test overrides this with a
# per-run temp dir; the fallback is per-process so it is not a shared path.
OSSH_FORCED_MARKER="${OSSH_FORCED_MARKER:-${TMPDIR:-/tmp}/wolfsshd_ossh_forced_marker.$$}"

if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "ssh-keygen not found, cannot renew OpenSSH certificates"
    exit 1
fi

# Committed key material, created on first run. One CA per algorithm covers the
# Ed25519/RSA/ECDSA verification paths; ossh-bad-ca is the untrusted CA.
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

# git does not track the rw bits, so committed keys can check out 0644, which
# both ssh-keygen and the OpenSSH client refuse for a private key.
chmod 600 ossh-ca ossh-ca-rsa ossh-ca-ecdsa ossh-bad-ca \
    ossh-user ossh-user-rsa ossh-user-ecdsa

# gen_cert_u <out-base> <user-pub> <ca-key> <key-id> <principal> [opts...]
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
# No principals (signed without -n): must not log in, like OpenSSH sshd.
cp ossh-user.pub "$USER_NAME-ossh-noprincipal.pub"
ssh-keygen -q -s ossh-ca -I "ossh-noprincipal" -V always:forever \
    "$USER_NAME-ossh-noprincipal.pub"
rm -f "$USER_NAME-ossh-noprincipal.pub"
# RSA and ECDSA (P-384) CAs cover those CA-signature paths. The user key stays
# Ed25519, so the ECDSA case also covers taking the digest from the CA curve.
gen_cert "$USER_NAME-ossh-rsaca"          ossh-ca-rsa   "ossh-rsaca" \
    "$USER_NAME"
gen_cert "$USER_NAME-ossh-ecdsaca"        ossh-ca-ecdsa "ossh-ecdsaca" \
    "$USER_NAME"
# An unrecognized critical option must be rejected; force-command and
# source-address are enforced.
gen_cert "$USER_NAME-ossh-unkcrit"        ossh-ca     "ossh-unkcrit" \
    "$USER_NAME" -O critical:made-up-option=x
gen_cert "$USER_NAME-ossh-forcecmd"       ossh-ca     "ossh-forcecmd" \
    "$USER_NAME" -O force-command="touch $OSSH_FORCED_MARKER"
# "internal-sftp" restricts the session to SFTP: shell/exec/SCP are denied,
# the SFTP subsystem is still served.
gen_cert "$USER_NAME-ossh-internalsftp"   ossh-ca     "ossh-internalsftp" \
    "$USER_NAME" -O force-command="internal-sftp"
gen_cert "$USER_NAME-ossh-srcok"          ossh-ca     "ossh-srcok" \
    "$USER_NAME" -O source-address="127.0.0.0/8,::1/128"
gen_cert "$USER_NAME-ossh-srcbad"         ossh-ca     "ossh-srcbad" \
    "$USER_NAME" -O source-address="10.0.0.0/8"
# A validity window entirely in the past is always expired.
gen_cert "$USER_NAME-ossh-expired"        ossh-ca     "ossh-expired" \
    "$USER_NAME" -V 20200101:20200102
# RSA and ECDSA user keys: the client signs with the certified key of that type.
gen_cert_u "$USER_NAME-ossh-rsauser"   ossh-user-rsa.pub   ossh-ca \
    "ossh-rsauser"   "$USER_NAME"
gen_cert_u "$USER_NAME-ossh-ecdsauser" ossh-user-ecdsa.pub ossh-ca \
    "ossh-ecdsauser" "$USER_NAME"

exit 0
