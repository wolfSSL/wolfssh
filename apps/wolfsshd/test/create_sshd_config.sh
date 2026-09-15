#!/bin/bash

PWD=`pwd`

# $1 is the user to renew certificates for, $2 the port the daemon binds. The
# port used to be written into all four configs as a literal, so even a caller
# who set TEST_PORT could not move the daemon. Default it so a direct
# invocation still produces a usable config.
PORT=${2:-22222}

cat <<EOF > sshd_config_test
Port $PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key.pem
AuthorizedKeysFile $PWD/authorized_keys_test

EOF

cat <<EOF > sshd_config_test_mldsa
Port $PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no
HostKey $PWD/../../../keys/server-key-mldsa87es384
AuthorizedKeysFile $PWD/authorized_keys_test

EOF

# wolfSSHd refuses to start when AuthorizedUPNDomains is set on a build that
# cannot enforce it (wolfSSL without FPKI), so only write the directive when
# the build reports FPKI support. sshd_x509_upn_fail.sh skips itself on such
# builds using the same probe.
. ./wolfssh_options.sh
UPN_DOMAIN_GOOD=""
UPN_DOMAIN_BAD=""
if wolfssh_has FPKI; then
    UPN_DOMAIN_GOOD="AuthorizedUPNDomains example"
    UPN_DOMAIN_BAD="AuthorizedUPNDomains other.example"
fi

cat <<EOF > sshd_config_test_x509
Port $PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no

TrustedUserCAKeys $PWD/../../../keys/ca-cert-ecc.pem
HostKey $PWD/../../../keys/server-key.pem
HostCertificate $PWD/../../../keys/server-cert.pem
$UPN_DOMAIN_GOOD

EOF

cat <<EOF > sshd_config_test_x509_upn_bad
Port $PORT
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no

TrustedUserCAKeys $PWD/../../../keys/ca-cert-ecc.pem
HostKey $PWD/../../../keys/server-key.pem
HostCertificate $PWD/../../../keys/server-cert.pem
$UPN_DOMAIN_BAD

EOF

cd ../../../keys/
./renewcerts.sh $1
cd ../apps/wolfsshd/test/

exit 0

