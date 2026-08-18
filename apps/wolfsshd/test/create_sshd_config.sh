#!/bin/bash

PWD=`pwd`

cat <<EOF > sshd_config_test
Port 22222
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
Port 22222
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
# the daemon binary reports FPKI support. sshd_x509_upn_fail.sh skips itself
# on such builds for the same reason.
UPN_DOMAIN_GOOD=""
UPN_DOMAIN_BAD=""
if ../wolfsshd "-?" 2>&1 | grep -q "FPKI"; then
    UPN_DOMAIN_GOOD="AuthorizedUPNDomains example"
    UPN_DOMAIN_BAD="AuthorizedUPNDomains other.example"
fi

cat <<EOF > sshd_config_test_x509
Port 22222
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
Port 22222
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

