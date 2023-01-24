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

cat <<EOF > sshd_config_test_x509
Port 22222
Protocol 2
LoginGraceTime 600
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePrivilegeSeparation no
UseDNS no

TrustedUserCAKeys $PWD/ca-cert-ecc.pem     
HostKey $PWD/server-key.pem                
HostCertificate $PWD/server-cert.pem

EOF

exit 0

