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

TrustedUserCAKeys $PWD/../../../keys/ca-cert-ecc.pem     
HostKey $PWD/../../../keys/server-key.pem                
HostCertificate $PWD/../../../keys/server-cert.pem

EOF

cd ../../../keys/
./renewcerts.sh $1
cd ../apps/wolfsshd/test/

exit 0

