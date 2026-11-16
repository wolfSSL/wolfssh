#!/bin/sh
# Generate the name-constraint test chain: nc-root (permitted DNS
# example.com) -> nc-ca-a (excluded DNS bad.example.com) -> nc-ca-b ->
# leaves. All ECDSA P-256, valid 100 years.
set -e
OUT=${1:-.}
cd "$OUT"
D=36500
for n in root ca-a ca-b leaf-in leaf-out leaf-excl; do
    openssl ecparam -name prime256v1 -genkey -noout -out nc-$n-key.pem
done
cat > nc-root.cnf <<X
[req]
distinguished_name=dn
prompt=no
[dn]
C=US
CN=NC Root
[v3]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
nameConstraints=critical,permitted;DNS:example.com
X
openssl req -new -x509 -key nc-root-key.pem -days $D -sha256 -config nc-root.cnf -extensions v3 -out nc-root.pem
mkca() { # name subject-cn issuer extra
cat > nc-$1.cnf <<X
[req]
distinguished_name=dn
prompt=no
[dn]
C=US
CN=$2
[v3]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
$4
X
openssl req -new -key nc-$1-key.pem -config nc-$1.cnf -out nc-$1.csr
openssl x509 -req -in nc-$1.csr -CA nc-$3.pem -CAkey nc-$3-key.pem -CAcreateserial -days $D -sha256 -extfile nc-$1.cnf -extensions v3 -out nc-$1.pem
}
mkca ca-a "ca-a.example.com" root "nameConstraints=critical,excluded;DNS:bad.example.com"
mkca ca-b "ca-b.example.com" ca-a ""
mkleaf() { # name cn san
cat > nc-$1.cnf <<X
[req]
distinguished_name=dn
prompt=no
[dn]
C=US
CN=$2
[v3]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:$3
X
openssl req -new -key nc-$1-key.pem -config nc-$1.cnf -out nc-$1.csr
openssl x509 -req -in nc-$1.csr -CA nc-ca-b.pem -CAkey nc-ca-b-key.pem -CAcreateserial -days $D -sha256 -extfile nc-$1.cnf -extensions v3 -out nc-$1.pem
}
mkleaf leaf-in "NC Leaf In" host.example.com
mkleaf leaf-out "NC Leaf Out" host.evil.test
mkleaf leaf-excl "NC Leaf Excl" host.bad.example.com
for n in root ca-a ca-b leaf-in leaf-out leaf-excl; do
    openssl x509 -in nc-$n.pem -outform DER -out nc-$n.der
done
# Remove only this script's own intermediates; the DER files are the output.
for n in root ca-a ca-b leaf-in leaf-out leaf-excl; do
    rm -f "nc-$n.csr" "nc-$n.cnf" "nc-$n.srl" "nc-$n.pem" "nc-$n-key.pem"
done
