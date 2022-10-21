touch index.txt

# renew CA
openssl req -subj '/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=ca@example.com' -key ca-key-ecc.pem -text -out ca-cert-ecc.pem -config renewcerts.cnf -new -nodes -x509 -extensions v3_ca -days 3650 -set_serial 6
openssl x509 -in ca-cert-ecc.pem -outform DER -out ca-cert-ecc.der

# renew fred-cert
openssl req -subj '/C=US/ST=WA/L=Seattle/O=wolfSSL Inc/OU=Development/CN=Fred/emailAddress=fred@example.com' -key fred-key.pem -out fred-cert.csr -config renewcerts.cnf -new -nodes

openssl x509 -req -in fred-cert.csr -days 3650 -extfile renewcerts.cnf -extensions v3_fred -CA ca-cert-ecc.pem -CAkey ca-key-ecc.pem -text -out fred-cert.pem -set_serial 7
openssl x509 -in fred-cert.pem -outform DER -out fred-cert.der

# renew server-cert
openssl req -subj '/C=US/ST=Washington/L=Seattle/O=Eliptic/OU=ECC/CN=www.wolfssl.com/emailAddress=server@example.com' -key server-key.pem -out server-cert.csr -config renewcerts.cnf -new -nodes

openssl x509 -req -in server-cert.csr -days 3650 -extfile renewcerts.cnf -extensions v3_server -CA ca-cert-ecc.pem -CAkey ca-key-ecc.pem -text -out server-cert.pem -set_serial 8
openssl x509 -in server-cert.pem -outform DER -out server-cert.der

rm index.*
