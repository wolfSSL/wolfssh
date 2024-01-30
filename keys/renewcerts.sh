touch index.txt

if [ -z "$1" ]; then
    USER_NAME="fred"
else
    USER_NAME=$1
    cp fred-key.der $USER_NAME-key.der
    cp fred-key.pem $USER_NAME-key.pem
    sed -i "s/fred/$USER_NAME/g" renewcerts.cnf
fi

# renew CA
openssl req -subj '/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=ca@example.com' -key ca-key-ecc.pem -text -out ca-cert-ecc.pem -config renewcerts.cnf -new -nodes -x509 -extensions v3_ca -days 3650 -set_serial 6
openssl x509 -in ca-cert-ecc.pem -outform DER -out ca-cert-ecc.der

# renew user cert
openssl req -subj "/C=US/ST=WA/L=Seattle/O=wolfSSL Inc/OU=Development/CN=$USER_NAME/emailAddress=fred@example.com" -key $USER_NAME-key.pem -out $USER_NAME-cert.csr -config renewcerts.cnf -new -nodes

openssl x509 -req -in $USER_NAME-cert.csr -days 3650 -extfile renewcerts.cnf -extensions v3_$USER_NAME -CA ca-cert-ecc.pem -CAkey ca-key-ecc.pem -text -out $USER_NAME-cert.pem -set_serial 7
openssl x509 -in $USER_NAME-cert.pem -outform DER -out $USER_NAME-cert.der

# renew server-cert
openssl req -subj '/C=US/ST=Washington/L=Seattle/O=Eliptic/OU=ECC/CN=www.wolfssl.com/emailAddress=server@example.com' -key server-key.pem -out server-cert.csr -config renewcerts.cnf -new -nodes

openssl x509 -req -in server-cert.csr -days 3650 -extfile renewcerts.cnf -extensions v3_server -CA ca-cert-ecc.pem -CAkey ca-key-ecc.pem -text -out server-cert.pem -set_serial 8
openssl x509 -in server-cert.pem -outform DER -out server-cert.der

rm index.*
