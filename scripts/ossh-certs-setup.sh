#!/bin/bash

# 
# This script can be used to regenerate the keys and OpenSSH-style certificates
# in the keys/ossh/ directory. This should never be necessary, as the valid
# (i.e. not intentionally expired) certs are made to never expire.
#

script_dir=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
ossh_dir=$script_dir/../keys/ossh

which ssh-keygen
if [ $? != 0 ]; then
    echo "ssh-keygen not found."
    exit 1
fi

which openssl
if [ $? != 0 ]; then
    echo "openssl not found."
    exit 1
fi

# Host/server setup

echo "Creating host CA RSA key pair..."
ssh-keygen -f $ossh_dir/ossh-host-ca \
           -N '' \
           -b 2048 \
           -t rsa \
           -C ossh-host-ca <<< y
if [ $? != 0 ]; then
    echo "Failed to create host CA RSA key pair."
    exit 1
fi

chmod 600 $ossh_dir/ossh-host-ca
if [ $? != 0 ]; then
    echo "Failed to set permissions for host CA RSA private key."
    exit 1
fi

echo "Creating host (server) RSA key pair..."
ssh-keygen -f $ossh_dir/ossh-host-rsa-key \
           -N '' \
           -b 2048 \
           -t rsa \
           -C ossh-host <<< y
if [ $? != 0 ]; then
    echo "Failed to create host RSA key pair."
    exit 1
fi

chmod 600 $ossh_dir/ossh-host-rsa-key
if [ $? != 0 ]; then
    echo "Failed to set permissions for host RSA private key."
fi

echo "Converting host RSA private key to PEM..."
ssh-keygen -p \
           -N '' \
           -m pem \
           -f $ossh_dir/ossh-host-rsa-key
if [ $? != 0 ]; then
    echo "Failed to convert host RSA private key to PEM."
    exit 1
fi

echo "Converting host RSA private key from PEM to DER..."
openssl rsa -in $ossh_dir/ossh-host-rsa-key \
            -outform DER \
            -out $ossh_dir/ossh-host-rsa-key.der
if [ $? != 0 ]; then
    echo "Failed to convert host RSA private key from PEM to DER."
    exit 1
fi

echo "Creating host RSA certificate, signed by host CA..."
ssh-keygen -s $ossh_dir/ossh-host-ca \
           -I localhost \
           -n localhost \
           -V always:forever \
           -h \
           $ossh_dir/ossh-host-rsa-key.pub
if [ $? != 0 ]; then
    echo "Failed to create host RSA certificate."
    exit 1
fi

# User/client setup

echo "Creating user CA RSA key pair..."
ssh-keygen -f $ossh_dir/ossh-user-ca \
           -N '' \
           -b 2048 \
           -t rsa \
           -C ossh-user-ca <<< y
if [ $? != 0 ]; then
    echo "Failed to create user CA RSA key pair."
    exit 1
fi

chmod 600 $ossh_dir/ossh-user-ca
if [ $? != 0 ]; then
    echo "Failed to set permissions for user CA RSA private key."
fi

echo "Creating user (client) RSA key pair..."
ssh-keygen -f $ossh_dir/ossh-user-rsa-key \
           -N '' \
           -b 2048 \
           -t rsa \
           -C ossh-admin <<< y
if [ $? != 0 ]; then
    echo "Failed to create user RSA key pair."
    exit 1
fi

chmod 600 $ossh_dir/ossh-user-rsa-key
if [ $? != 0 ]; then
    echo "Failed to set permissions for user RSA private key."
    exit 1
fi

echo "Creating user RSA certificate, signed by user CA..."
ssh-keygen -s $ossh_dir/ossh-user-ca \
           -I ossh-admin \
           -n ossh-admin \
           -V always:forever \
           $ossh_dir/ossh-user-rsa-key.pub
if [ $? != 0 ]; then
    echo "Failed to create user RSA certificate."
    exit 1
fi

echo "Creating known_hosts file so client trusts host CA..."
echo "@cert-authority localhost $(cat $ossh_dir/ossh-host-ca.pub)" > $ossh_dir/known_hosts
if [ $? != 0 ]; then
    echo "Failed to create known_hosts file."
    exit 1
fi
