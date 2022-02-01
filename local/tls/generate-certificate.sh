#!/bin/sh

applicationName=$1
if [ -z "$applicationName" ]
then
  echo "\$applicationName is empty"
  exit 1;
fi

host=$applicationName.localhost # ex. admin.localhost

echo "---------------------------------- Generating certificates for '$host' ----------------------------------"

mkdir -p "$applicationName"
cd "$applicationName" || { echo "Failed to enter directory"; exit 1; }

# Generate ECDSA key
openssl ecparam \
  -name prime256v1 \
  -genkey \
  -out "$host".key

# Generate CSR from key
# MSYS_NO_PATHCOW=1 needed for Git Bash on Windows users - unable to handle "/"-s in -subj parameter.
MSYS_NO_PATHCONV=1 \
openssl req \
  -new \
  -sha512 \
  -nodes \
  -key "$host".key \
  -subj "/CN=$host" \
  -out "$host".csr

# Configure subject alternate names, passed to openssl.cnf and openssl-ext.cnf
export SAN="DNS:$host"

# Generate CA signed certificate
openssl x509 \
  -req \
  -sha512 \
  -in "$host".csr \
  -CA ../ca/ca.localhost.crt \
  -CAkey ../ca/ca.localhost.key \
  -CAcreateserial \
  -days 363 \
  -extfile ../openssl.cnf \
  -out "$host".crt

# Generate PKCS12 file from application cert and key
# TODO: include CA certificate
openssl pkcs12 \
  -export \
  -in "$host".crt \
  -inkey "$host".key \
  -passout pass:changeit \
  -out "$host".keystore.p12

cd .. || { echo "Failed to exit directory"; exit 1; }
