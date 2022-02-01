#!/bin/sh

echo "---------------------------------- Generating CA certificates ----------------------------------"

mkdir -p "ca"
cd "ca" || { echo "Failed to enter directory"; exit 1; }

# Generate CA private key
openssl ecparam \
  -genkey \
  -name prime256v1 \
  -out ca.localhost.key

# Generate CA certificate
MSYS_NO_PATHCONV=1 \
openssl req \
  -x509 \
  -new \
  -sha512 \
  -nodes \
  -key ca.localhost.key \
  -days 365 \
  -subj "/C=EE/L=Tallinn/O=govsso-local/CN=govsso.localhost.ca" \
  -out ca.localhost.crt

cd .. || { echo "Failed to exit directory"; exit 1; }

./generate-certificate.sh 'clienta'
./generate-certificate.sh 'clientb'
./generate-certificate.sh 'gateway'
./generate-certificate.sh 'hydra'
./generate-certificate.sh 'session'
./generate-certificate.sh 'admin'
./generate-certificate.sh 'hydra-db'
./generate-certificate.sh 'admin-db'

# Copying these files, because postgres TLS configuration requires cert and key file setting of permissions
# in Dockerfile thus these files must be reachable from Dockerfile context.
cp ./hydra-db/hydra-db.localhost.crt ../hydra-db
cp ./hydra-db/hydra-db.localhost.key ../hydra-db
cp ./admin-db/admin-db.localhost.crt ../admin-db
cp ./admin-db/admin-db.localhost.key ../admin-db

# Copy keystore for use in unit tests
cp ./session/session.localhost.keystore.p12 ../../src/test/resources

./generate-admin-truststore.sh
./generate-clients-truststore.sh

echo "---------------------------------- Process finished ----------------------------------"
# Prevents script window to be closed after completion
read -rn1
