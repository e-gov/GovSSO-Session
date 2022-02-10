#!/bin/sh

# Recursively remove all directories from current path
cd "$(command dirname -- "${0}")" || exit
rm -rf ./*/

./generate-ca-certificate.sh 'govsso'

./generate-certificate.sh 'govsso-ca' 'clienta'
./generate-certificate.sh 'govsso-ca' 'clientb'
./generate-certificate.sh 'govsso-ca' 'gateway'
./generate-certificate.sh 'govsso-ca' 'hydra'
./generate-certificate.sh 'govsso-ca' 'session'
./generate-certificate.sh 'govsso-ca' 'admin'
./generate-certificate.sh 'govsso-ca' 'hydra-db'
./generate-certificate.sh 'govsso-ca' 'admin-db'

./generate-ca-certificate.sh 'tara'
./generate-certificate.sh 'tara-ca' 'tara'

mkdir -p "ldap"
# Get SK LDAP CA certificate
curl http://c.sk.ee/ldapca.crt --output ldap/sk-ldap-ca.crt

./generate-truststore.sh 'govsso-ca' 'admin'
./add-ca-certificate-to-truststore.sh 'admin' 'sk-ldap-ca' './ldap/sk-ldap-ca.crt'

./generate-truststore.sh 'govsso-ca' 'clienta'
./generate-truststore.sh 'govsso-ca' 'clientb'

./generate-truststore.sh 'govsso-ca' 'session' 'session.localhost.hydra.truststore.p12'
./generate-truststore.sh 'tara-ca' 'session' 'session.localhost.tara.truststore.p12'

# Copying these files, because postgres TLS configuration requires cert and key file setting of permissions
# in Dockerfile thus these files must be reachable from Dockerfile context.
cp ./hydra-db/hydra-db.localhost.crt ../hydra-db
cp ./hydra-db/hydra-db.localhost.key ../hydra-db
cp ./admin-db/admin-db.localhost.crt ../admin-db
cp ./admin-db/admin-db.localhost.key ../admin-db

# Remove all existing PKCS12 files and copy all session PKCS12 files to main resources
rm -f ../../src/main/resources/*.p12
cp session/*.p12 ../../src/main/resources

# Remove all existing PKCS12 files and copy required PKCS12 files to test resources
rm -f ../../src/test/resources/*.p12
cp './session/session.localhost.keystore.p12' '../../src/test/resources'
cp './session/session.localhost.tara.truststore.p12' '../../src/test/resources'
cp './session/session.localhost.hydra.truststore.p12' '../../src/test/resources'
cp './hydra/hydra.localhost.keystore.p12' '../../src/test/resources'
cp './tara/tara.localhost.keystore.p12' '../../src/test/resources'

echo "--------------------------- Process finished"
# Prevents script window to be closed after completion
read -rn1
