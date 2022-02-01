#!/bin/sh

echo "---------------------------------- Generating admin truststore ----------------------------------"

# Get ldap CA certificate
mkdir -p "ldap"
curl http://c.sk.ee/ldapca.crt --output ldap/sk-ldap-ca.crt

# Remove existing truststore
rm admin/admin.localhost.truststore.p12

# Generate truststore and add ldap certificate to it
keytool -noprompt -importcert \
  -alias sk-ldap-ca \
  -file ldap/sk-ldap-ca.crt \
  -storepass changeit \
  -keystore admin/admin.localhost.truststore.p12

# Add CA certificate to truststore
keytool -noprompt -importcert \
  -alias ca.localhost \
  -file ca/ca.localhost.crt \
  -storepass changeit \
  -keystore admin/admin.localhost.truststore.p12

# Add hydra certificate to truststore
keytool -noprompt -importcert \
  -alias hydra.localhost \
  -file hydra/hydra.localhost.crt \
  -storepass changeit \
  -keystore admin/admin.localhost.truststore.p12
