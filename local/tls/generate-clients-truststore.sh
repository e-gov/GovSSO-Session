#!/bin/sh

echo "---------------------------------- Generating clients truststore ----------------------------------"

# Remove existing truststore
rm clienta/clienta.localhost.truststore.p12
rm clientb/clientb.localhost.truststore.p12

# Generate clienta truststore and add gateway certificate to it
keytool -noprompt -importcert \
  -alias gateway \
  -file gateway/gateway.localhost.crt \
  -storepass changeit \
  -keystore clienta/clienta.localhost.truststore.p12

# Add CA certificate to truststore
keytool -noprompt -importcert \
  -alias ca.localhost \
  -file ca/ca.localhost.crt \
  -storepass changeit \
  -keystore clienta/clienta.localhost.truststore.p12

# Generate truststore and add gateway certificate to it
keytool -noprompt -importcert \
  -alias gateway \
  -file gateway/gateway.localhost.crt \
  -storepass changeit \
  -keystore clientb/clientb.localhost.truststore.p12

# Add CA certificate to truststore
keytool -noprompt -importcert \
  -alias ca.localhost \
  -file ca/ca.localhost.crt \
  -storepass changeit \
  -keystore clientb/clientb.localhost.truststore.p12
