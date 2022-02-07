#!/bin/bash

application=$1
alias=$2
certPath=$3
if [ -z "$application" ]; then
  echo "\$application is empty"
  exit 1
fi

echo "--------------------------- Adding '$alias' certificate to '$application' truststore"

# Add certificate to application truststore
keytool -noprompt \
  -importcert \
  -alias "$alias" \
  -file "$certPath" \
  -storepass changeit \
  -keystore "$application/$application.localhost.truststore.p12"
