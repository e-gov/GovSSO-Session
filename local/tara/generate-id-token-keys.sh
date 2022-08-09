#!/bin/bash

set -eu

destinationFolder="id-token"
keyFileName="id-token-issuer.localhost"

echo "--------------------------- Generating TARA id-token keys"

# Create folder if does not exist
mkdir -p "$destinationFolder"

# Generate private key
openssl genrsa \
  -out "$destinationFolder/$keyFileName.key" \
  4096

# Generate public key
openssl rsa \
  -in "$destinationFolder/$keyFileName.key" \
  -pubout > "$destinationFolder/$keyFileName.pub"
