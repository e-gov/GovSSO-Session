#!/bin/bash

set -eu

cd tara || exit
./generate-id-token-keys.sh

cd ../tls || exit
./clean-certificates.sh

cd ../tls || exit
./generate-certificates.sh

echo "--------------------------- All resources generated"

# Prevents script window to be closed after completion
echo -e "\nPress any key to exit the script."
read -rn1
