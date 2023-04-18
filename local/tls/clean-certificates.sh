#!/bin/bash

set -eu

# Recursively remove all directories from current path
cd "$(command dirname -- "${0}")" || exit
rm -rf ./*/

# Remove all existing PKCS12 files
rm -f ../../src/main/resources/*.p12

# Remove all existing PKCS12 files
rm -f ../../src/test/resources/*.p12
