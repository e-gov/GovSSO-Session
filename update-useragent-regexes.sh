#!/usr/bin/env bash
set -euo pipefail
mkdir -p src/main/resources/useragent && curl -fsSL https://raw.githubusercontent.com/ua-parser/uap-core/master/regexes.yaml -o src/main/resources/useragent/regexes.yaml