#!/bin/sh
set -ux

basedir=$(dirname "$0")

psql --file "${basedir}/row_counts.sql"

# Call Hydra built-in clean-up method
hydra janitor \
  --config /etc/govsso-hydra/config.yml \
  --keep-if-younger 24h \
  --requests \
  --tokens \
  --grants

psql --file "${basedir}/row_counts.sql"

# Call GOVSSO custom data clean-up script
psql --echo-all --file "${basedir}/delete_rows.sql"

psql --file "${basedir}/row_counts.sql"
