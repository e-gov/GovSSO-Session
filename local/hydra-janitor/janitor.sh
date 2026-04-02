#!/bin/sh
set -ux

basedir=$(dirname "$0")

psql --file "${basedir}/row_counts.sql"

psql --echo-all --file "${basedir}/delete_rows.sql"

psql --file "${basedir}/row_counts.sql"
