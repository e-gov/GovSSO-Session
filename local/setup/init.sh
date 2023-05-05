#!/bin/sh
set -u

echo 'Check - is admin service API to be ready to accept requests...'
./wait-for.sh $ADMIN_SERVICE_URL --timeout=300 -- echo "the $ADMIN_SERVICE_URL is up" || { echo "the $ADMIN_SERVICE_URL is not available"; exit 1; }

echo 'Adding client A'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS '70000001' './institution-a.json' 'client-a' './client-a.json'

echo 'Adding client B'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS '70000002' './institution-b.json' 'client-b' './client-b.json'

echo 'Adding client C'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS '70000001' './institution-a.json' 'client-c' './client-c.json'

echo 'Adding client D'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS '70000002' './institution-b.json' 'client-d' './client-d.json'

echo 'Adding client E'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS '70000001' './institution-a.json' 'client-e' './client-e.json'

echo 'Adding client F'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS '70000002' './institution-b.json' 'client-f' './client-f.json'
