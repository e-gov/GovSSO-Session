#!/bin/sh
set -u

echo 'Check - is admin service API to be ready to accept requests...'
./wait-for.sh $ADMIN_SERVICE_URL --timeout=300 -- echo "the $ADMIN_SERVICE_URL is up" || { echo "the $ADMIN_SERVICE_URL is not available"; exit 1; }

echo 'Adding client A'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS $OIDC_SERVICE_URL '70000001' './institution-a.json' 'client-a' './client-a.json' 'secreta'

echo 'Adding client B'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS $OIDC_SERVICE_URL '70000002' './institution-b.json' 'client-b' './client-b.json' 'secretb'

echo 'Adding client C'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS $OIDC_SERVICE_URL '70000001' './institution-a.json' 'client-c' './client-c.json' 'secretc'

echo 'Adding client D'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS $OIDC_SERVICE_URL '70000002' './institution-b.json' 'client-d' './client-d.json' 'secretd'

echo 'Adding client E'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS $OIDC_SERVICE_URL '70000001' './institution-a.json' 'client-e' './client-e.json' 'secrete'

echo 'Adding client F'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS $OIDC_SERVICE_URL '70000002' './institution-b.json' 'client-f' './client-f.json' 'secretf'

echo 'Adding client Mock ACR Low'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS $OIDC_SERVICE_URL '70000003' './institution-mock.json' 'client-mock-acr-low' './client-mock-acr-low.json' 'secret'

echo 'Adding client Mock ACR Substantial'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS $OIDC_SERVICE_URL '70000003' './institution-mock.json' 'client-mock-acr-substantial' './client-mock-acr-substantial.json' 'secret'

echo 'Adding client Mock ACR High'
./add-client.sh $ADMIN_SERVICE_URL $ADMIN_USER $ADMIN_PASS $OIDC_SERVICE_URL '70000003' './institution-mock.json' 'client-mock-acr-high' './client-mock-acr-high.json' 'secret'
