#!/bin/sh

adminServiceUrl=$1
adminServiceUsername=$2
adminServicePassword=$3
institution=$4
createInstitutionPayload=$5
clientId=$6
createClientPayload=$7

echo
echo "----- [ Login to admin service ]"
echo
curl --request POST --cookie-jar cookies.txt \
  --url "http://$adminServiceUrl/login" \
  --header 'Content-Type: application/json' \
  --data "{\"username\":\"$adminServiceUsername\",\"password\":\"$adminServicePassword\"}"

XSRFTOKEN=$(grep -oP 'XSRF-TOKEN\s*\K([\w-]+)' cookies.txt)

echo
echo "----- [ Delete institution: $institution ]"
echo
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --request DELETE --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 http://$adminServiceUrl/institutions/$institution)

echo "response code = '$http_response'"

if [ "$http_response" == 200 ]; then
        echo "Existing institution successfully removed"
        echo
else
        echo "Error when removing existing institution: $institution"
        echo "Response: $(cat response.txt)"
fi

echo "----- [ Create institution: $institution from file: $createInstitutionPayload ]"
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --request POST --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 http://$adminServiceUrl/institutions -H 'Content-Type: application/json' --data-binary "@$createInstitutionPayload")

if [ "$http_response" == 200 ]; then
       echo "Institution successfully added"
       echo
else
       echo "Unexpected error when adding new institution: $institution"
       echo "Response: $(cat response.txt)"
       exit 1
fi

echo
echo "----- [ Delete client: $clientId ]"
echo
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --request DELETE --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 http://$adminServiceUrl/institutions/$institution/clients/$clientId)

echo "response code = '$http_response'"

if [ "$http_response" == 200 ]; then
        echo "Existing client successfully removed"
        echo
else
        echo "Error when removing existing client: $clientId"
        echo "Response: $(cat response.txt)"
fi

echo "----- [ Create client: $clientId from file: $createClientPayload ]"
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --request POST --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 http://$adminServiceUrl/institutions/$institution/clients -H 'Content-Type: application/json' --data-binary "@$createClientPayload")

if [ "$http_response" == 200 ]; then
       echo "Client successfully added"
       echo
else
       echo "Unexpected error when adding new client: $clientId"
       echo "Response: $(cat response.txt)"
       exit 1
fi

