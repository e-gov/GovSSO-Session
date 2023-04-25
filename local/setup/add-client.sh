#!/bin/sh

adminServiceUrl=$1
adminServiceUsername=$2
adminServicePassword=$3
institution=$4
createInstitutionPayload=$5
clientId=$6
createClientPayload=$7
# curl resolves *.localhost addresses to 127.0.0.1, work around it with curl --resolve option.
ipaddress=$(getent hosts $(echo ${adminServiceUrl} | sed -e 's/:.*//') | awk '{ print $1 }')

echo
echo "----- [ Load home page for XSRF token ]"
echo
curl --insecure \
  --request GET \
  --cookie-jar cookies.txt \
  --resolve "$adminServiceUrl:${ipaddress}" \
  --url "https://$adminServiceUrl/" \
  --header "Content-Type: application/json" \

XSRFTOKEN=$(grep -oP '__Host-XSRF-TOKEN\s*\K([\w-]+)' cookies.txt)

echo
echo "----- [ Login to admin service ]"
echo
#TODO: possible to use --cacert to pass truststore instead of --insecure
curl --insecure \
  --request POST \
  --cookie cookies.txt \
  --cookie-jar cookies.txt \
  --resolve "$adminServiceUrl:${ipaddress}" \
  --url "https://$adminServiceUrl/login" \
  --header "Content-Type: application/json" \
  --header "X-XSRF-TOKEN: $XSRFTOKEN" \
  --data "{\"username\":\"$adminServiceUsername\",\"password\":\"$adminServicePassword\"}"

echo
echo "----- [ Delete client: $clientId ]"
echo
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --insecure --request DELETE --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 --resolve "$adminServiceUrl:${ipaddress}" https://$adminServiceUrl/institutions/$institution/clients/$clientId)

echo "response code = '$http_response'"

if [ "$http_response" = 200 ]; then
        echo "Existing client successfully removed"
        echo
else
        echo "Error when removing existing client: $clientId"
        echo "Response: $(cat response.txt)"
fi

echo
echo "----- [ Delete institution: $institution ]"
echo
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --insecure --request DELETE --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 --resolve "$adminServiceUrl:${ipaddress}" https://$adminServiceUrl/institutions/$institution)

echo "response code = '$http_response'"

if [ "$http_response" = 200 ]; then
        echo "Existing institution successfully removed"
        echo
else
        echo "Error when removing existing institution: $institution"
        echo "Response: $(cat response.txt)"
fi

echo "----- [ Create institution: $institution from file: $createInstitutionPayload ]"
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --insecure --request POST --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 --resolve "$adminServiceUrl:${ipaddress}" https://$adminServiceUrl/institutions -H 'Content-Type: application/json' --data-binary "@$createInstitutionPayload")

if [ "$http_response" = 200 ]; then
       echo "Institution successfully added"
       echo
else
       echo "Error when adding new institution: $institution"
       echo "Response: $(cat response.txt)"
fi

echo "----- [ Create client: $clientId from file: $createClientPayload ]"
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --insecure --request POST --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 --resolve "$adminServiceUrl:${ipaddress}" https://$adminServiceUrl/institutions/$institution/clients -H 'Content-Type: application/json' --data-binary "@$createClientPayload")

if [ "$http_response" = 200 ]; then
       echo "Client successfully added"
       echo
else
       echo "Unexpected error when adding new client: $clientId"
       echo "Response: $(cat response.txt)"
       exit 1
fi
