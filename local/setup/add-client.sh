#!/bin/sh
set -u

adminServiceUrl=$1
adminServiceUsername=$2
adminServicePassword=$3
oidcServiceUrl=$4
institution=$5
createInstitutionPayload=$6
clientId=$7
createClientPayload=$8
clientSecret=$9
# curl resolves *.localhost addresses to 127.0.0.1, work around it with curl --resolve option.
adminServiceIp=$(getent hosts $(echo ${adminServiceUrl} | sed -e 's/:.*//') | awk '{ print $1 }')
oidcServiceIp=$(getent hosts $(echo ${oidcServiceUrl} | sed -e 's/:.*//') | awk '{ print $1 }')

banner() {
    text="$*"
    len=$(echo -n "$text" | wc -m)
    line=$(printf '─%.0s' $(seq 1 $len))
    echo "┌─$line─┐"
    echo "│ $text │"
    echo "└─$line─┘"
}

banner "Load home page for XSRF token"
curl --insecure \
  --request GET \
  --cookie-jar cookies.txt \
  --resolve "$adminServiceUrl:${adminServiceIp}" \
  --url "https://$adminServiceUrl/" \
  --header "Content-Type: application/json" \

XSRFTOKEN=$(grep -oP '__Host-XSRF-TOKEN\s*\K([\w-]+)' cookies.txt)

banner "Login to admin service"
#TODO: possible to use --cacert to pass truststore instead of --insecure
curl --insecure \
  --request POST \
  --cookie cookies.txt \
  --cookie-jar cookies.txt \
  --resolve "$adminServiceUrl:${adminServiceIp}" \
  --url "https://$adminServiceUrl/login" \
  --header "Content-Type: application/json" \
  --header "X-XSRF-TOKEN: $XSRFTOKEN" \
  --data "{\"username\":\"$adminServiceUsername\",\"password\":\"$adminServicePassword\"}"
echo

banner "Delete client: $clientId"
deleteClientUrl="https://$adminServiceUrl/institutions/$institution/clients/$clientId"
echo "DELETE $deleteClientUrl"
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --insecure --request DELETE --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 --resolve "$adminServiceUrl:${adminServiceIp}" $deleteClientUrl)

echo "response code = '$http_response'"

if [ "$http_response" = 200 ]; then
        echo "Existing client successfully removed"
else
        echo "Error when removing existing client: $clientId"
        echo "Response: $(cat response.txt)"
fi

banner "Delete institution: $institution"
deleteInstitutionUrl="https://$adminServiceUrl/institutions/$institution"
echo "DELETE $deleteInstitutionUrl"
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --insecure --request DELETE --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 --resolve "$adminServiceUrl:${adminServiceIp}" $deleteInstitutionUrl)

echo "response code = '$http_response'"

if [ "$http_response" = 200 ]; then
        echo "Existing institution successfully removed"
else
        echo "Error when removing existing institution: $institution"
        echo "Response: $(cat response.txt)"
fi

banner "Create institution: $institution from file: $createInstitutionPayload"
createInstitutionUrl="https://$adminServiceUrl/institutions"
echo "POST $createInstitutionUrl"
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --insecure --request POST --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 --resolve "$adminServiceUrl:${adminServiceIp}" $createInstitutionUrl -H 'Content-Type: application/json' --data-binary "@$createInstitutionPayload")

if [ "$http_response" = 200 ]; then
       echo "Institution successfully added"
else
       echo "Error when adding new institution: $institution"
       echo "Response: $(cat response.txt)"
fi

banner "Create client: $clientId from file: $createClientPayload"
createClientUrl="https://$adminServiceUrl/institutions/$institution/clients"
echo "POST $createClientUrl"
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --insecure --request POST --cookie cookies.txt --header "X-XSRF-TOKEN: $XSRFTOKEN" --retry-connrefused --retry-delay 15 --resolve "$adminServiceUrl:${adminServiceIp}" $createClientUrl -H 'Content-Type: application/json' --data-binary "@$createClientPayload")

if [ "$http_response" = 200 ]; then
       echo "Client successfully added"
else
       echo "Unexpected error when adding new client: $clientId"
       echo "Response: $(cat response.txt)"
       exit 1
fi

banner "Set client: $clientId secret"
setClientSecretPayload=$(cat <<EOF
[
  {
    "op": "replace",
    "path": "/client_secret",
    "value": "$clientSecret"
  }
]
EOF
)

setClientSecretUrl="https://$oidcServiceUrl/admin/clients/$clientId"
echo "PATCH $setClientSecretUrl"
http_response=$(curl --silent --output response.txt --write-out "%{http_code}" --insecure --request PATCH --retry-connrefused --retry-delay 15  --resolve "$oidcServiceUrl:${oidcServiceIp}" $setClientSecretUrl -H 'Content-Type: application/json' --data "$setClientSecretPayload")

if [ "$http_response" = 200 ]; then
       echo "Client secret successfully set"
else
       echo "Unexpected error setting client secret"
       echo "Response: $(cat response.txt)"
       exit 1
fi
