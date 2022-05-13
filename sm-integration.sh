#!/bin/bash

# Description: Sample AuthHub configuration Script
# Created by: 
# Last Modification: 

DIRNAME="$(cd "${BASH_SOURCE[0]%/*}"; pwd)"
source ${DIRNAME}/0.gks_env.sh


TENANT_ADMIN_CLIENTID=$(kubectl get secret ${RELEASENAME}-ssp-secret-defaulttenantclient -n ${NAMESPACE} -o jsonpath="{.data.clientId}" | base64 --decode)
TENANT_ADMIN_CLIENTSECRET=$(kubectl get secret ${RELEASENAME}-ssp-secret-defaulttenantclient -n ${NAMESPACE} -o jsonpath="{.data.clientSecret}" | base64 --decode)
SSP_AT=$(curl -s --insecure -u "${TENANT_ADMIN_CLIENTID}:${TENANT_ADMIN_CLIENTSECRET}" --request POST --url "https://${SSP_FQDN}/default/oauth2/v1/token" --header "Content-Type: application/x-www-form-urlencoded" --data-urlencode "grant_type=client_credentials" --data-urlencode "scope=urn:iam:myscopes" | jq -r .access_token )

sed 's/\[SA_FQDN\]/'${SA_FQDN}'/g' allow_origin_template.json > allow_origin.json

curl --insecure -L -X PATCH "https://${SSP_FQDN}/default/admin/v1/Configs" -H 'Content-Type: application/json' -H "Authorization: Bearer ${SSP_AT}" -d '@./allow_origin.json'


#
# Get the IDs for the policy and rule to be updated in the AUTHZ policy
#
POLICY_ID=$(curl -s --insecure --request GET "https://${SSP_FQDN}/default/admin/v1/AuthZPolicies" -H 'Content-Type: application/json'  -H "Authorization: Bearer ${SSP_AT}" | jq -r '.[] | select(.policyName=="TenantAdminPolicy").policyId')

RULE_ID=$(curl -s --insecure --request GET "https://${SSP_FQDN}/default/admin/v1/AuthZPolicies" -H 'Content-Type: application/json'  -H "Authorization: Bearer ${SSP_AT}" | jq -r '.[] | select(.policyName=="TenantAdminPolicy").rules[].id')

sed 's/\[RuleId\]/'${RULE_ID}'/g' AdminAzPolicy_template.json > AdminAzPolicy.json

curl --insecure -L -X PATCH "https://${SSP_FQDN}/default/admin/v1/AuthZPolicies/${POLICY_ID}" -H 'Content-Type: application/json' -H "Authorization: Bearer ${SSP_AT}" -d '@./AdminAzPolicy.json'


