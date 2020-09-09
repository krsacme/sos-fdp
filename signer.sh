#!/bin/bash
#
# It will approve any CSR that is not approved yet, and delete any CSR that expired more than 60 seconds
# ago.
#
set -o errexit
set -o nounset
set -o pipefail
name="$1"
condition="$2"
username="$3"
# auto approve
if [[ -z "${condition}" && 
("${username}" == "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper" ||
 "${username}" == "system:serviceaccount:openshift-infra:node-bootstrapper" || 
 "${username}" == "system:node:"* || 
 "${username}" == "system:admin" ) ]]; then
  oc adm certificate approve "${name}"
  exit 0
fi