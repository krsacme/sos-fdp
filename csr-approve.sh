#!/bin/bash

set -e

WORKERS=$1
if [ -z ${WORKERS} ]; then
  echo "Provide number of worker nodes"
  exit 1
fi

while true; do
  READY_NODES=$(oc get nodes --selector node-role.kubernetes.io/worker= --selector node-role.kubernetes.io/master!= -o json | jq -r '.items[] | select(.status.conditions[] | select(.type=="Ready" and .status=="True")) | .metadata.name' | wc -l)
  if [[ "${WORKERS}" == "${READY_NODES}" ]]; then
    exit 0
  fi
  if oc get csr 2>/dev/null | grep -q Pending; then
    oc get csr -o go-template='{{range .items}}{{if not .status}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' | xargs oc adm certificate approve
  fi
  sleep 10
done
