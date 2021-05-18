#!/bin/bash

while true; do
  if oc get csr 2>/dev/null | grep -q Pending; then
    oc get csr -o go-template='{{range .items}}{{if not .status}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' | xargs oc adm certificate approve
  fi
  sleep 10
done
