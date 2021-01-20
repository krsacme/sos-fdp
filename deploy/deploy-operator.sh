#!/bin/bash

git clone

git checkout release-4.7

oc create -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: �openshift-sriov-network-operator
EOF

oc project openshift-sriov-network-operator

for file in manifests/4.7/sriov-network-operator-sriov*; do
    oc apply -f "$file"
done

hack/deploy-setup.sh openshift-sriov-network-operator

printf "Wait for webhook to start\n"

for i in {1..10}; do
    sleep 5 printf "%d\n" "$i"
    if oc get pods | grep webhook; then
        break
    fi
done

oc patch sriovoperatorconfig default --type=merge \ -n openshift-sriov-network-operator \ --patch '{ "spec": { "enableOperatorWebhook": false } }'

workers=$(oc get nodes -ojson | jq -r '.items[].metadata.labels."kubernetes.io/hostname"' | grep worker)
for w in $workers; do
    oc label node "$w" feature.node.kubernetes.io/network-sriov.capable="true"
done
