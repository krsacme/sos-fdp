#!/bin/bash

export NET_ID=$(openstack network show radio_downlink -c id -f value); envsubst < deploy/nodepolicy-radio-downlink.yaml | oc apply -f -
export NET_ID=$(openstack network show radio_uplink -c id -f value); envsubst < deploy/nodepolicy-radio-uplink.yaml | oc apply -f -
