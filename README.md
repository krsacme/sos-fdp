# sos-fdp

This repository contains files related to a PoC enabling Fast-Datapath with Kubernetes on OpenStack.
There are several parts to the PoC:

  1. Deploy a base k8s cluster with no workers on OpenStack
  1. Deploy workers into the cluster (using UPI)
  1. Deploy the Performance-Add-On operator to enable tuning and hugepage support
  1. Create a MachineConfig Object to configure the vfio driver
  1. Deploy the modified sriov-network-operator

## Deploy the base cluster

  1. ./fdp.sh deploy cluster

## Deploy the workers

  1. ./fdp.sh deploy workers 0
  1. ./fdp.sh csr -- Wait for two approvals
  1. ./fdp.sh deploy workers 1 
  1. ./fdp.sh csr -- Wait for two approvals
  1. etc...

## Deploy SriovNetworkOperator

**Only necessary when building the SiovNetwork Operator locally**

To deploy the PoC sriov-network-operator

- kubectl apply -f deploy/namespace.yaml
- kubectl apply -f deploy/sriov-network-operator.v4.6.0.clusterserviceversion.yaml

To create node policies for the attached interfaces

- kubectl apply -f deploy/nodepolicy-radio-downlink.yaml
- kubectl apply -f deploy/nodepolicy-radio-uplink.yaml
  
The deploy directory contains the following files:

- namespace.yaml -- Create a test namespace for PoC
- nodepolicy-radio-downlink -- Create an SriovNetworkNodePolicy for the radio downlink interface
- nodepolicy-radio-uplink -- Create an SriovNetworkNodePolicy for the radio uplink interface
