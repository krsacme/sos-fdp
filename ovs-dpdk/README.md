# Work related to the day 2 installation of OVS-DPDK support for Shift-on-Stack

## Introduction

When deploying OpenShift on OpenStack, underlying OVS-DPDK networks can be used to network OCP cluster nodes.  Other networking technologies such as SR-IOV can be used as well.  However, this folder will focus on providing OVS-DPDK support.  

When an OVS-DPDK network is attached to an OCP VM, the default *netdev* driver is installed for the port and port appears as a normal interface.  In order to use DPDK within the VM (i.e. to attach the interface to Pods that utilize DPDK), the interface driver may need to be changed.  For Intel-based NICs, the interface driver must be changed to the **VFIO** driver.  For Mellanox-based NICs, the default netdev driver can be used as is.

The next step is to create a resource config for the SR-IOV CNI plugin.

## Managing the interface driver

### Day 2

### Systemd

### MachineConfig

### Tying it all together

## Making the interface available to Pods

### SR-IOV CNI

### configMap Generation

### Attaching to Pods

