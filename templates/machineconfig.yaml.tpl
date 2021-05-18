---
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  labels:
    machineconfiguration.openshift.io/role: ${role}
  name: ${metadata_name}
spec:
  config:
    ignition:
      version: 2.2.0
    storage: 
      files:
      - contents:
          source: data:text/plain;charset=utf-8;base64,${content}
        filesystem: root
        mode: ${mode}
        path: ${path}
