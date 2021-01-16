#!/bin/bash

set -euo pipefail
# Pull the latest version of the image, in order to
# populate the build cache:
podman pull quay.io/aasmith/testpmd:compile-stage || true
podman pull quay.io/aasmith/testpmd:dpdk-stage    || true
podman pull quay.io/aasmith/testpmd:latest        || true

# Build the compile stage:
docker build --target compile-image \
       --cache-from=quay.io/aasmith/testpmd:compile-stage \
       --tag quay.io/aasmith/testpmd:compile-stage .

# Build the dpdk stage, using cached compile stage.
# Download and compile dpdk
docker build --target dpdk-image \
       --cache-from=quay.io/aasmith/testpmd:compile-stage \
       --cache-from=quay.io/aasmith/testpmd:dpdk-stage \
       --tag quay.io/aasmith/testpmd:dpdk-stage .

# Build the runtime image
# 
docker build --target runtime-image \
       --cache-from=quay.io/aasmith/testpmd:dpdk-stage \
       --cache-from=quay.io/aasmith/testpmd:latest \
       --tag quay.io/aasmith/testpmd:latest .