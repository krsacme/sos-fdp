#!/bin/bash

CLOUDS_YAML=~/.config/openstack/clouds.yaml

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATES_DIR="$PROJECT_DIR/templates"
BUILD_DIR="$PROJECT_DIR/build"
ARTIFACTS_DIR="$PROJECT_DIR/build-artifacts"

KUBECONFIG=${KUBECONFIG:-"$BUILD_DIR/auth/kubeconfig"}

# Fill in default of openstack if not set
export OS_CLOUD=${OS_CLOUD:-openstack}

DEPLOY_USER=${DEPLOY_USER:-admin}
DEPLOY_PROJECT=${DEPLOY_PROJECT:-admin}

WORKER_SDN_IP_OFFSET=${WORKER_SDN_IP_OFFSET:-"70"}
WORKER_SRIOV_IP_OFFSET=${WORKER_SRIOV_IP_OFFSET:-"10"}
INGRESS_FIP=${INGRESS_FIP:-"192.168.122.151"}

WORKER_FLAVOR="ocp-worker"

declare -a install_manifests=(
    "${PROJECT_DIR}/deploy/20-mount-config.yaml" 
    "${PROJECT_DIR}/deploy/99-vfio-noiommu.yaml"
    "${PROJECT_DIR}/deploy/prom_ret.yaml")

# declare -a networks=("radio_up 192.0.2.0/24 sriov"
#     "radio_down 192.0.3.0/24 sriov"
#     "uplink1 192.0.10.0/24 dpdk"
#     "uplink2 192.0.11.0/24 dpdk")

usage() {
    local out_dir="$1"

    prog=$(basename "$0")
    cat <<-EOM
    Deploy/Destroy/Update an OpenShift on OpenStack cluster
    Usage:
        $prog [-h] [-d] [-v] [-m manfifest_dir]  deploy|destroy
            deploy cluster   -- Deploy cluster.  Runs the following steps
                                create_deploy, prepare_openstack, manage_cluster "deploy"
            create-deploy    -- create $BUILD_DIR director and populate 
            deploy workers path_to_UPI_project   -- Deploy worker nodes using UPI.  Must provide path to UPI Ansible
            destroy [cluster|workers [index]]  -- Destroy workers or all nodes in the cluster. (destroy cluster first destroys worker nodes)
            prep-osp  -- Create all resources needed to deploy (called by deploy cluster as well)
            patch-ocp -- After a successful deployment, scale to one node
            prep-ocp  -- Get OCP ready for adding worker nodes (also called by deploy workers index)
            label-nodes -- Label worker nodes for sriov
            deploy-operator sriov-operator-repo-dir -- Deploy the sriov operator 
            pull-secret namespace -- Create a pull secret for quay.io
            
    Options
            You really have no other options :)
            -h  -- Print this usage and exit.
            -d  -- set -x
            -v  -- Provide more info
    ENVIRONEMENT VARIABLES
            INGRESS_FIP -- IP Address to use for the Ingress Floating IP (default 192.168.122.151)
            WORKER_SDN_IP_OFFSET -- Numerical offset for worker IPs inside OCP subnet (default 70)
            INGRESS_SRIOV_IP_OFFSET -- Numerical offset for worker IPs inside SRIOV subnet (default 70)
            DEPLOY_USER -- OpenStack user for deployment (default admin)
            DEPLOY_PROJECT -- OpenStack project for deployment (default admin)
            KUBECONFIG

EOM
    exit 0
}

install_manifests() {
    for file in  "${install_manifests[@]}";
    do
        oc apply -f "${file}"
    done
}
# parse_yaml() {
#     local file="$1"

#     # Parse the yaml file using yq
#     # The end result is an associative array, manifest_vars
#     # The keys are the fields in the yaml file
#     # and the values are the values in the yaml file
#     # shellcheck disable=SC2016
#     if ! values=$(yq 'paths(scalars) as $p | [ ( [ $p[] | tostring ] | join(".") ) , ( getpath($p) | tojson ) ] | join(" ")' "$file"); then
#         printf "Error during parsing..."
#         exit 1
#     fi
#     mapfile -t lines < <(echo "$values" | sed -e 's/^"//' -e 's/"$//' -e 's/\\\\\\"/"/g' -e 's/\\"//g')
#     unset manifest_vars
#     declare -A manifest_vars
#     for line in "${lines[@]}"; do
#         # create the associative array
#         manifest_vars[${line%% *}]=${line#* }
#     done
# }
#
# This function generates an IP address given as network CIDR and an offset
# nthhost(192.168.111.0/24,3) => 192.168.111.3
#

#
# Calculate the nth host in a given CIDR
#
nthhost() {
    address="$1"
    nth="$2"

    mapfile -t ips < <(nmap -n -sL "$address" 2>&1 | awk '/Nmap scan report/{print $NF}')
    #ips=($(nmap -n -sL "$address" 2>&1 | awk '/Nmap scan report/{print $NF}'))
    ips_len="${#ips[@]}"

    if [ "$ips_len" -eq 0 ] || [ "$nth" -gt "$ips_len" ]; then
        echo "Invalid address: $address or offset $nth"
        exit 1
    fi

    echo "${ips[$nth]}"
}

etcd_hack() {
    oc patch etcd cluster -p='{"spec": {"unsupportedConfigOverrides": {"useUnsupportedUnsafeNonHANonProductionUnstableEtcd": true}}}' --type=merge
}

create_ingress_fip() {
    printf "Create Ingress Floating IP...\n"

    ingressFIP=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".platform.openstack.ingressFloatingIP")

    cluster_name=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".metadata.name")
    cluster_domain=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".baseDomain")

    printf "Create Ingress %s.%s (%s) floating ip...\n" "$cluster_name" "$cluster_domain" "$ingressFIP"
    openstack floating ip list | grep -q "$ingressFIP" >/dev/null 2>&1 || (
        openstack floating ip create --floating-ip-address "$ingressFIP" --description "Ingress $cluster_name.$cluster_domain" public || (
            printf "Failed to create <Ingress %s.%s> (%s) floating ip...\n" "$cluster_name" "$cluster_domain" "$ingressFIP"
            exit 1
        )
    )

    # infraID=$(get_value_by_tag "$ARTIFACTS_DIR/metadata.json" ".infraID")
    # printf "Attach \"Ingress %s.%s\" floating ip to %s...\n" "$cluster_name" "$cluster_domain" "$infraID-ingress-port"
    # openstack floating ip set --port "$infraID-ingress-port" "$INGRESS_FIP" || exit 1
}

function apply_bootstrap_etcd_hack() {
    # This is needed for now due to etcd changes in 4.4:
    # https://github.com/openshift/cluster-etcd-operator/pull/279
    while ! oc get etcds cluster >/dev/null 2>&1; do
        sleep 3
    done
    echo "API server is up, applying etcd hack"
    oc patch etcd cluster -p='{"spec": {"unsupportedConfigOverrides": {"useUnsupportedUnsafeNonHANonProductionUnstableEtcd": true}}}' --type=merge
}

function apply_auth_hack() {
    # This is needed for now due to recent change in auth:
    # https://github.com/openshift/cluster-authentication-operator/pull/318
    while ! oc get authentications.operator.openshift.io cluster >/dev/null 2>&1; do
        sleep 3
    done
    echo "Auth operator is now available, applying auth hack"
    oc patch authentications.operator.openshift.io cluster -p='{"spec": {"unsupportedConfigOverrides": {"useUnsupportedUnsafeNonHANonProductionUnstableOAuthServer": true}}}' --type=merge
}

gen_chrony_mc() {
    read -r -d '' content <<EOF
server _gateway iburst
server infoblox-trust01.intranet.prod.int.phx2.redhat.com iburst
server clock01.util.phx2.redhat.com iburst
server clock.bos.redhat.com iburst
server clock1.rdu2.redhat.com iburst
server clock02.util.phx2.redhat.com iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF

    gen_machineconfig "master" "0420" "/etc/chrony.conf" "masters-chrony-configuration" "$content" || exit 1
}

deploy_cluster() {
    # Assume $BUILD_DIR has been freshly created and empty
    #
    cd "$BUILD_DIR" || return 1

    printf "Generate manifests...\n" 
    if ! openshift-install --log-level debug create manifests >/dev/null; then
        printf "%s create manifests failed!\n" "openshift-install"
        exit 1
    fi

    printf "Generate chrony config...\n" 
    # Generate MachineConfig for chrony config
    gen_chrony_mc

    # Install extra manifests
    for file in "${install_manifests[@]}"; do
        cp "${file}" ./manifests || exit 1
    done

    printf "Generate ignition files...\n" 
    if ! openshift-install create ignition-configs --log-level debug; then
        printf "Error: failed to create ignition configs!"
        return 1
    fi

    # Save the ignition artifacts
    #
    mkdir -p "$ARTIFACTS_DIR" || return 1
    cp ./*.ign "$ARTIFACTS_DIR" || return 1
    cp metadata.json "$ARTIFACTS_DIR" || return 1

    printf "Skip auth_hack for single master...\n" 
    #apply_auth_hack &
    printf "Skip bootstrap etcd hack for single master...\n" 
    #apply_bootstrap_etcd_hack &

    openshift-install create cluster --log-level debug || exit 1
}

#
# Create resources necessary to deploy OCP
#
prepare_openstack() {
    printf "Add swiftoperator role...\n"
    openstack role add --user "$DEPLOY_USER" --project "$DEPLOY_PROJECT" swiftoperator

    printf "Check for external network..."
    openstack network show public >/dev/null 2>&1 || {
        printf "creating..."
        openstack network create --share --provider-network-type flat --provider-physical-network external --external public ||
            {
                printf "failed!\n"
                exit 1
            }
    }
    printf "\n"

    printf "Check for external network subnet..."
    openstack subnet show public >/dev/null 2>&1 || {
        printf "creating..."
        openstack subnet create --no-dhcp --allocation-pool start=192.168.122.125,end=192.168.122.200 --gateway 192.168.122.1 --subnet-range 192.168.122.0/24 --network public public || {
            printf "failed!\n"
            exit 1
        }
    }
    printf "\n"

    # The following section is comemented out since the install now creates these resources
    #
    printf "Check for internal test network..."
    openstack network show test-net >/dev/null 2>&1 || {
        printf "creating"
         openstack network create test-net || {
             printf "failed!\n"
             exit 1
         }
    }
    printf "\n"

    # machine_cidr=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".networking.machineNetwork.cidr") || {
    #     printf "Could not access .networking.machineNetwork.cidr in %s\n" "$PROJECT_DIR/install-config.yaml"
    #     exit 1
    # }

    printf "Check for internal test network subnet..."
    openstack subnet show test-net >/dev/null 2>&1 || {
        printf "creating...\n"
        openstack subnet create test-net --network test-net --subnet-range "192.168.10.0/24" --dhcp || {
            printf "failed!\n"
            exit 1
        }
    }
    printf "\n"

    # if ! MACHINES_SUBNET=$(openstack subnet show ocp -c id -f value); then
    #     printf "OCP Subnet missing!"
    #     exit 1
    # fi

    # export MACHINES_SUBNET
    # envsubst <"$PROJECT_DIR/install-config.yaml" >"$BUILD_DIR/install-config.yaml"

    printf "Check for external router..."
    openstack router show public >/dev/null 2>&1 || {
        printf "creating"
        openstack router create public || {
            printf "failed!"
            exit 1
        }
    }
    printf "\n"

    (openstack router show public | grep -q -e '.*external_gateway_info.*|.*network_id' >/dev/null 2>&1) || {
        printf "Add external gateway to external router...\n"
        openstack router set --external-gateway public public || {
            printf "External router external-gateway set"
            exit 1
        }
    }

    (openstack router show public | grep -q -e '.*interfaces_info.*|.*port_id' >/dev/null 2>&1) || {
         printf "Add internal test-net network to external router..."
         openstack router add subnet public test-net || {
             printf "failed!...\n"
             exit 1
         }
         printf "\n"
     }

    masterFlavor=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".platform.openstack.computeFlavor") || {
        printf "Could not access .platform.openstack.computeFlavor\n"
        exit 1
    }

    printf "Check for master node ocp flavor %s..." "$masterFlavor"
    openstack flavor show "$masterFlavor" >/dev/null 2>&1 || {
        printf "create..."
        openstack flavor create --ram 16384 --disk 25 --vcpus 4 --property hw:cpu_policy=dedicated --property hw:mem_page_size=1GB "$masterFlavor" || {
            printf "Failed!\n"
            exit 1
        }
    }
    printf "\n"

    printf "Check for ocp worker flavor %s..." "$WORKER_FLAVOR"
    openstack flavor show "$WORKER_FLAVOR" >/dev/null 2>&1 || {
        printf "create..."
        openstack flavor create --ram 16384 --disk 25 --vcpus 8 --property hw:cpu_policy=dedicated --property hw:mem_page_size=1GB "$WORKER_FLAVOR" || {
            printf "failed!..\n"
            exit 1
        }
    }
    printf "\n"

    openstack quota set --cores 80 "$DEPLOY_PROJECT" || exit
    openstack quota set --ram 200000 "$DEPLOY_PROJECT" || exit

    apiFloatingIP=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".platform.openstack.apiFloatingIP") || {
        printf "Could not access .platform.openstack.apiFloatingIP\n"
        exit 1
    }

    cluster_name=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".metadata.name")
    cluster_domain=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".baseDomain")

    printf "Check API %s.%s floating ip on %s..." "$cluster_name" "$cluster_domain" "$apiFloatingIP"
    (openstack floating ip list | grep -q "$apiFloatingIP" >/dev/null 2>&1) || {
        printf "create..."
        openstack floating ip create --floating-ip-address "$apiFloatingIP" --description "Ingress $cluster_name.$cluster_domain" public || {
            printf "failed!\n"
            exit 1
        }
    }
    printf "\n"

    create_ingress_fip
}

patch_ocp() {
    oc patch clusterversion/version --type='merge' -p "$(
        cat <<-EOF
spec:
  overrides:
    - group: apps/v1
      kind: Deployment
      name: etcd-quorum-guard
      namespace: openshift-machine-config-operator
      unmanaged: true
EOF
    )"
    oc patch etcd cluster -p='{"spec": {"unsupportedConfigOverrides": {"useUnsupportedUnsafeNonHANonProductionUnstableEtcd": true}}}' --type=merge

    oc scale --replicas=1 deployment/etcd-quorum-guard -n openshift-machine-config-operator

    oc scale --replicas=1 ingresscontroller/default -n openshift-ingress-operator

    oc scale --replicas=1 deployment.apps/console -n openshift-console
    oc scale --replicas=1 deployment.apps/downloads -n openshift-console

    oc scale --replicas=1 deployment.apps/oauth-openshift -n openshift-authentication

    oc scale --replicas=1 deployment.apps/packageserver -n openshift-operator-lifecycle-manager

    # NOTE: When enabled, the Operator will auto-scale this services back to original quantity
    oc scale --replicas=1 deployment.apps/prometheus-adapter -n openshift-monitoring
    oc scale --replicas=1 deployment.apps/thanos-querier -n openshift-monitoring
    oc scale --replicas=1 statefulset.apps/prometheus-k8s -n openshift-monitoring
    oc scale --replicas=1 statefulset.apps/alertmanager-main -n openshift-monitoring
}

get_value_by_tag() {
    local yaml="$1"
    local tag="$2"

    val=$(yq "$tag" "$yaml") || return 1

    if [[ "$val" =~ null ]]; then
        printf "Error: Unable to extract %s from %s\n" "$tag" "$yaml"
        return 1
    fi

    val="${val%\"}"
    val="${val#\"}"

    echo "$val"
}

get_tag() {
    INFRA_ID=$(get_value_by_tag "$ARTIFACTS_DIR/metadata.json" ".infraID")
    TAG="openshiftClusterID=$INFRA_ID"

    echo "$TAG"
}

create_network() {
    local name="$1"
    local tag="$2"
    local cidr="$3"
    local net_type="$4"

    params=(--provider-physical-network radio --provider-network-type vlan)

    if [[ $net_type =~ dpdk ]]; then
        printf "Check for dpdk network...%s" "$name"
        params=()
    else
        printf "Check for sriov network...%s" "$name"
    fi

    openstack network show "$name" >/dev/null 2>&1 || {
        openstack network create "$name" "${params[@]}" ||
            {
                printf "Error creating sriov network...%s!" "$name"
                exit 1
            }
    }

    if [ -n "$tag" ]; then
        openstack network set --tag "$tag" "$name" || exit 1
    fi

    printf "Check for network %s subnet...\n" "$name"
    openstack subnet show "$name" >/dev/null 2>&1 || {
        openstack subnet create "$name" --network "$name" --subnet-range "$cidr" --no-dhcp ||
            {
                printf "Error creating sriov subnet...%s" "$name"
                exit 1
            }
    }
    if [ -n "$tag" ]; then
       openstack subnet set --tag "$TAG" "$name" || exit 1
    fi
 }

test_sriov() {    
    create_network "sriov-net" "" "192.0.20.0/24" "sriov"
    
    SRIOV_UPLINK_ID1=$(create_ocp_sriov_port "0" "" "infra" "sriov-net" "1")

    openstack server create --image "cirros" --flavor "ocp-worker" --net test-net --nic port-id="$SRIOV_UPLINK_ID1" "test-sriov"
}

prepare_for_ocp_worker() {
    TAG=$(get_tag)

    create_network "radio_uplink" "$TAG" "192.0.2.0/24" "sriov"
    create_network "radio_downlink" "$TAG" "192.0.3.0/24" "sriov"

    create_network "uplink1" "$TAG" "192.0.10.0/24" "dpdk"
    create_network "uplink2" "$TAG" "192.0.11.0/24" "dpdk"
}

create_ocp_sriov_port() {
    local worker_id="$1"
    local tag="$2"
    local infraID="$3"
    local network="$4"
    local instance="$5"

    #
    # Create an SRIOV port for the worker
    #

    port_name="$infraID-worker-$worker_id-$network-$instance"

    openstack port show "$port_name" -c id -f value >/dev/null 2>&1 || (
        openstack port create "$port_name" --vnic-type direct --network "$network" \
            --tag "$tag" --tag "$network" \
            --disable-port-security --binding-profile trusted=true >/dev/null ||
            (
                printf "Error creating %s!\n" "$port_name"
                exit 1
            )
    )
    SRIOV_ID=$(openstack port show "$port_name" -c id -f value) || exit 1

    echo "$SRIOV_ID"
}

create_ocp_worker_net() {
    local worker_id="$1"

    cluster_name=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".metadata.name")
    cluster_domain=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".baseDomain")
    infraID=$(get_value_by_tag "$PROJECT_DIR/build-artifacts/metadata.json" ".infraID")
    TAG=$(get_tag)

    ocp_cidr=$(openstack subnet show "$infraID-nodes" -c cidr -f value) || exit 1
    #
    # Create a SDN port for the worker
    #
    port_name="$infraID-worker-port-$worker_id"

    printf "Create %s SDN port...\n" "$port_name"

    # Calculate an address
    address=$(nthhost "$ocp_cidr" "$((WORKER_SDN_IP_OFFSET + worker_id))")

    ingressVIP=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".platform.openstack.ingressVIP")

    printf "Create %s, with ip=%s...\n" "$port_name" "$address"

    openstack port show "$port_name" 2>/dev/null || (
        openstack port create "$port_name" --network "$infraID-openshift" \
            --security-group "$infraID-worker" --fixed-ip subnet="$infraID-nodes,ip-address=$address" \
            --allowed-address ip-address="$ingressVIP" --binding-profile sdn=true ||
            (
                printf "Error creating %s!" "$port_name"
                exit 1
            )
    )
    openstack port set --tag "$TAG" "$port_name" >/dev/null

    SDN_ID=$(openstack port show "$port_name" -c id -f value) || exit 1

    #
    # Create an SRIOV port for the worker
    #

    # radio_cidr=$(openstack subnet show radio -c cidr -f value) || exit 1
    # address=$(nthhost "$radio_cidr" "$((WORKER_SRIOV_IP_OFFSET + worker_id))")
    # port_name="$infraID.worker-radio-port-$worker_id"

    # printf "Create %s...\n" "$port_name"
    # openstack port show "$port_name" -c id -f value 2>/dev/null || (
    #     openstack port create "$port_name" --vnic-type direct --network radio \
    #      --fixed-ip subnet=radio,ip-address="$address" --tag "$TAG" --tag radio \
    #      --disable-port-security --binding-profile trusted=true --binding-profile vf=true ||
    #         (
    #             printf "Error creating %s!\n" "$port_name"
    #             exit 1
    #         )
    # )
    # SRIOV_ID=$(openstack port show "$port_name" -c id -f value) || exit 1
    printf "Create %s...\n" "sriov uplink port 1"
    SRIOV_UPLINK_ID1=$(create_ocp_sriov_port "$worker_id" "$TAG" "$infraID" "radio_uplink" "1")
    printf "Create %s...\n" "sriov uplink port 2"
    SRIOV_UPLINK_ID2=$(create_ocp_sriov_port "$worker_id" "$TAG" "$infraID" "radio_uplink" "2")

    printf "Create %s...\n" "sriov downlink port 1"
    SRIOV_DOWNLINK_ID1=$(create_ocp_sriov_port "$worker_id" "$TAG" "$infraID" "radio_downlink" "1")
    printf "Create %s...\n" "sriov downlink port 2"
    SRIOV_DOWNLINK_ID2=$(create_ocp_sriov_port "$worker_id" "$TAG" "$infraID" "radio_downlink" "2")
    #
    # Get the DPDK network uuid
    #

    DPDK_ID=$(openstack network show uplink1 -c id -f value) || exit 1
    DPDK2_ID=$(openstack network show uplink2 -c id -f value) || exit 1

    printf "Launch Worker VM...\n"
    openstack server show "worker-$worker_id.$cluster_name.$cluster_domain" 2>/dev/null || (
        OS_USERNAME=$(get_value_by_tag "$CLOUDS_YAML" ".clouds.openstack.auth.username") || exit 1
        export OS_USERNAME
        OS_PROJECT_NAME=$(get_value_by_tag "$CLOUDS_YAML" ".clouds.openstack.auth.project_name") || exit 1
        export OS_PROJECT_NAME
        export OS_AUTH_TYPE="password"
        OS_AUTH_URL=$(get_value_by_tag "$CLOUDS_YAML" ".clouds.openstack.auth.auth_url") || exit 1
        export OS_AUTH_URL
        OS_PASSWORD=$(get_value_by_tag "$CLOUDS_YAML" ".clouds.openstack.auth.password") || exit 1
        export OS_PASSWORD

        if [[ "$NOVA_BOOT" =~ true ]]; then
            nova boot --image "$infraID-rhcos" --flavor "$WORKER_FLAVOR" --user-data "$PROJECT_DIR/build-artifacts/worker.ign" \
                --nic port-id="$SDN_ID",tag=sdn --nic port-id="$SRIOV_UPLINK_ID1",tag=uplink --nic port-id="$SRIOV_UPLINK_ID2",tag=uplink --nic port-id="$SRIOV_DOWNLINK_ID1",tag=downlink --nic port-id="$SRIOV_DOWNLINK_ID2",tag=downlink --nic net-id="$DPDK_ID",tag=dpdk1 --nic net-id="$DPDK2_ID",tag=dpdk2 --config-drive true "worker-$worker_id.$cluster_name.$cluster_domain"
        else
            openstack server create --image "$infraID-rhcos" --flavor "$WORKER_FLAVOR" --user-data "$PROJECT_DIR/build-artifacts/worker.ign" \
                --nic port-id="$SDN_ID" \
                --nic port-id="$SRIOV_UPLINK_ID1" --nic port-id="$SRIOV_UPLINK_ID2" \
                --nic port-id="$SRIOV_DOWNLINK_ID1" --nic port-id="$SRIOV_DOWNLINK_ID2" \
                --nic net-id="$DPDK_ID" --nic net-id="$DPDK2_ID" \
                --config-drive true "worker-$worker_id.$cluster_name.$cluster_domain"
        fi

        # maps to
        # curl http://169.254.169.254/openstack/latest/meta_data.json
        #
        # echo "options vfio enable_unsafe_noiommu_mode=1" > /etc/modprobe.d/vfio-noiommu.conf
        #
        # modprobe vfio-pci
        #
        # echo -n "0000:00:06.0" > /sys/bus/pci/devices/0000\:00\:06.0/driver/unbind
        # echo "vfio-pci" >  /sys/bus/pci/devices/0000\:00\:06.0/driver_override
        #
        # # echo -n "0000:00:06.0" > /sys/bus/pci/drivers/iavf/unbind
        #
        # oc adm drain --ignore-daemonsets worker-0.fdp.nfv
        # oc delete nodes/worker-0.fdp.nfv

        #approve_csr
    )
}

create_deploy() {
    [ -d "$BUILD_DIR" ] && rm -rf "$BUILD_DIR"

    mkdir "$BUILD_DIR"

    if [ ! -e "$CLOUDS_YAML" ]; then
        echo "Error: missing $CLOUDS_YAML!"
        return 1
    fi

    if [ ! -e ./install-config.yaml ]; then
        echo "Error: missing install-config.yaml file!"
        return 1
    fi

    # if [ ! -f "$BUILD_DIR/clouds.yaml" ] || [ ./clouds.yaml -nt "$BUILD_DIR/clouds.yaml" ]; then
    #     if ! PROJECT_ID=$(openstack project show "$DEPLOY_PROJECT" -c id -f value); then
    #         printf "OCP project \"%s\" missing!" "$DEPLOY_PROJECT"
    #         exit 1
    #     fi
    #     export PROJECT_ID

    #     printf "Generate %s...\n" "$BUILD_DIR/clouds.yaml"

    #     if ! yq -y ".clouds.openstack.auth += {\"project_id\" : \"$PROJECT_ID\" }" clouds.yaml >"$BUILD_DIR/clouds.yaml"; then
    #         printf "Error generating %s" "$BUILD_DIR/clouds.yaml"
    #     fi
    # fi

    if [ ! -f "$BUILD_DIR/install-config.yaml" ] || [ ./install-config.yaml -nt "$PROJECT_DIR/install-config.yaml" ]; then
        printf "Copy %s...\n" "$BUILD_DIR/install-config.yaml"
        cp "$PROJECT_DIR/install-config.yaml" "$BUILD_DIR" || exit 1
    fi
}

manage_cluster() {
    cmd="$1"

    case $cmd in
    deploy)
        deploy_cluster
        ;;
    destroy) ;;

    *)
        printf "Invalid cmd %s\n" "$cmd"
        return 1
        ;;
    esac
}

sign_csr() {
    oc get csr -o go-template='{{range .items}}{{if not .status}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' | xargs oc adm certificate approve
}

approve_csr() {
    oc observe csr --maximum-errors=1 --resync-period=0s -a '{.status.conditions[*].type}' -a '{.spec.username}' -- "$PROJECT_DIR/signer.sh"
}

destroy_workers() {
    local cmd="$1"

    cluster_name=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".metadata.name")
    cluster_domain=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".baseDomain")
    infraID=$(get_value_by_tag "$PROJECT_DIR/build-artifacts/metadata.json" ".infraID")

    openstack server list -c ID -c Name -f value | sed -rn "s/^([^ ]+)[[:space:]]+worker-$cmd\.$cluster_name\.$cluster_domain.*/\1/p" |
        while read -r uuid; do
            #oc delete node worker-0.fdp.nfv
            openstack server delete "$uuid"
        done

    # delete sriov ports
    openstack port list -c ID -c Name -f value | sed -rn "s/^([^ ]+)[[:space:]]+$infraID-worker-$cmd.*/\1/p" |
        while read -r uuid; do
            openstack port delete "$uuid"
        done
    # delete sdn ports
    openstack port list -c ID -c Name -f value | sed -rn "s/^([^ ]+)[[:space:]]+$infraID-worker-port-$cmd.*/\1/p" |
        while read -r uuid; do
            openstack port delete "$uuid"
        done

}

destroy_cluster() {
    (
        cd "$PROJECT_DIR/build" || exit 1

        cp "$PROJECT_DIR/build-artifacts/metadata.json" .

        openshift-install destroy cluster --log-level debug
    )
}

deploy() {
    local args=("$@")

    if [ ${#args[@]} -lt 1 ]; then
        printf "Error: Missing command for deploy!\n"
        usage
    fi

    local command="${args[0]}"

    [ -z "$command" ] && command="cluster"

    case $command in
    cluster-only)
        create_deploy
        prepare_for_ocp_worker
        manage_cluster "deploy"
        ;;
    cluster)
        create_deploy
        prepare_openstack
        manage_cluster "deploy"
        ;;
    workers)
        if [ ${#args[@]} -lt 2 ]; then
            printf "Error: Missing Ansible UPI repo for deploy workers!\n"
            usage
        fi
        prepare_for_ocp_worker
        deploy_workers "${args[1]}"
#        create_ocp_worker_net "${args[1]}"
        ;;
    *)
        printf "Unknown deploy sub command %s!\n" "$command"
        exit 1
        ;;
    esac
}

destroy() {
    local args=("$@")

    if [ ${#args[@]} -lt 1 ]; then
        printf "Error: Missing command for deploy!\n"
        usage
    fi

    local command="${args[0]}"

    [ -z "$command" ] && command="cluster"

    case $command in
    cluster)
        destroy_workers "[0-9]+"
        destroy_cluster
        ;;
    workers)
        if [ ${#args[@]} -lt 2 ]; then
            printf "Error: Missing worker [id | all] for destroy workers!\n"
            usage
        fi
        cmd="${args[1]}"
        if [[ $cmd =~ ^all$ ]]; then
            cmd="[0-9]+"
        elif [[ ! $cmd =~ ^[1-9]+[0-9]*|^0$ ]]; then
            printf "Invalid worker id, integer expected %s\n" "$cmd"
            return 1
        fi

        destroy_workers "$cmd"
        ;;
    *)
        printf "Unknown deploy sub command %s!\n" "$command"
        exit 1
        ;;
    esac
}

label_nodes() {
    local l="$1"

    workers=$(oc get nodes -ojson | jq -r '.items[].metadata.labels."kubernetes.io/hostname"' | grep worker)

    for w in $workers; do
        echo oc label node "$w" "$l"
        oc label node "$w" "$l"
    done
}

deploy_workers() {
    repo="$1"

    pushd "$repo" || ( echo "$repo does not exists" && exit )

    cp "$PROJECT_DIR/build-artifacts/metadata.json" . || exit 1
    cp "$PROJECT_DIR/build-artifacts/worker.ign" . || exit 1

    image=$(openstack image list -c Name -f value|grep rhcos)

    ansible-playbook -vvv -i inventory.yaml --extra-vars "os_image_rhcos=${image}" compute-nodes.yaml
}

deploy_operator() {
    repo="$1"

    oc apply -f deploy/namespace.yaml

    oc project openshift-sriov-network-operator

    pushd "$repo" || ( echo "$repo does not exists" && exit )

    for file in manifests/4.7/sriov-network-operator-sriov*
    do
        oc apply -f "$file"
    done

    hack/deploy-setup.sh openshift-sriov-network-operator

    printf "Wait for webhook to start\n"

    for i in {1..10}
    do
        sleep 5
        printf "%d\n" "$i"
        if oc get pods | grep webhook; then
            break;
        fi
    done

    oc patch sriovoperatorconfig default --type=merge \
        -n openshift-sriov-network-operator \
        --patch '{ "spec": { "enableOperatorWebhook": false } }'

    label_nodes feature.node.kubernetes.io/network-sriov.capable="true"

    popd || exit
}

deploy_policy() {
    NET_ID=$(openstack network show radio_downlink -c id -f value)
    export NET_ID
    envsubst <deploy/nodepolicy-radio-downlink.yaml | oc apply -f -
    NET_ID=$(openstack network show radio_uplink -c id -f value)
    envsubst <deploy/nodepolicy-radio-uplink.yaml | oc apply -f -
}

create_pull_secret() {
    nspace="$1"

    oc create secret generic quay-pull-secret --from-file=.dockerconfigjson=/home/kni/.docker/config.json --type=kubernetes.io/dockerconfigjson -n "$nspace"
    oc secrets link default quay-pull-secret --for=pull -n "$nspace"
}

gen_machineconfig() {
    local role="$1"
    local mode="$2"
    local path="$3"
    local metadata_name="$4"
    local content="$5"

    mkdir -p "$BUILD_DIR/openshift-patches"

    content=$(echo "$content" | base64 -w0)

    template="$TEMPLATES_DIR/machineconfig.yaml.tpl"
    if [ ! -f "$template" ]; then
        printf "Template \"%s\" does not exist!\n" "$template"
        exit 1
    fi
    export metadata_name path mode content role

    manifest="$BUILD_DIR/openshift-patches/$metadata_name.yaml"
    envsubst <"${template}" >"${manifest}"

    cp "$BUILD_DIR/openshift-patches/$metadata_name.yaml" ./openshift || exit 1
}

VERBOSE="false"
export VERBOSE
NOVA_BOOT="false"
export NOVA_BOOT

while getopts ":hvo:dn" opt; do
    case ${opt} in
    o)
        out_dir=$OPTARG
        ;;
    v)
        VERBOSE="true"
        ;;
    d)
        set -x
        ;;
    h)
        usage
        exit 0
        ;;
    n)
        NOVA_BOOT="true"
        ;;
    \?)
        echo "Invalid Option: -$OPTARG" 1>&2
        exit 1
        ;;
    esac
done
shift $((OPTIND - 1))

if [ "$#" -gt 0 ]; then
    COMMAND=$1
    shift
else
    usage
fi

case "$COMMAND" in
# Parse options to the install sub command
deploy)
    if [ "$#" -lt 1 ]; then
        usage
    fi
    deploy "$@"
    ;;
destroy)
    if [ "$#" -lt 1 ]; then
        usage
    fi
    destroy "$@"
    ;;
create-deploy)
    create_deploy
    ;;
prep-osp)
    prepare_openstack
    ;;
test-sriov)
    test_sriov
    ;;
patch-ocp)
    patch_ocp
    ;;
prep-ocp)
    prepare_for_ocp_worker
    ;;
csr)
    sign_csr
    ;;
clean)
    rm -rf "$BUILD_DIR"
    ;;
label-nodes)
    label_nodes feature.node.kubernetes.io/network-sriov.capable="true"
    ;;
deploy-operator)
    if [ "$#" -lt 1 ]; then
        usage
    fi
    deploy_operator "$1"
    ;;
deploy-policy)
    deploy_policy
    ;;
pull-secret)
    if [ "$#" -lt 1 ]; then
        usage
    fi
    create_pull_secret "$1"
    ;;
install-manifests)
    install_manifests
    ;;
ingress-fip)
    create_ingress_fip
    ;;
*)
    echo "Unknown command: $COMMAND"
    usage "$out_dir"
    ;;
esac
