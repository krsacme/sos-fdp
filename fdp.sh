#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

usage() {
    local out_dir="$1"

    prog=$(basename "$0")
    cat <<-EOM
    Deploy/Destroy/Update an OpenShift on OpenStack cluster
    Usage:
        $prog [-h] [-d] [-v] [-m manfifest_dir]  deploy|destroy
            deploy [cluster|workers index]   -- Deploy cluster or worker nodes.  Run for initial deploy. 
            destroy [cluster|workers [index]]  -- Destroy workers or all nodes in the cluster. (destroy cluster first destroys worker nodes)
            prep-osp  -- Create all resources needed to deploy (called by deploy cluster as well)
            patch-ocp -- After a successful deployment, scale to one node
            prep-ocp  -- Get OCP ready for adding worker nodes (also called by deploy workers index)
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

    ingressVIP=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".platform.openstack.ingressVIP")

    cluster_name=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".metadata.name")
    cluster_domain=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".baseDomain")

    printf "Create Ingress %s.%s floating ip...\n" "$cluster_name" "$cluster_domain"
    openstack floating ip list | grep -q "$INGRESS_FIP" >/dev/null 2>&1 || (
        openstack floating ip create --floating-ip-address "$INGRESS_FIP" --description "API $cluster_name.$cluster_domain" public || (
            printf "Failed to create Ingress %s.%s floating ip...\n" "$cluster_name" "$cluster_domain"
            exit 1
        )
    )

    infraID=$(get_value_by_tag "$ARTIFACTS_DIR/metadata.json" ".infraID")

    printf "Attach \"Ingress %s.%s\" floating ip to %s...\n" "$cluster_name" "$cluster_domain" "$infraID-ingress-port"
    openstack floating ip set --port "$infraID-ingress-port" "$INGRESS_FIP" || exit 1
}

deploy_cluster() {
    # Assume $BUILD_DIR has been freshly created and empty
    #
    cd "$BUILD_DIR" || return 1

    if ! openshift-install create ignition-configs --log-level debug; then
        printf "Error: failed to create ignition configs!"
        return 1
    fi

    # Save the ignition artifacts
    #
    cp ./*.ign "$ARTIFACTS_DIR" || return 1
    cp metadata.json "$ARTIFACTS_DIR" || return 1

    openshift-install create cluster --log-level debug || exit 1

    create_ingress_fip
}

#
# Create resources necessary to deploy OCP
#
prepare_openstack() {
    cluster_name=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".metadata.name")
    cluster_domain=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".baseDomain")

    printf "Add swiftoperator role...\n"
    openstack role add --user "$DEPLOY_USER" --project "$DEPLOY_PROJECT" swiftoperator

    printf "Create external network...\n"
    openstack network show public >/dev/null 2>&1 || (
        openstack network create --share --provider-network-type flat --provider-physical-network external --external public || (
            printf "Failed to create external network\n"
            exit 1
        )
    )

    printf "Create external network subnet...\n"
    openstack subnet show public >/dev/null 2>&1 || (
        openstack subnet create --no-dhcp --allocation-pool start=192.168.122.125,end=192.168.122.200 --gateway 192.168.122.1 --subnet-range 192.168.122.0/24 --network public public || (
            printf "Failed to create external network subnet\n"
            exit 1
        )
    )

    printf "Create internal ocp network...\n"
    openstack network show ocp >/dev/null 2>&1 || (
        openstack network create ocp || (
            printf "Failed tp create create internal ocp network\n"
            exit 1
        )
    )

    machine_cidr=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".networking.machineNetwork.cidr")

    printf "Create internal ocp network subnet (%s)...\n" "$machine_cidr"
    openstack subnet show ocp >/dev/null 2>&1 || (
        openstack subnet create ocp --network ocp --subnet-range "$machine_cidr" --dhcp || (
            printf "Failed to create internal ocp network subnet...\n"
            exit 1
        )
    )

    printf "Create external router...\n"
    openstack router show public >/dev/null 2>&1 || (
        openstack router create public || (
            printf "Failed to create external router"
            exit 1
        )
    )

    printf "Add external gateway to external router...\n"
    (openstack router show public | grep -q -e '.*external_gateway_info.*|.*network_id' >/dev/null 2>&1) || (
        openstack router set --external-gateway public public || (
            printf "External router external-gateway set"
            exit 1
        )
    )

    printf "Add internal ocp network to external router...\n"
    (openstack router show public | grep -q -e '.*interfaces_info.*|.*port_id' >/dev/null 2>&1) || (
        openstack router add subnet public ocp || (
            printf "Failed to add internal ocp network to external router...\n"
            exit 1
        )
    )

    printf "Create ocp flavor...\n"
    openstack flavor show ocp >/dev/null 2>&1 || (
        openstack flavor create --ram 24576 --disk 25 --vcpus 16 --property hw:cpu_policy=dedicated --property hw:mem_page_size=1GB ocp || (
            printf "Failed to create ocp flavor.."
            exit 1
        )
    )

    lbFloatingIP=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".platform.openstack.lbFloatingIP")

    printf "Create API %s.%s floating ip on %s...\n" "$cluster_name" "$cluster_domain" "$lbFloatingIP"
    (openstack floating ip list | grep -q "$lbFloatingIP" >/dev/null 2>&1) || (
        openstack floating ip create --floating-ip-address "$lbFloatingIP" --description "API $cluster_name.$cluster_domain" public || (
            printf "Failed to create API %s.%s floating ip...\n" "$cluster_name" "$cluster_domain"
            exit 1
        )
    )
}

patch_ocp() {
    oc patch etcd cluster -p='{"spec": {"unsupportedConfigOverrides": {"useUnsupportedUnsafeNonHANonProductionUnstableEtcd": true}}}' --type=merge

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

    val=$(yq "$tag" "$yaml" | tr -d \") || (
        printf "Error: Unable to extract %s from %s\n" "$tag" "$yaml"
        exit 1
    )
    echo "$val"
}

get_tag() {
    INFRA_ID=$(get_value_by_tag "$ARTIFACTS_DIR/metadata.json" ".infraID")
    TAG="openshiftClusterID=$INFRA_ID"

    echo "$TAG"
}

prepare_for_ocp_worker() {
    printf "Create sriov network...\n"
    openstack network show radio >/dev/null 2>&1 || (
        openstack network create radio --provider-physical-network radio --provider-network-type vlan ||
            (
                printf "Error creating sriov network!"
                exit 1
            )
    )

    printf "Create sriov network subnet...\n"
    openstack subnet show radio >/dev/null 2>&1 || (
        openstack subnet create radio --network radio --subnet-range 192.0.2.0/24 --dhcp ||
            (
                printf "Error creating OCP sriov subnet!"
                exit 1
            )

    )

}

create_ocp_worker_net() {
    local worker_id="$1"

    cluster_name=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".metadata.name")
    cluster_domain=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".baseDomain")
    infraID=$(get_value_by_tag "$PROJECT_DIR/build-artifacts/metadata.json" ".infraID")
    TAG=$(get_tag)

    ocp_cidr=$(openstack subnet show ocp -c cidr -f value) || exit 1
    #
    # Create a SDN port for the worker
    #
    printf "Create %s SDN port...\n" "worker-$worker_id"

    # Calculate an address
    address=$(nthhost "$ocp_cidr" "$((WORKER_SDN_IP_OFFSET + worker_id))")

    port_name="$infraID-worker-port-$worker_id"

    ingressVIP=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".platform.openstack.ingressVIP")

    printf "Create %s, with ip=%s...\n" "$port_name" "$address"

    openstack port show "$port_name" 2>/dev/null || (
        openstack port create "$port_name" --network ocp --security-group "$infraID-worker" --fixed-ip subnet=ocp,ip-address="$address" --allowed-address ip-address="$ingressVIP" ||
            (
                printf "Error creating %s!" "$port_name"
                exit 1
            )
    )
    openstack port set --tag "$TAG" "$port_name"

    SDN_ID=$(openstack port show "$port_name" -c id -f value) || exit 1

    #
    # Create an SRIOV port for the worker
    #

    radio_cidr=$(openstack subnet show radio -c cidr -f value) || exit 1
    address=$(nthhost "$radio_cidr" "$((WORKER_SRIOV_IP_OFFSET + worker_id))")
    port_name="$infraID.worker-radio-port-$worker_id"

    printf "Create %s...\n" "$port_name"
    openstack port show "$port_name" -c id -f value 2>/dev/null || (
        openstack port create "$port_name" --vnic-type direct --network radio --fixed-ip subnet=radio,ip-address="$address" --tag "$TAG" --tag radio --disable-port-security ||
            (
                printf "Error creating %s!\n" "$port_name"
                exit 1
            )
    )
    SRIOV_ID=$(openstack port show "$port_name" -c id -f value) || exit 1

    printf "Launch Worker VM...\n"
    openstack server show "worker-$worker_id.$cluster_name.$cluster_domain" 2>/dev/null || (
        OS_USERNAME=$(get_value_by_tag "$PROJECT_DIR/clouds.yaml" ".clouds.openstack.auth.username")
        export OS_USERNAME
        OS_PROJECT_NAME=$(get_value_by_tag "$PROJECT_DIR/clouds.yaml" ".clouds.openstack.auth.project_name")
        export OS_PROJECT_NAME
        export OS_AUTH_TYPE="password"
        OS_AUTH_URL=$(get_value_by_tag "$PROJECT_DIR/secure.yaml" ".clouds.openstack.auth.auth_url")
        export OS_AUTH_URL
        OS_PASSWORD=$(get_value_by_tag "$PROJECT_DIR/secure.yaml" ".clouds.openstack.auth.password")
        export OS_PASSWORD

        nova boot --image "$infraID-rhcos" --flavor ocp --user-data "$PROJECT_DIR/build-artifacts/worker.ign" --nic port-id="$SDN_ID",tag=sdn --nic port-id="$SRIOV_ID",tag=radio --config-drive true "worker-$worker_id.$cluster_name.$cluster_domain"
    )
}

create_secure() {
    cat <<EOF >"$PROJECT_DIR/secure.yaml"
clouds:
  openstack:
    auth:
      password: <your AMDIN password here>
      auth_url: <your auth_url here>
EOF
}

manage_cluster() {
    cmd="$1"

    case $cmd in
    deploy)
        rm -rf "$BUILD_DIR"
        mkdir -p "$BUILD_DIR"
        if [ ! -e "$PROJECT_DIR/clouds.yaml" ]; then
            echo "Error: missing $PROJECT_DIR/clouds.yaml file!"
            return 1
        fi
        if [ ! -e "$PROJECT_DIR/secure.yaml" ]; then
            echo "Error: missing $PROJECT_DIR/secure.yaml file!"
            return 1
        fi
        if [ ! -e ./install-config.yaml ]; then
            echo "Error: missing install-config.yaml file!"
            return 1
        fi

        if ! PROJECT_ID=$(openstack project show "$DEPLOY_PROJECT" -c id -f value); then
            printf "OCP project \"%s\" missing!" "$DEPLOY_PROJECT"
            exit 1
        fi
        export PROJECT_ID

        if ! yq -y ".clouds.openstack.auth += {\"project_id\" : \"$PROJECT_ID\" }" clouds.yaml >"$BUILD_DIR/clouds.yaml"; then
            printf "Error generating %s" "$BUILD_DIR/clouds.yaml"
        fi

        cp "$PROJECT_DIR/secure.yaml" "$BUILD_DIR"

        if ! MACHINES_SUBNET=$(openstack subnet show ocp -c id -f value); then
            printf "OCP Subnet missing!"
            exit 1
        fi

        export MACHINES_SUBNET
        envsubst <"$PROJECT_DIR/install-config.yaml" >"$BUILD_DIR/install-config.yaml"

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

destroy_workers() {
    local cmd="$1"

    cluster_name=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".metadata.name")
    cluster_domain=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".baseDomain")
    infraID=$(get_value_by_tag "$PROJECT_DIR/build-artifacts/metadata.json" ".infraID")

    openstack server list -c ID -c Name -f value | sed -rn "s/^([^ ]+)[[:space:]]+worker-$cmd\.$cluster_name\.$cluster_domain.*/\1/p" |
        while read -r uuid; do
            openstack server delete "$uuid"
        done

    openstack port list -c ID -c Name -f value | sed -rn "s/^([^ ]+)[[:space:]]+$infraID-worker-port-$cmd.*/\1/p" |
        while read -r uuid; do
            openstack port delete "$uuid"
        done

}

destroy_cluster() {
    (
        cd "$PROJECT_DIR/build" || exit 1
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
    cluster)
        prepare_openstack
        manage_cluster "deploy"
        ;;
    workers)
        if [ ${#args[@]} -lt 2 ]; then
            printf "Error: Missing worker id for deploy workers!\n"
            usage
        fi
        prepare_for_ocp_worker
        create_ocp_worker_net "${args[1]}"
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
        destroy_workers "all"
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

VERBOSE="false"
export VERBOSE

while getopts ":hvo:d" opt; do
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
prep-osp)
    prepare_openstack
    ;;
create-secure)
    create_secure
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
*)
    echo "Unknown command: $COMMAND"
    usage "$out_dir"
    ;;
esac
