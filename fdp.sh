#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
ARTIFACTS_DIR="$PROJECT_DIR/build-artifacts"
BUILD_LOG="$BUILD_DIR/.openshift_install.log"
export OS_CLOUD=openstack

export KUBECONFIG="$BUILD_DIR/auth/kubeconfig"

declare -A manifest_vars

WORKER_SDN_IP_OFFSET="70"
WORKER_SRIOV_IP_OFFSET="10"
INGRESS_FIP="192.168.122.151"

set -x

usage() {
    local out_dir="$1"

    prog=$(basename "$0")
    cat <<-EOM
    Deploy/Destroy/Update an OpenShift on OpenStack cluster
    Usage:
        $prog [-h] [-m manfifest_dir]  deploy|destroy
            deploy [cluster|workers]   -- Deploy cluster or worker nodes.  Run for initial deploy. 
            destroy [cluster|workers]  -- Destroy workers or all nodes in the cluster. (destroy cluster first destroys worker nodes)
    Options
        -m cluster_dir -- Location of working dir for cluster creation.
            Requires: install-config.yaml, bootstrap.yaml, master-0.yaml, [masters/workers...]
            Defaults to $PROJECT_DIR/cluster/
EOM
    exit 0
}

parse_yaml() {
    local file="$1"

    # Parse the yaml file using yq
    # The end result is an associative array, manifest_vars
    # The keys are the fields in the yaml file
    # and the values are the values in the yaml file
    # shellcheck disable=SC2016
    if ! values=$(yq 'paths(scalars) as $p | [ ( [ $p[] | tostring ] | join(".") ) , ( getpath($p) | tojson ) ] | join(" ")' "$file"); then
        printf "Error during parsing..."
        exit 1
    fi
    mapfile -t lines < <(echo "$values" | sed -e 's/^"//' -e 's/"$//' -e 's/\\\\\\"/"/g' -e 's/\\"//g')
    unset manifest_vars
    declare -A manifest_vars
    for line in "${lines[@]}"; do
        # create the associative array
        manifest_vars[${line%% *}]=${line#* }
    done
}
#
# This function generates an IP address given as network CIDR and an offset
# nthhost(192.168.111.0/24,3) => 192.168.111.3
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

wait_for_log() {

    # wait for deploy log file to file to exist
    count=0
    while [ ! -f "$BUILD_LOG" ]; do
        sleep 1
        if [[ ++$count -gt 20 ]]; then
            exit 0
        fi
    done

}

etcd_hack() {

    touch f0

    wait_for_log

    touch f1

    while IFS= read -r line; do
        echo "$line" >>f3
        [[ "$VERBOSE" =~ true ]] && echo "$line"
        touch f4

        if [[ ${line} =~ "for bootstrapping to complete" ]]; then
            echo "$line" >f5
            break
        fi
    done | tail -f "$BUILD_LOG"

    touch f2

    oc patch etcd cluster -p='{"spec": {"unsupportedConfigOverrides": {"useUnsupportedUnsafeNonHANonProductionUnstableEtcd": true}}}' --type=merge
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

    # Queue up tasks to run according to the stage in deployment
    # etcd_hack &

    openshift-install create cluster --log-level debug

    # Wait for hacks to finish
    wait
}

#
# pre -> Precheck command.  If true cmd will not be executed
# cmd -> command to be executed
# post -> command to check if successful
#
run_cmd() {
    local pre="$1"
    local cmd="$2"
    local post="$2"

    # if there is precheck command, run it.
    # if successful, return
    if [ -n "$pre" ] && $pre; then
        return 1
    fi

    if [ -z "$cmd" ]; then
        return 0
    fi

    if ! $cmd; then
        printf "Error: Execution failed: %s!\n" "$cmd"
        return 1
    fi

    if [ -z "$post" ]; then
        return 0
    fi

    if ! $post; then
        printf "Error: Execution failed: %s!\n" "$cmd"
        return 1
    fi

}

prepare_openstack() {
    cluster_name=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".metadata.name")
    cluster_domain=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".baseDomain")

    printf "Add swiftoperator role...\n"
    openstack role add --user admin --project admin swiftoperator

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
    printf "Create internal ocp network subnet...\n"
    openstack subnet show ocp >/dev/null 2>&1 || (
        openstack subnet create ocp --network ocp --subnet-range 10.0.0.0/16 --dhcp || (
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

    printf "Create ocp_master flavor...\n"
    openstack flavor show ocp_master >/dev/null 2>&1 || (
        openstack flavor create --ram 16384 --disk 25 --vcpus 8 ocp_master || (
            printf "Failed to create ocp_master flavor.."
            exit 1
        )
    )

    printf "Create ocp_worker flavor...\n"
    openstack flavor show ocp_worker >/dev/null 2>&1 || (
        openstack flavor create --ram 16384 --disk 25 --vcpus 8 --property hw:cpu_policy=dedicated --property hw:mem_page_size=1GB ocp_worker || (
            printf "Failed to create ocp_worker flavor.."
            exit 1
        )
    )

    lbFloatingIP=$(get_value_by_tag "$PROJECT_DIR/install-config.yaml" ".platform.openstack.apiVIP")

    printf "Create API %s.%s floating ip on %s...\n" "$cluster_name" "$cluster_domain" "$lbFloatingIP"
    (openstack floating ip list | grep -q "$lbFloatingIP" >/dev/null 2>&1) || (
        openstack floating ip create --floating-ip-address "$lbFloatingIP" --description "API $cluster_name.$cluster_domain" public || (
            printf "Failed to create API %s.%s floating ip...\n" "$cluster_name" "$cluster_domain"
            exit 1
        )
    )

    #     )
    # )

}

patch_ocp() {
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

    openstack floating ip set --port "$infraID-ingress-port" "$INGRESS_FIP"
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

    port_name="$infraID.worker-port-$worker_id"

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
    openstack port show "$port_name" -c id -f value  2>/dev/null || (
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

        nova boot --image "$infraID-rhcos" --flavor ocp_worker --user-data "$PROJECT_DIR/build-artifacts/worker.ign" --nic port-id="$SDN_ID",tag=sdn --nic port-id="$SRIOV_ID",tag=radio --config-drive true "worker-$worker_id.$cluster_name.$cluster_domain"
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

        if ! PROJECT_ID=$(openstack project show admin -c id -f value); then
            printf "OCP Admin Project missing!"
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

manage_workers() {
    cmd="$1"

    if [[ ! $cmd =~ ^apply$|^destroy$ ]]; then
        printf "Invalid cmd %s\n" "$cmd"
        return 1
    fi

    [[ "$VERBOSE" =~ true ]] && printf "%s workers...\n" "$cmd"

    (
        cd "$TERRAFORM_DIR/workers" || return 1

        if ! terraform init; then
            printf "terraform init failed!\n"
            return 1
        fi
        if ! terraform "$cmd" --auto-approve; then
            printf "terraform %s failed!\n" "$cmd"
            return 1
        fi
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
        manage_cluster "deploy"
        ;;
    workers)
        if [ ${#args[@]} -lt 2 ]; then
            printf "Error: Missing worker id for deploy cluster!\n"
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
    local command="$1"

    [ -z "$command" ] && command="cluster"

    case $command in
    cluster)
        manage_workers "destroy"
        manage_cluster "destroy"
        ;;
    workers)
        manage_workers "destroy"
        ;;
    *)
        printf "Unknown deploy sub command %s!\n" "$command"
        exit 1
        ;;
    esac
}

VERBOSE="false"
export VERBOSE

while getopts ":hvo:" opt; do
    case ${opt} in
    o)
        out_dir=$OPTARG
        ;;
    v)
        VERBOSE="true"
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
    SUB_COMMAND=$1
    shift
    destroy "$SUB_COMMAND"
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
