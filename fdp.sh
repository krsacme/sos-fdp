#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
ARTIFACTS_DIR="$PROJECT_DIR/build-artifacts"
BUILD_LOG="$BUILD_DIR/.openshift_install.log"
export OS_CLOUD=openstack

export KUBECONFIG="$BUILD_DIR/auth/kubeconfig"

declare -a network_cmds=(
    "openstack network create --share --provider-network-type flat --provider-physical-network external --external public"
    "openstack subnet create --no-dhcp --allocation-pool start=192.168.122.125,end=192.168.122.200\\
      --gateway 192.168.122.1 --subnet-range 192.168.122.0/24 --network public public_subnet"
    "openstack router create public"
    "router set --external-gateway public public"
    "subnet create ocp --network ocp --subnet-range 10.0.0.0/16 --dhcp"
    "router add subnet public ocp"
    "openstack floating ip create --floating-ip-address 192.168.122.150 --description "API fdp.nfv" public"
    "openstack floating ip create --floating-ip-address 192.168.122.151 --description "Ingress fdp.nfv" public"
)

usage() {
    local out_dir="$1"

    prog=$(basename "$0")
    cat <<-EOM
    Deploy/Destroy/Update an OpenShift on OpenStack cluster
    Usage:
        $prog [-h] [-m manfifest_dir]  deploy|destroy
            deploy [cluster|workers]   -- Deploy cluster or worker nodes.  Run for initial deploy or after worker hosts have been changed
                         in install-config.yaml.  Master nodes cannot be changed (added or removed) after an
                         initial deploy.  
            destroy [cluster|workers]  -- Destroy workers or all nodes in the cluster. (destroy cluster first destroys worker nodes)
            update                     -- Invoke this operation afer adding/removing to/from the additionalNetworkIDs field
                                          in the compute.platform.openstack.additionalNetworkIDs list.  This operation will redeploy
    Options
        -m cluster_dir -- Location of working dir for cluster creation.
            Requires: install-config.yaml, bootstrap.yaml, master-0.yaml, [masters/workers...]
            Defaults to $PROJECT_DIR/cluster/
EOM
    exit 0
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
    if [ -n "$pre" ] && "$pre"; then
        return 1
    fi

    if [ -z "$cmd" ]; then
        return 0
    fi

    if ! "$cmd"; then
        printf "Error: Execution failed: %s!\n" "$cmd"
        return 1
    fi

    if [ -z "$post" ]; then
        return 0
    fi

    if ! "$post"; then
        printf "Error: Execution failed: %s!\n" "$cmd"
        return 1
    fi

}

setup() {
    declare -a network_cmds=(
        "openstack network create --share --provider-network-type flat --provider-physical-network external --external public"
        "openstack subnet create --no-dhcp --allocation-pool start=192.168.122.125,end=192.168.122.200\\
      --gateway 192.168.122.1 --subnet-range 192.168.122.0/24 --network public public_subnet"
        "openstack router create public"
        "openstack router set --external-gateway public public"
        "openstack subnet create ocp --network ocp --subnet-range 10.0.0.0/16 --dhcp"
        "openstack router add subnet public ocp"
        "openstack floating ip create --floating-ip-address 192.168.122.150 --description "API fdp.nfv" public"
        "openstack floating ip create --floating-ip-address 192.168.122.151 --description "Ingress fdp.nfv" public"
    )
    run_cmd "openstack network show public" \
        "openstack network create --share --provider-network-type flat --provider-physical-network external --external public" \
        "openstack network show public"

    run_cmd "openstack subnet show public" \
        "openstack subnet create --no-dhcp --allocation-pool start=192.168.122.125,end=192.168.122.200\\
         --gateway 192.168.122.1 --subnet-range 192.168.122.0/24 --network public public" \
        "openstack subnet show public"

    run_cmd "openstack network show ocp" \
        "openstack network create ocp" \
        "openstack network show ocp"

    run_cmd "openstack subnet show ocp" \
        "openstack subnet create ocp --network ocp --subnet-range 10.0.0.0/16 --dhcp" \
        "openstack router show public | grep -q -e '.*external_gateway_info.*|.*network_id'"

    run_cmd "openstack router show public" \
        "openstack router create public" \
        "openstack router show public"

    run_cmd "openstack router show public | grep -q -e '.*external_gateway_info.*|.*network_id'" \
        "openstack router set --external-gateway public public" \
        "openstack router show public | grep -q -e '.*external_gateway_info.*|.*network_id'"

    run_cmd "openstack router show public | grep -q -e '.*interfaces_info.*|.*port_id'" \
        "openstack router add subnet public ocp" \
        "openstack router show public | grep -q -e '.*interfaces_info.*|.*port_id'"



    if ! openstack flavor create --ram 16384 --disk 25 --vcpus 8 --property hw:cpu_policy=dedicated --property hw:mem_page_size=1GB ocp; then
        printf "Error: Failed to create OCP flavor!"
        return 1
    fi

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
        cp "$PROJECT_DIR/clouds.yaml" "$BUILD_DIR"
        cp "$PROJECT_DIR/secure.yaml" "$BUILD_DIR"
        cp "$PROJECT_DIR/install-config.yaml" "$BUILD_DIR"

        deploy_cluster
        ;;
    destroy) ;;

    *)
        printf "Invalid cmd %s\n" "$cmd"
        return 1
        ;;
    esac
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
    local command="$1"

    [ -z "$command" ] && command="cluster"

    case $command in
    cluster)
        export TF_LOG_PATH=/tmp/tflog_cluster.txt
        manage_cluster "deploy"
        ;;
    workers)
        export TF_LOG_PATH=/tmp/tflog_workers.txt
        manage_workers "deploy"
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
    SUB_COMMAND=$1
    shift
    deploy "$SUB_COMMAND"
    ;;
destroy)
    SUB_COMMAND=$1
    shift
    destroy "$SUB_COMMAND"
    ;;
setup)
    setup
    ;;
*)
    echo "Unknown command: $COMMAND"
    usage "$out_dir"
    ;;
esac
