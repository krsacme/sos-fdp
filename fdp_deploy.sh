#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
ARTIFACTS_DIR="$PROJECT_DIR/build-artifacts"
BUILD_LOG="$BUILD_DIR/.openshift_install.log"
export OS_CLOUD=openstack

export KUBECONFIG="$BUILD_DIR/auth/kubeconfig"

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
        echo "$line" >>  f3
        [[ "$VERBOSE" =~ true ]] && echo "$line"
        touch f4

        if [[ ${line} =~ "for bootstrapping to complete" ]]; then
          echo "$line" > f5          
          break;
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
    etcd_hack &

    openshift-install create cluster --log-level debug

    # Wait for hacks to finish
    wait 
}

manage_cluster() {
    cmd="$1"

    case $cmd in
    deploy)
        rm -rf "$BUILD_DIR"
        mkdir -p "$BUILD_DIR"
        if [ ! -e ./clouds.yaml ]; then
            echo "Error: missing clouds.yaml file!"
            return 1
        fi
        if [ ! -e ./install-config.yaml ]; then
            echo "Error: missing install-config.yaml file!"
            return 1
        fi
        cp ./clouds.yaml "$BUILD_DIR"
        cp ./install-config.yaml "$BUILD_DIR"

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
*)
    echo "Unknown command: $COMMAND"
    usage "$out_dir"
    ;;
esac
