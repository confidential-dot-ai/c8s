#!/usr/bin/env bash
# Run against a disposable, single-node c8s image using its operator kubeconfig.
# Requires kubectl + jq. No exec/logs endpoint, external test image or allowlist
# change: reuse the baked local-path-provisioner image (Alpine + BusyBox).
# The control runs Unconfined with SYS_ADMIN only in the exempt system namespace.
set -euo pipefail
. "$(dirname "$0")/../../test/e2e/lib.sh"
k() { kubectl --request-timeout=30s "$@"; }

nodes=$(k get nodes -o json)
[ "$(jq '.items | length' <<<"$nodes")" = 1 ] || fail "requires a disposable single-node cluster"
node=$(jq -er '.items[0].metadata.name' <<<"$nodes")
image=$(k -n local-path-storage get deployment local-path-provisioner \
    -o jsonpath='{.spec.template.spec.containers[0].image}')
[ -n "$image" ] || fail "local-path-provisioner image is missing"

# Let the API allocate unique names; only delete resources this invocation made.
ns=""
pod=""
cleanup() {
    local result=$?
    if [ -n "$pod" ]; then k -n kube-system delete pod "$pod" --wait=false --ignore-not-found || result=1; fi
    if [ -n "$ns" ]; then k delete namespace "$ns" --wait=false --ignore-not-found || result=1; fi
    return "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
ns=$(k create -f - -o jsonpath='{.metadata.name}' <<'EOF'
{"apiVersion":"v1","kind":"Namespace","metadata":{"generateName":"apparmor-admission-"}}
EOF
)

# First prove the same pod is admissible under Restricted. Then change ONLY
# AppArmor: an unrelated admission/RBAC/network failure is not a passing denial.
admission=$(jq -n --arg ns "$ns" --arg image "$image" '{
    apiVersion:"v1",kind:"Pod",metadata:{name:"apparmor-admission",namespace:$ns},
    spec:{restartPolicy:"Never",automountServiceAccountToken:false,
        securityContext:{runAsNonRoot:true,runAsUser:65534,seccompProfile:{type:"RuntimeDefault"}},
        containers:[{name:"probe",image:$image,command:["/bin/true"],
            securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]},
                appArmorProfile:{type:"RuntimeDefault"}}}]}}')
k create --dry-run=server -f - <<<"$admission" >/dev/null
denied=$(jq '.spec.containers[0].securityContext.appArmorProfile.type="Unconfined"' <<<"$admission")
if output=$(k create --dry-run=server -f - <<<"$denied" 2>&1); then
    fail "Restricted admitted an Unconfined container"
fi
[[ "$output" == *'violates PodSecurity'* && "$output" == *'forbidden AppArmor profile'* && "$output" == *'Unconfined'* ]] \
    || fail "Unconfined failed for an unrelated reason: $output"

# No host mounts/namespaces. Each container has its own writable /tmp. Matching
# SYS_ADMIN and Unconfined seccomp remove alternate reasons for mount denial.
# Both omitted and explicit RuntimeDefault must select the enforcing profile.
probe=$(cat <<'EOF'
set -eu
export LC_ALL=C
label=$(cat /proc/self/attr/current)
mkdir /tmp/apparmor-mount
if [ "$1" = control ]; then
    [ "$label" = unconfined ]
    mount -t tmpfs tmpfs /tmp/apparmor-mount
    umount /tmp/apparmor-mount
else
    [ "$label" = 'cri-containerd.apparmor.d (enforce)' ]
    if mount -t tmpfs tmpfs /tmp/apparmor-mount; then
        umount /tmp/apparmor-mount
        exit 1
    fi
fi
printf '%s\n' "$label" > /dev/termination-log
EOF
)
manifest=$(jq -n --arg image "$image" --arg node "$node" --arg probe "$probe" '{
    apiVersion:"v1",kind:"Pod",metadata:{generateName:"apparmor-runtime-",namespace:"kube-system"},
    spec:{nodeName:$node,restartPolicy:"Never",activeDeadlineSeconds:180,
        automountServiceAccountToken:false,
        containers:(["control","default","explicit"] | map(
            {name:.,image:$image,imagePullPolicy:"IfNotPresent",
             command:["/bin/sh","-ec",$probe,"probe",.],
             securityContext:{privileged:false,runAsUser:0,
                 capabilities:{drop:["ALL"],add:["SYS_ADMIN"]},
                 seccompProfile:{type:"Unconfined"}}}
            | if .name=="control" then .securityContext.appArmorProfile={type:"Unconfined"}
              elif .name=="explicit" then .securityContext.appArmorProfile={type:"RuntimeDefault"}
              else . end))}}')
pod=$(k create -f - -o jsonpath='{.metadata.name}' <<<"$manifest")
for _ in $(seq 1 45); do
    status=$(k -n kube-system get pod "$pod" -o json)
    phase=$(jq -r '.status.phase' <<<"$status")
    case "$phase" in
        Succeeded) break ;;
        Failed) jq '.status' <<<"$status"; fail "AppArmor runtime probe failed" ;;
    esac
    sleep 5
done
[ "$phase" = Succeeded ] || { jq '.status' <<<"$status"; fail "AppArmor runtime probe timed out"; }
jq -e '
    .status.containerStatuses | length==3 and
    all(.[]; .state.terminated.exitCode==0 and
        (.state.terminated.message | rtrimstr("\n")) ==
        (if .name=="control" then "unconfined" else "cri-containerd.apparmor.d (enforce)" end))
' <<<"$status" >/dev/null || fail "unexpected runtime labels or exit status"
echo "PASS: omitted/explicit RuntimeDefault labels, mount denial/control, and Unconfined admission rejection"
