#!/bin/sh
# Gate attested credential release on the live guards: the PodSecurity
# invariant, the operator-scope policy that keeps cred-release credentials
# away from the guards themselves, the pod-exec policy, and the two RBAC
# bindings the issued groups rely on. RKE2 reconciles server/manifests
# asynchronously after kube-apiserver is ready, so object presence is not
# enough: prove the allow and deny paths through the real admission chain,
# and prove that every live guard equals its reference copy on the read-only
# root (server/manifests is on the writable overlay), before cred-release
# starts listening.
set -eu

KUBECTL=${KUBECTL:-/var/lib/rancher/rke2/bin/kubectl}
KUBECONFIG=${KUBECONFIG:-/etc/rancher/rke2/rke2.yaml}
KUBECTL_CACHE_DIR=${KUBECTL_CACHE_DIR:-/run/cred-release/kubecache}
CLIENT_CA_KEY=${CLIENT_CA_KEY:-/var/lib/rancher/rke2/server/tls/client-ca.key}
# The C8S_DEV=1 build drops a `.skip` marker next to the pod-exec AddOn so
# RKE2 never applies it; the gate must not wait for what will never appear.
MANIFESTS_DIR=${MANIFESTS_DIR:-/var/lib/rancher/rke2/server/manifests}
# Reference copies of the guard AddOns, staged by mkosi.sync onto the
# read-only root. Every file here is compared against the live objects.
GUARDS_DIR=${GUARDS_DIR:-/usr/lib/confai/guards}
PSA_WAIT_ATTEMPTS=${PSA_WAIT_ATTEMPTS:-120}
PSA_WAIT_SECONDS=${PSA_WAIT_SECONDS:-5}

policy=confos-psa-level
scope_policy=confos-operator-scope
exec_policy=confos-pod-exec
operator_binding=c8s-node-operators
log_reader_binding=c8s-log-readers
operator_group=c8s:node-operators
probe=confos-psa-readiness-probe
probe_user=confos:psa-readiness-probe
expected_message='pod-security.kubernetes.io/enforce may not be set below restricted'
expected_scope_message='may not write in the PodSecurity-exempt namespaces'

fail() {
    echo "psa-ready: $1" >&2
    exit 1
}

case "$PSA_WAIT_ATTEMPTS" in
    ''|*[!0-9]*|0) fail "PSA_WAIT_ATTEMPTS must be a positive integer" ;;
esac
case "$PSA_WAIT_SECONDS" in
    ''|*[!0-9]*) fail "PSA_WAIT_SECONDS must be a non-negative integer" ;;
esac

mkdir -p "$KUBECTL_CACHE_DIR"
k() {
    "$KUBECTL" --kubeconfig "$KUBECONFIG" --cache-dir "$KUBECTL_CACHE_DIR" "$@"
}

cleanup() {
    k delete clusterrolebinding "$probe" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    k delete clusterrole "$probe" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

install_probe_rbac() {
    k apply -f - >/dev/null <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: $probe
rules:
  - apiGroups: [""]
    resources: ["namespaces", "configmaps"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: $probe
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: $probe
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: $probe_user
EOF
}

# The fields that make a guard a guard, rendered identically for a live
# object and for the reference file. `replace --dry-run=server` returns the
# file exactly as the apiserver would store it (defaults applied, nothing
# retained from the live object), so the two sides differ only when the
# live object differs from the file. `get -f` fetches the objects the file
# names; a missing one fails the get. The template prints the spec (VAP and
# binding), rules, roleRef and subjects (RBAC); absent fields print empty.
guard_fields='{.spec}{.rules}{.roleRef}{.subjects}{"\n"}'
guards_match() {
    for file in "$GUARDS_DIR"/*.yaml; do
        [ -e "$file" ] || { last_error="no guard reference copies in $GUARDS_DIR"; return 1; }
        name=$(basename "$file" .yaml)
        if [ -e "$MANIFESTS_DIR/$name.yaml.skip" ]; then
            continue
        fi
        if ! expected=$(k replace --dry-run=server -f "$file" -o jsonpath="$guard_fields" 2>&1); then
            last_error="guard $name: reference copy is not admitted by the apiserver: $expected"
            return 1
        fi
        if ! live=$(k get -f "$file" -o jsonpath="$guard_fields" 2>&1); then
            last_error="guard $name: live objects are not all present: $live"
            return 1
        fi
        if [ "$live" != "$expected" ]; then
            last_error="guard $name: live objects differ from the read-only reference copy"
            return 1
        fi
    done
    return 0
}

# A ConfigMap create in the given namespace, as the probe user carrying the
# operator group: RBAC admits it (the probe role above), so a denial can only
# come from admission.
probe_scope() {
    ns=$1
    k --as="$probe_user" --as-group="$operator_group" -n "$ns" create --dry-run=server -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: $probe
EOF
}

probe_namespace() {
    level=$1
    k --as="$probe_user" create --dry-run=server -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $probe-$level
  labels:
    pod-security.kubernetes.io/enforce: $level
    pod-security.kubernetes.io/enforce-version: latest
EOF
}

rbac_installed=
last_error='the API server is not ready'
attempt=1
while [ "$attempt" -le "$PSA_WAIT_ATTEMPTS" ]; do
    if [ ! -r "$CLIENT_CA_KEY" ]; then
        last_error="client CA key is not readable"
    elif ! k get clusterrolebinding "$operator_binding" >/dev/null 2>&1; then
        last_error="ClusterRoleBinding $operator_binding is not available"
    elif ! k get clusterrolebinding "$log_reader_binding" >/dev/null 2>&1; then
        last_error="ClusterRoleBinding $log_reader_binding is not available"
    elif [ ! -e "$MANIFESTS_DIR/pod-exec-policy.yaml.skip" ] && ! k get validatingadmissionpolicy "$exec_policy" >/dev/null 2>&1; then
        last_error="ValidatingAdmissionPolicy $exec_policy is not available"
    elif [ ! -e "$MANIFESTS_DIR/pod-exec-policy.yaml.skip" ] && ! k get validatingadmissionpolicybinding "$exec_policy" >/dev/null 2>&1; then
        last_error="ValidatingAdmissionPolicyBinding $exec_policy is not available"
    elif ! k get validatingadmissionpolicy "$policy" >/dev/null 2>&1; then
        last_error="ValidatingAdmissionPolicy $policy is not available"
    elif ! k get validatingadmissionpolicybinding "$policy" >/dev/null 2>&1; then
        last_error="ValidatingAdmissionPolicyBinding $policy is not available"
    elif ! k get validatingadmissionpolicy "$scope_policy" >/dev/null 2>&1; then
        last_error="ValidatingAdmissionPolicy $scope_policy is not available"
    elif ! k get validatingadmissionpolicybinding "$scope_policy" >/dev/null 2>&1; then
        last_error="ValidatingAdmissionPolicyBinding $scope_policy is not available"
    elif ! guards_match; then
        : # last_error set by guards_match
    else
        if [ -z "$rbac_installed" ]; then
            if install_probe_rbac; then
                rbac_installed=1
            else
                last_error="could not install the temporary readiness-probe RBAC"
            fi
        fi

        if [ -n "$rbac_installed" ]; then
            if restricted_out=$(probe_namespace restricted 2>&1); then
                if privileged_out=$(probe_namespace privileged 2>&1); then
                    last_error="privileged namespace dry-run was admitted"
                else
                    case "$privileged_out" in
                        *"$policy"*)
                            case "$privileged_out" in
                                *"$expected_message"*)
                                    if ! scope_allow_out=$(probe_scope default 2>&1); then
                                        last_error="operator-scoped configmap dry-run in default was denied: $scope_allow_out"
                                    elif scope_deny_out=$(probe_scope kube-system 2>&1); then
                                        last_error="operator-scoped configmap dry-run in kube-system was admitted"
                                    else
                                        case "$scope_deny_out" in
                                            *"$scope_policy"*"$expected_scope_message"*)
                                                echo "psa-ready: $policy is enforcing the restricted namespace floor; $scope_policy is enforcing the operator scope; live guards match $GUARDS_DIR"
                                                exit 0
                                                ;;
                                            *) last_error="operator-scoped configmap dry-run in kube-system was denied by a different guard: $scope_deny_out" ;;
                                        esac
                                    fi
                                    ;;
                                *) last_error="privileged namespace was denied by $policy without its expected validation message" ;;
                            esac
                            ;;
                        *) last_error="privileged namespace was denied by a different guard: $privileged_out" ;;
                    esac
                fi
            else
                last_error="restricted namespace dry-run was denied: $restricted_out"
            fi
        fi
    fi

    if [ "$attempt" -lt "$PSA_WAIT_ATTEMPTS" ]; then
        sleep "$PSA_WAIT_SECONDS"
    fi
    attempt=$((attempt + 1))
done

fail "timed out waiting for enforced PodSecurity admission: $last_error"
