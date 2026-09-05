#!/bin/sh
# Gate attested credential release on the live PodSecurity invariant. RKE2
# reconciles server/manifests asynchronously after kube-apiserver is ready, so
# object presence is not enough: prove both the allow and deny paths through
# the real admission chain before cred-release starts listening.
set -eu

KUBECTL=${KUBECTL:-/var/lib/rancher/rke2/bin/kubectl}
KUBECONFIG=${KUBECONFIG:-/etc/rancher/rke2/rke2.yaml}
KUBECTL_CACHE_DIR=${KUBECTL_CACHE_DIR:-/run/cred-release/kubecache}
CLIENT_CA_KEY=${CLIENT_CA_KEY:-/var/lib/rancher/rke2/server/tls/client-ca.key}
PSA_WAIT_ATTEMPTS=${PSA_WAIT_ATTEMPTS:-120}
PSA_WAIT_SECONDS=${PSA_WAIT_SECONDS:-5}

policy=confos-psa-level
operator_binding=c8s-node-operators
probe=confos-psa-readiness-probe
probe_user=confos:psa-readiness-probe
expected_message='pod-security.kubernetes.io/enforce may not be set below restricted'

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
    resources: ["namespaces"]
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
    elif ! k get validatingadmissionpolicy "$policy" >/dev/null 2>&1; then
        last_error="ValidatingAdmissionPolicy $policy is not available"
    elif ! k get validatingadmissionpolicybinding "$policy" >/dev/null 2>&1; then
        last_error="ValidatingAdmissionPolicyBinding $policy is not available"
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
                                    echo "psa-ready: $policy is enforcing the restricted namespace floor"
                                    exit 0
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
