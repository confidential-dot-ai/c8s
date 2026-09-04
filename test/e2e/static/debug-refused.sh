#!/usr/bin/env bash
# Live-cluster check that the two ways into a running container are shut on
# a sealed node: `kubectl exec` is refused by the kubelet (the locked image
# runs it with enable-debugging-handlers=false), and `kubectl debug`, which
# the kubelet flag does not cover because an ephemeral container is created
# like any other, is refused by the sealed allowlist at container creation.
# The debug image is one the node already holds (busybox from the RKE2
# bundle), so what refuses it is the absence of a rule, not a pull.
#
# Needs kubectl pointed at a static-allowlist cluster with the demo-nginx
# workload from workload.sh running. Optional:
#   E2E_TARGET_POD   pod to exec into and attach the ephemeral container to
#                    (default: the first demo-nginx pod in default)
#   E2E_DEBUG_IMAGE  ephemeral container image (default busybox:1.38.0)
set -euo pipefail
# shellcheck disable=SC1091  # resolved relative to this script at run time
. "$(dirname "$0")/lib.sh"

ns=default
target=${E2E_TARGET_POD:-$(kubectl -n "$ns" get pods -l app=demo-nginx -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}
[ -n "$target" ] || fail "no demo-nginx pod in $ns to target; run workload.sh first or set E2E_TARGET_POD"
image=${E2E_DEBUG_IMAGE:-busybox:1.38.0}
probe=sealed-debug-probe

expect_deny "kubectl exec into $target" "Debug endpoints are disabled" -- \
  kubectl -n "$ns" exec "$target" -c nginx -- true

# No -it: the command returns once the API server accepts the ephemeral
# container; the kubelet's verdict lands in the pod status.
kubectl -n "$ns" debug "$target" --image="$image" --container="$probe" -- sleep 3600 >/dev/null \
  || fail "kubectl debug was rejected by the API server; the check needs the ephemeral container to reach the kubelet"
wait_container_denied "$ns" "$target" ephemeralContainerStatuses "$probe"

echo "PASS: kubectl exec and kubectl debug are refused on the sealed node"
