#!/usr/bin/env bash
# Live-cluster check that a sealed node refuses a privileged copy of a
# node-TCB image. The pod runs the node's own Cilium image, whose digest is
# on every node's floor, privileged and with the host /sys bound in. On a
# dynamic node the floor admits that on the digest alone (forge-rtmr3.sh
# relies on it); on a sealed node the Cilium rule's reviewed host paths do
# not include /sys, so the container is refused before it starts.
#
# Needs kubectl pointed at a static-allowlist cluster.
set -euo pipefail
# shellcheck disable=SC1091  # resolved relative to this script at run time
. "$(dirname "$0")/lib.sh"

# kube-system is exempt from the chart's host-namespace admission policy
# (which denies the hostPath volume everywhere else) and from the restricted
# PSA default; the sealed plugin exempts no namespace, so a denial here is
# the sealed allowlist.
ns=kube-system
pod=cilium-copy-probe

cleanup() {
  local rc=$?
  [ "$rc" -eq 0 ] || return 0
  kubectl -n "$ns" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

image=$(cilium_image)
echo "cilium image on this node: $image"
cilium_copy_manifest "$ns" "$pod" "$image" '"sleep 3600"' | kubectl apply -f - >/dev/null
wait_container_denied "$ns" "$pod" containerStatuses agent

echo "PASS: a privileged copy of cilium is refused by the sealed allowlist"
