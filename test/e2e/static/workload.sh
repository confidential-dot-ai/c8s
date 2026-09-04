#!/usr/bin/env bash
# Live-cluster check of the sealed rules around one workload entry: the
# sample from workloads/demo-nginx.yaml is admitted and scales, while the
# same image with a ConfigMap mount, an env var the rule does not list, or
# another argv is refused at container creation. The refused variants carry
# the cw annotation too, so their injected c8s-cert init container runs and
# obtains a certificate first: what is refused is the workload container
# itself, for the one field that differs from the bundle's rule.
#
# Leaves the demo-nginx Deployment running for the checks that follow
# (debug-refused.sh); `kubectl delete -f workloads/demo-nginx.yaml` removes
# it. Needs kubectl pointed at a static-allowlist cluster whose bundle was
# rendered from workloads/demo-nginx.yaml.
set -euo pipefail
# shellcheck disable=SC1091  # resolved relative to this script at run time
. "$(dirname "$0")/lib.sh"

here=$(cd "$(dirname "$0")" && pwd)
ns=default
deploy=demo-nginx
variants=(configmap env argv)

# The variants must differ from the admitted manifest in exactly the field
# each one tests, so the image line is held identical across the four files.
image=$(grep -oE '[[:graph:]]+@sha256:[0-9a-f]{64}' "$here/workloads/demo-nginx.yaml" | head -1)
[ -n "$image" ] || fail "no digest-pinned image in workloads/demo-nginx.yaml"
for v in "${variants[@]}"; do
  grep -qF "image: $image" "$here/workloads/demo-nginx-$v.yaml" \
    || fail "workloads/demo-nginx-$v.yaml does not pin $image; keep the image line identical across the variants"
done

cleanup() {
  local rc=$?
  [ "$rc" -eq 0 ] || return 0
  for v in "${variants[@]}"; do
    kubectl -n "$ns" delete -f "$here/workloads/demo-nginx-$v.yaml" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

for v in "${variants[@]}"; do
  kubectl apply -f "$here/workloads/demo-nginx-$v.yaml" >/dev/null
done
wait_container_denied "$ns" demo-nginx-configmap containerStatuses nginx
wait_container_denied "$ns" demo-nginx-env containerStatuses nginx
wait_container_denied "$ns" demo-nginx-argv containerStatuses nginx

# wait_ready <replicas>: the Deployment reports that many ready replicas.
wait_ready() {
  local want=$1 have=""
  for _ in $(seq 1 60); do
    have=$(kubectl -n "$ns" get deploy "$deploy" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)
    [ "${have:-0}" -ge "$want" ] && return 0
    sleep 10
  done
  kubectl -n "$ns" describe pods -l "app=$deploy" | tail -40
  fail "$deploy has ${have:-0} ready replicas, want $want"
}

kubectl apply -f "$here/workloads/demo-nginx.yaml" >/dev/null
wait_ready 1
names=$(kubectl -n "$ns" get pods -l "app=$deploy" \
  -o jsonpath='{.items[0].spec.initContainers[*].name}' 2>/dev/null || true)
case "$names" in
  *c8s-cert*) ;;
  *) fail "the webhook did not inject the c8s-cert sidecar (init containers: ${names:-none})" ;;
esac
echo "ok: $deploy Ready with the injected c8s-cert sidecar"

kubectl -n "$ns" scale deploy "$deploy" --replicas=2 >/dev/null
wait_ready 2
echo "ok: $deploy scaled to 2 Ready"

echo "PASS: the matching workload runs and scales; a ConfigMap mount, an unlisted env var and another argv are refused"
