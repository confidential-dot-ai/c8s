#!/usr/bin/env bash
# Live-cluster check that the c8s control plane converged: pods in c8s-system
# are Running with every container Ready.
#
# With no arguments every pod must be ready. Name-prefix arguments narrow it to
# those components, for installs that deliberately leave others out.
#
# Needs kubectl pointed at a cluster with c8s installed.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ns=c8s-system

if [ "${C8S_NODE_IMAGE:-}" = 1 ]; then
  : "${C8S_MEASUREMENTS_CONFIG:?node-image checks require the full leader policy}"
  : "${C8S_ALLOWLIST_URL:?node-image checks require the measured CDS front door}"
  kubectl -n "$ns" rollout status deployment/c8s-operator --timeout=8m
  runtime=$(kubectl -n "$ns" get configmap c8s-node-runtime -o json)
  jq -e '.data["cds-url"] | test("^https://[0-9.]+:30808$")' <<< "$runtime" >/dev/null \
    || fail "node runtime ConfigMap has no concrete CDS URL"
  expected=$(jq -cS 'del(.measurements[].name)' "$C8S_MEASUREMENTS_CONFIG")
  actual=$(jq -cer '.data["cds.json"] | fromjson | del(.measurements[].name)' <<< "$runtime" | jq -cS .)
  [ "$actual" = "$expected" ] || fail "node runtime lost or changed the leader image/operator pins"
  chart=$(kubectl -n kube-system get helmcharts.helm.cattle.io c8s --ignore-not-found -o name)
  [ -z "$chart" ] || fail "node image unexpectedly started a runtime c8s Helm installation"
fi

select_pods() {
  if [ "$#" -eq 0 ]; then cat; return 0; fi
  local pat="" p
  for p in "$@"; do pat="${pat:+$pat|}^$p"; done
  grep -E "$pat" || true
}

# awk, not a regex backreference: `$2 !~ /^([0-9]+)\/\1$/` looks right and is
# not (awk has no backreferences), so it silently only ever matches 1/1 and
# calls every sidecar-bearing pod not-ready.
count_notready() {
  awk 'NF {split($2,a,"/"); if (a[1]!=a[2] || $3!="Running") n++} END {print n+0}'
}

converged=""
backoff=0
for _ in $(seq 1 40); do
  listing=$(kubectl -n "$ns" get pods --no-headers 2>/dev/null | select_pods "$@" || true)
  total=$(printf '%s\n' "$listing" | awk 'NF' | wc -l)
  n=$(printf '%s\n' "$listing" | count_notready)
  if [ "$total" -gt 0 ] && [ "$n" -eq 0 ]; then converged=1; break; fi
  # A pull that is still backing off after a minute does not recover inside
  # the window; fail now rather than spending the whole timeout on it.
  case "$listing" in
    *ImagePullBackOff*) backoff=$((backoff + 1)) ;;
    *) backoff=0 ;;
  esac
  if [ "$backoff" -ge 5 ]; then
    kubectl -n "$ns" get events --sort-by=.lastTimestamp 2>/dev/null | grep -i pull | tail -6 || true
    fail "image pulls are backing off; components cannot converge"
  fi
  sleep 15
done

printf '%s\n' "${listing:-}"
if [ -z "$converged" ]; then
  kubectl -n "$ns" describe pods | tail -40
  fail "c8s components did not converge (${n:-?} of ${total:-0} not ready)"
fi

if [ "${C8S_NODE_IMAGE:-}" = 1 ]; then
  ready=0
  for _ in $(seq 1 60); do
    if c8s allowlist list --url "$C8S_ALLOWLIST_URL" --measurements-config "$C8S_MEASUREMENTS_CONFIG" >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 5
  done
  [ "$ready" = 1 ] || fail "measured CDS/front-door services did not become ready under the leader policy"
fi

echo "PASS: all $total c8s Kubernetes components Running"
