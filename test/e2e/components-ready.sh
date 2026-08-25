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

echo "PASS: all $total c8s components Running"
