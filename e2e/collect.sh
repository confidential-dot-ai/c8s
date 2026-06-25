#!/usr/bin/env bash
# Collect logs/evidence for the run (runs with `if: always()`), into ./e2e-artifacts.
set -euo pipefail
OUT="${OUT_DIR:-e2e-artifacts}"
mkdir -p "$OUT"
kubectl get all -A -o wide                 > "$OUT/resources.txt"  2>&1 || true
kubectl get events -A --sort-by=.lastTimestamp > "$OUT/events.txt" 2>&1 || true
for ns in confidential-serving attestation kserve; do
  kubectl logs -n "$ns" --all-containers --tail=500 -l app 2>/dev/null > "$OUT/logs-$ns.txt" || true
done
echo "collected -> $OUT"
