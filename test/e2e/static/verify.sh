#!/usr/bin/env bash
# Live check, from outside the cluster, that `c8s verify --static-allowlist`
# proves the front door runs on a node sealed to the reviewed bundle: exit 0,
# every register pinned including RTMR[3] derived from the bundle, and the
# bundle's index digest reported as the static policy.
#
# Needs c8s, curl and jq on PATH and:
#   E2E_LB_URL          tls-lb front door, https://<node>:443
#   E2E_IMAGE_MANIFEST  manifest.json of the node image
#   E2E_BUNDLE          the bundle directory the node booted with
# Optional:
#   E2E_WORKLOAD        entry the front door's leaf must be stamped with (default c8s-tls-lb)
#   E2E_OUT             where to keep mesh-ca.pem and verify.json (default: a temp dir)
set -euo pipefail
# shellcheck disable=SC1091  # resolved relative to this script at run time
. "$(dirname "$0")/lib.sh"

: "${E2E_LB_URL:?tls-lb front door URL}"
: "${E2E_IMAGE_MANIFEST:?manifest.json of the node image}"
: "${E2E_BUNDLE:?bundle directory}"
workload=${E2E_WORKLOAD:-c8s-tls-lb}
out=${E2E_OUT:-$(mktemp -d)}
mkdir -p "$out"

# The CA is fetched from the door it anchors: the e2e proves the evidence
# chain, not the out-of-band distribution of the CA, which is the operator's.
fetched=""
for _ in $(seq 1 30); do
  if curl -fsk --max-time 10 "$E2E_LB_URL/.well-known/mesh-ca.pem" -o "$out/mesh-ca.pem" && grep -q 'BEGIN CERTIFICATE' "$out/mesh-ca.pem"; then
    fetched=1; break
  fi
  sleep 5
done
[ -n "$fetched" ] || fail "no mesh CA served at $E2E_LB_URL/.well-known/mesh-ca.pem"

rc=0
c8s verify "$E2E_LB_URL" --kind lb \
  --image-manifest "$E2E_IMAGE_MANIFEST" \
  --static-allowlist "$E2E_BUNDLE" \
  --workload "$workload" \
  --mesh-ca "$out/mesh-ca.pem" \
  -o json > "$out/verify.json" || rc=$?
cat "$out/verify.json"
[ "$rc" -eq 0 ] || fail "c8s verify --static-allowlist exited $rc (0 = verified, 2 = failed, 3 = no evidence, 4 = partial)"
jq -e '.verified == true' "$out/verify.json" >/dev/null || fail "verify exited 0 without verified=true"

want_rtmr3=$(static_rtmr3_hex "$E2E_BUNDLE/static-allowlist.json")
jq -e --arg pin "3:$want_rtmr3" '.rtmrs_pinned | index($pin) != null' "$out/verify.json" >/dev/null \
  || fail "verify did not report RTMR[3] pinned to $want_rtmr3 (rtmrs_pinned: $(jq -c '.rtmrs_pinned' "$out/verify.json"))"
want_index="sha256:$(bundle_index "$E2E_BUNDLE/static-allowlist.json" | sha256sum | cut -d' ' -f1)"
jq -e --arg d "$want_index" '.static_policy_digest == $d' "$out/verify.json" >/dev/null \
  || fail "verify reported static_policy_digest $(jq -r '.static_policy_digest' "$out/verify.json"), want $want_index"
jq -e --arg w "$workload" '.workload == $w' "$out/verify.json" >/dev/null \
  || fail "verify reported workload $(jq -r '.workload' "$out/verify.json"), want $workload"

echo "PASS: c8s verify --static-allowlist proves the front door runs on a node sealed to the bundle"
