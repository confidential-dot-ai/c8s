#!/usr/bin/env bash
# Live check that the mode event keeps a dynamic node from posing as a
# sealed one. On a dynamic node cluster-admin is node root: a privileged
# copy of Cilium (admitted there by the floor on its digest alone) extends
# RTMR[3] with the very events a static boot extends, the static mode event
# and the policy event of the reviewed bundle. Because the register already
# holds the operator-key seed and the dynamic mode event, the result is
# Extend(Extend(ForDynamic(seed), ModeStatic), PolicyEvent(index)), never
# ForStaticAllowlist(index), and `c8s verify --static-allowlist` keeps
# failing on RTMR[3].
#
# The register is read through verify's own error text ("RTMR[3] (...) is
# <got>, expected <want>"), so each step asserts the exact value: before the
# forge it must be ForDynamic(ForOperatorKey(pub)), which is the dynamic-boot
# assertion of the lane, and after it the forged chain above.
#
# Needs c8s, curl, jq and openssl on PATH, kubectl pointed at the dynamic
# node's cluster, and:
#   E2E_LB_URL          the dynamic node's tls-lb front door, https://<node>:443
#   E2E_IMAGE_MANIFEST  manifest.json of the node image
#   E2E_BUNDLE          the static bundle directory (the one the sealed node booted)
#   E2E_OPERATOR_PUB    the operator public key file the dynamic node booted with,
#                       byte for byte (the initrd hashed the file as attached)
# Optional:
#   E2E_WORKLOAD        entry name passed to --workload (default c8s-tls-lb; verify
#                       fails on RTMR[3] before it reads the stamp)
#   E2E_OUT             where to keep the verify outputs (default: a temp dir)
set -euo pipefail
# shellcheck disable=SC1091  # resolved relative to this script at run time
. "$(dirname "$0")/lib.sh"

: "${E2E_LB_URL:?tls-lb URL of the dynamic node}"
: "${E2E_IMAGE_MANIFEST:?manifest.json of the node image}"
: "${E2E_BUNDLE:?static bundle directory}"
: "${E2E_OPERATOR_PUB:?operator public key the dynamic node booted with}"
workload=${E2E_WORKLOAD:-c8s-tls-lb}
out=${E2E_OUT:-$(mktemp -d)}
mkdir -p "$out"
# kube-system: the chart's host-namespace admission policy denies the pod's
# hostPath volume in every other namespace.
ns=kube-system
pod=rtmr3-forge

member="$E2E_BUNDLE/static-allowlist.json"
[ -f "$member" ] || fail "$member is missing"
static=$(static_rtmr3_hex "$member")
dynamic=$(dynamic_rtmr3_hex "$E2E_OPERATOR_PUB")
mode_static=$(mode_static_hex)
policy=$(policy_event_hex "$(bundle_index "$member")")
forged=$(extend_hex "$(extend_hex "$dynamic" "$mode_static")" "$policy")
echo "static register:  $static"
echo "dynamic register: $dynamic"
echo "forged register:  $forged"

cleanup() {
  local rc=$?
  [ "$rc" -eq 0 ] || return 0
  kubectl -n "$ns" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

fetched=""
for _ in $(seq 1 30); do
  if curl -fsk --max-time 10 "$E2E_LB_URL/.well-known/mesh-ca.pem" -o "$out/mesh-ca.pem" && grep -q 'BEGIN CERTIFICATE' "$out/mesh-ca.pem"; then
    fetched=1; break
  fi
  sleep 5
done
[ -n "$fetched" ] || fail "no mesh CA served at $E2E_LB_URL/.well-known/mesh-ca.pem"

# reported_rtmr3 <label>: runs the static verifier against the dynamic node,
# requires the policy failure (exit 2) to be the RTMR[3] pin with the static
# register as the expectation, and prints the register the node reported.
reported_rtmr3() {
  local rc=0 err got want
  c8s verify "$E2E_LB_URL" --kind lb \
    --image-manifest "$E2E_IMAGE_MANIFEST" \
    --static-allowlist "$E2E_BUNDLE" \
    --workload "$workload" \
    --mesh-ca "$out/mesh-ca.pem" \
    -o json > "$out/verify-$1.json" || rc=$?
  [ "$rc" -eq 2 ] || fail "$1: c8s verify --static-allowlist against the dynamic node exited $rc, want 2 (policy failed): $(cat "$out/verify-$1.json")"
  err=$(jq -r '.error // ""' "$out/verify-$1.json")
  got=$(sed -nE 's/^RTMR\[3\] \(.*\) is ([0-9a-f]{96}), expected ([0-9a-f]{96})$/\1/p' <<<"$err")
  want=$(sed -nE 's/^RTMR\[3\] \(.*\) is ([0-9a-f]{96}), expected ([0-9a-f]{96})$/\2/p' <<<"$err")
  [ -n "$got" ] || fail "$1: verify failed, but not on the RTMR[3] pin: $err"
  [ "$want" = "$static" ] || fail "$1: verify expects RTMR[3] $want, but the bundle derives $static"
  printf '%s' "$got"
}

got=$(reported_rtmr3 before)
[ "$got" = "$dynamic" ] || fail "before the forge the dynamic node reports RTMR[3] $got, want ForDynamic(ForOperatorKey(pub)) $dynamic"
echo "ok: dynamic node reports the operator-key seed extended by the dynamic mode event; the static verifier refuses it"

# Two 48-byte writes, in the order a static boot extends them. dd holds each
# to a single write, which is what the tdx_guest sysfs node accepts.
sysfs=/host/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384
script=$(printf "printf '%s' | dd of=%s bs=48 count=1 2>/dev/null && printf '%s' | dd of=%s bs=48 count=1 2>/dev/null" \
  "$(hex2octal "$mode_static")" "$sysfs" "$(hex2octal "$policy")" "$sysfs")
cilium_copy_manifest "$ns" "$pod" "$(cilium_image)" "$(jq -Rn --arg s "$script" '$s')" | kubectl apply -f - >/dev/null
phase=""
for _ in $(seq 1 60); do
  phase=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  case "$phase" in Succeeded|Failed) break ;; esac
  sleep 2
done
if [ "$phase" != Succeeded ]; then
  kubectl -n "$ns" describe pod "$pod" | tail -25
  fail "the privileged cilium copy did not run to completion on the dynamic node (phase ${phase:-none}); the floor no longer admits it, or the sysfs write failed"
fi
echo "ok: privileged pod on the dynamic node extended RTMR[3] with the static events"

got=$(reported_rtmr3 after)
[ "$got" = "$forged" ] || fail "after the forge the dynamic node reports RTMR[3] $got, want the forged chain $forged"
echo "ok: the register carries the forged chain and the static verifier still refuses it"

echo "PASS: a dynamic node cannot forge the static register; the mode event keeps the two shapes apart"
