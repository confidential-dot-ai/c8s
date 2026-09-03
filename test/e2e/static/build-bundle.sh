#!/usr/bin/env bash
# Builds the policy bundle the static lane boots, from the published image
# evidence and the fixtures beside this script, and proves the bundle is the
# fixed point of the install that consumes it:
#
#   1. `c8s render-values` computes the dynamic node-mode values install
#      would apply at E2E_IMAGE_TAG; static-overlay.yaml adds what
#      `c8s install --static-allowlist` sets on top.
#   2. `c8s allowlist render --sealed` turns those values, the image's
#      system-floor.json and workloads/demo-nginx.yaml into rules.
#   3. complete/ applies reviews.json (the lane's reviewer) and lints.
#   4. `c8s render-values --static-allowlist <bundle>` is rendered again and
#      must reproduce the bundle byte for byte, so the values install derives
#      from the bundle are the values the bundle was rendered from.
#   5. `c8s policy-disk` writes the ISO, the KubeVirt Secret and the expected
#      RTMR[3], which is cross-checked against lib.sh's shell arithmetic.
#
# REVIEWER'S COMPLETION. system-floor.json only names each RKE2 image and its
# image-config argv; what the static pods bind, share and run is completed by
# reviews.json, which cannot be verified on the runner. It is written for the
# RKE2 bundle pinned in node-guest-image/c8s/mkosi.sync and MUST be refreshed
# when that pin moves: a stale entry fails step 3 here (entry names carry the
# tag), a wrong one shows up as a sealed node whose system pods never start.
#
# A sealed document has no open argv, env or mounts, privileged or not, so
# every floor entry in reviews.json needs the env values and mount rules (and
# the argv, where the static pod manifest overrides the image config) observed
# on a dynamic node of the same image: the sealed plugin's deny log prints one
# observation per refused container. A floor entry without them fails step 3.
#
# Needs c8s, helm, crane, jq, yq, go and one of xorrisofs, genisoimage or
# mkisofs on PATH, registry access for the image configs, and:
#   E2E_IMAGE_MANIFEST  manifest.json of the node image (tdx.mrtd/rtmr1/rtmr2)
#   E2E_SYSTEM_FLOOR    system-floor.json published beside it
#   E2E_IMAGE_TAG       component image tag the bundle names (the c8s ref paired with the image)
#   E2E_OUT             output directory
# Optional:
#   E2E_POLICYDATA_SECRET  KubeVirt Secret name to emit (default c8s-policydata)
#   E2E_C8S_SRC            c8s checkout holding complete/ (default: the one this script is in)
#
# Writes under E2E_OUT: bundle/static-allowlist.json (the one-member bundle
# directory every c8s --static-allowlist flag takes), policydata.iso,
# policydata-secret.yaml, rtmr3, index-digest, values.yaml and the render
# report.
set -euo pipefail
# shellcheck disable=SC1091  # resolved relative to this script at run time
. "$(dirname "$0")/lib.sh"

here=$(cd "$(dirname "$0")" && pwd)
: "${E2E_IMAGE_MANIFEST:?manifest.json of the node image}"
: "${E2E_SYSTEM_FLOOR:?system-floor.json of the node image}"
: "${E2E_IMAGE_TAG:?component image tag}"
: "${E2E_OUT:?output directory}"
secret=${E2E_POLICYDATA_SECRET:-c8s-policydata}
src=${E2E_C8S_SRC:-$(cd "$here/../../.." && pwd)}

for tool in c8s helm crane jq yq go; do
  command -v "$tool" >/dev/null || fail "$tool is not on PATH"
done
command -v xorrisofs >/dev/null || command -v genisoimage >/dev/null || command -v mkisofs >/dev/null \
  || fail "no ISO9660 tool on PATH (xorrisofs, genisoimage or mkisofs)"

mkdir -p "$E2E_OUT/bundle"
mrtd=$(jq -r '.tdx.mrtd // empty' "$E2E_IMAGE_MANIFEST")
rtmr1=$(jq -r '.tdx.rtmr1 // empty' "$E2E_IMAGE_MANIFEST")
rtmr2=$(jq -r '.tdx.rtmr2 // empty' "$E2E_IMAGE_MANIFEST")
[ -n "$mrtd" ] && [ -n "$rtmr1" ] && [ -n "$rtmr2" ] || fail "$E2E_IMAGE_MANIFEST carries no TDX tuple"

# render-values takes the same flags install does, minus the cluster.
values_flags=(--cvm-mode node --hardware-platform tdx --single-node --distro rke2)

# render_bundle <values.yaml> <out.json>: rules from the chart, the floor and
# the sample workload, completed by the reviewer fixture.
render_bundle() {
  c8s allowlist render --sealed \
    --system-floor "$E2E_SYSTEM_FLOOR" \
    --chart-values "$1" \
    --workloads "$here/workloads/demo-nginx.yaml" \
    --report "$E2E_OUT/render-report.txt" > "$E2E_OUT/rendered.json" \
    || fail "c8s allowlist render --sealed failed (see $E2E_OUT/render-report.txt)"
  (cd "$src" && go run ./test/e2e/static/complete -reviews "$here/reviews.json" "$E2E_OUT/rendered.json") > "$2" \
    || fail "reviews.json does not complete the rendered document"
}

# 1. Values as install computes them, plus the static overlay. The
# measurements entry is a placeholder here: its RTMR[3] is what the bundle
# determines, and the chart only carries the file, so the rules do not
# depend on it.
c8s render-values "${values_flags[@]}" --image-tag "$E2E_IMAGE_TAG" \
  --measurements "$mrtd" --rtmrs "1=$rtmr1,2=$rtmr2" > "$E2E_OUT/values-base.yaml" \
  || fail "c8s render-values failed"
MC=$(jq -cn --arg m "$mrtd" --arg r1 "$rtmr1" --arg r2 "$rtmr2" --arg z "$(printf '%096d' 0)" \
  '{schema_version:"1",tee:"tdx",measurements:[{name:"static-allowlist",mrtd:$m,rtmr:[null,$r1,$r2,$z]}]}')
export MC
cp "$here/static-overlay.yaml" "$E2E_OUT/values-overlay.yaml"
yq -i '.cds.measurementsConfig = strenv(MC) | .ratlsMesh.measurementsConfig = strenv(MC)' "$E2E_OUT/values-overlay.yaml"
yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' \
  "$E2E_OUT/values-base.yaml" "$E2E_OUT/values-overlay.yaml" > "$E2E_OUT/values.yaml"
echo "ok: chart values rendered for tag $E2E_IMAGE_TAG"

# 2 + 3. Render and complete.
render_bundle "$E2E_OUT/values.yaml" "$E2E_OUT/bundle/static-allowlist.json"
c8s allowlist lint --sealed "$E2E_OUT/bundle/static-allowlist.json" >/dev/null \
  || fail "the completed bundle does not lint as sealed"
echo "ok: bundle rendered and linted ($(jq '.workloads | length' "$E2E_OUT/bundle/static-allowlist.json") entries)"

# 4. Fixed point: the values install derives from this bundle must render
# this bundle again.
c8s render-values "${values_flags[@]}" \
  --static-allowlist "$E2E_OUT/bundle" --image-manifest "$E2E_IMAGE_MANIFEST" > "$E2E_OUT/values-from-bundle.yaml" \
  || fail "c8s render-values --static-allowlist refused the bundle"
render_bundle "$E2E_OUT/values-from-bundle.yaml" "$E2E_OUT/static-allowlist.from-bundle.json"
if ! cmp -s "$E2E_OUT/bundle/static-allowlist.json" "$E2E_OUT/static-allowlist.from-bundle.json"; then
  diff <(jq -S . "$E2E_OUT/bundle/static-allowlist.json") <(jq -S . "$E2E_OUT/static-allowlist.from-bundle.json") || true
  fail "the bundle is not a fixed point of its own install: static-overlay.yaml no longer matches what c8s install --static-allowlist sets"
fi
echo "ok: bundle is the fixed point of c8s render-values --static-allowlist"

# 5. Disk, Secret and the expected register.
c8s policy-disk --member "$E2E_OUT/bundle/static-allowlist.json" -o "$E2E_OUT/policydata.iso" \
  --kubevirt-secret "$secret" > "$E2E_OUT/policydata-secret.yaml" 2> "$E2E_OUT/policy-disk.txt" \
  || fail "c8s policy-disk failed: $(cat "$E2E_OUT/policy-disk.txt")"
awk '$1 == "rtmr3:" { print $2 }' "$E2E_OUT/policy-disk.txt" > "$E2E_OUT/rtmr3"
awk '$1 == "index-digest:" { print $2 }' "$E2E_OUT/policy-disk.txt" > "$E2E_OUT/index-digest"
[ -s "$E2E_OUT/rtmr3" ] && [ -s "$E2E_OUT/index-digest" ] || fail "policy-disk printed no rtmr3/index-digest lines: $(cat "$E2E_OUT/policy-disk.txt")"
want=$(static_rtmr3_hex "$E2E_OUT/bundle/static-allowlist.json")
[ "$(cat "$E2E_OUT/rtmr3")" = "$want" ] \
  || fail "policy-disk rtmr3 $(cat "$E2E_OUT/rtmr3") differs from lib.sh's ForStaticAllowlist $want; the shell arithmetic forge-rtmr3.sh relies on is wrong"
echo "ok: policydata.iso written; RTMR[3] $(cut -c1-16 "$E2E_OUT/rtmr3")... index $(cut -c1-23 "$E2E_OUT/index-digest")..."

echo "PASS: policy bundle built under $E2E_OUT"
