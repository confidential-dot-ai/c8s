#!/usr/bin/env bash
# Fetches the node image's published evidence for the static lane: the
# manifest.json whose mrtd+rtmr1+rtmr2 match the booted build, and the
# system-floor.json the same build emitted beside it. Both ship as layers of
# the oras artifact that sits next to the CDI image (c8s-image.yml).
#
# The CM's 'image' may be a tag or a digest. A digest carries no name, so it
# is resolved back to the sibling tag that points at it; without that the
# only candidate left would be the floating dev tag. Candidates are matched
# on the whole tuple: two builds sharing a firmware have the same MRTD while
# their kernels, and so their RTMR[1], differ.
#
# Needs crane and jq on PATH, and:
#   image      node image reference (tag or digest) from the refs ConfigMap
#   mrtd, rtmr1, rtmr2   the tuple the ConfigMap pins
#   E2E_OUT    directory to write image-manifest.json and system-floor.json to
# Optional:
#   imageTag   oras tag published beside the image, when it cannot be derived
#   REFS_CM    ConfigMap name, for the error text
set -euo pipefail
# shellcheck disable=SC1091  # resolved relative to this script at run time
. "$(dirname "$0")/lib.sh"

: "${image:?node image reference}"
: "${mrtd:?MRTD the ConfigMap pins}"
: "${rtmr1:?RTMR[1] the ConfigMap pins}"
: "${rtmr2:?RTMR[2] the ConfigMap pins}"
: "${E2E_OUT:?output directory}"
refs_cm=${REFS_CM:-tdx-rke2-image-refs}
mkdir -p "$E2E_OUT"

repo="${image%%@*}"; repo="${repo%%:*}"
cands="${imageTag:-}"
case "$image" in
  *@*)
    want="${image#*@}"
    for t in $(crane ls "$repo" 2>/dev/null | grep -E -- '-cdi(-[0-9a-f]+)?$'); do
      [ "$(crane digest "$repo:$t" 2>/dev/null)" = "$want" ] || continue
      cands="$cands $t"; break
    done
    ;;
  *-cdi*) cands="$cands ${image#*:}" ;;
esac
# shellcheck disable=SC2086  # deliberate split: cands is a word list
cands="$(printf '%s\n' ${cands} | sed 's/-cdi//' | awk 'NF && !seen[$0]++')"
[ -n "$cands" ] || fail "cannot derive an oras tag from image '$image'. Set 'imageTag' in $refs_cm to the tag published beside it"

layer_digest() {
  crane manifest "$1" 2>/dev/null \
    | jq -r --arg title "$2" '.layers[]|select(.annotations["org.opencontainers.image.title"]==$title)|.digest'
}

oras_ref=""
for t in $cands; do
  d=$(layer_digest "$repo:$t" manifest.json) || true
  [ -n "$d" ] || { echo "  $t: no manifest.json layer"; continue; }
  crane blob "$repo@$d" > "$E2E_OUT/candidate-manifest.json" 2>/dev/null || continue
  m=$(jq -r '.tdx.mrtd // empty' "$E2E_OUT/candidate-manifest.json")
  m1=$(jq -r '.tdx.rtmr1 // empty' "$E2E_OUT/candidate-manifest.json")
  m2=$(jq -r '.tdx.rtmr2 // empty' "$E2E_OUT/candidate-manifest.json")
  if [ "$m" = "$mrtd" ] && [ "$m1" = "$rtmr1" ] && [ "$m2" = "$rtmr2" ]; then
    mv "$E2E_OUT/candidate-manifest.json" "$E2E_OUT/image-manifest.json"
    oras_ref="$repo:$t"; break
  fi
  echo "  $t: tuple mismatch (mrtd ${m:0:16}/${mrtd:0:16} rtmr1 ${m1:0:16}/${rtmr1:0:16} rtmr2 ${m2:0:16}/${rtmr2:0:16})"
done
rm -f "$E2E_OUT/candidate-manifest.json"
[ -n "$oras_ref" ] || fail "no oras artifact among [$cands] publishes a manifest.json whose mrtd+rtmr1+rtmr2 matches the build this CVM boots. Set 'imageTag' in $refs_cm to the tag published beside the pinned image"
echo "ok: manifest from $oras_ref"

# The floor is the same build's, never another tag's: the RKE2 bundle pin,
# and so every system digest, is part of what the tuple measures.
d=$(layer_digest "$oras_ref" system-floor.json) || true
[ -n "$d" ] || fail "$oras_ref publishes no system-floor.json layer: the image was built before c8s-image.yml emitted the floor skeleton; rebuild and re-seed $refs_cm"
crane blob "$oras_ref@$d" > "$E2E_OUT/system-floor.json" || fail "cannot fetch system-floor.json from $oras_ref"
jq -e '.schema == "c8s.system-floor/v1"' "$E2E_OUT/system-floor.json" >/dev/null \
  || fail "system-floor.json from $oras_ref is not a c8s.system-floor/v1 document"
echo "ok: system floor from $oras_ref ($(jq '.images | length' "$E2E_OUT/system-floor.json") images)"

echo "PASS: image evidence fetched into $E2E_OUT"
