#!/usr/bin/env bash
# Keep the chart's attestationApi pinnedDigest equal to the attestation-api
# image built from the attestation-rs commit pinned in build-pins.json.

set -euo pipefail

tmp_path=
cleanup() {
  if [[ -n "$tmp_path" ]]; then
    rm -f -- "$tmp_path"
  fi
}
trap cleanup EXIT

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage:
  attestation-api-pin.sh check --manifest PATH --values PATH [--domain DOMAIN]
  attestation-api-pin.sh stamp --values PATH --attest SHA

check: fail unless values.yaml pins the digest of attestation-api:sha-<7> for
       the manifest's DOMAIN attestation_rs_ref (default node-image).
stamp: resolve that digest for --attest and rewrite the pinnedDigest line.
       Prints "no-drift" when the file already carries it.

C8S_ATTESTATION_API_RESOLVER=CMD replaces the ghcr.io lookup: CMD is run with
the image reference as its single argument and must print the digest.
EOF
  exit 2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

is_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

is_digest() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

require_sha() {
  is_sha "$1" || die "$2 must be a full lowercase 40-hex SHA"
}

image_repo=ghcr.io/confidential-dot-ai/attestation-api
values_path=attestationApi.image

# attestation-rs publishes one immutable tag per main commit.
image_tag() {
  printf 'sha-%s\n' "${1:0:7}"
}

resolve_ghcr() {
  local tag=$1 token headers code digest
  require_command curl
  token=$(curl -fsSL --retry 3 --max-time 20 \
    "https://ghcr.io/token?scope=repository:${image_repo#ghcr.io/}:pull" |
    jq -er .token) || die "ghcr.io token request failed"
  headers=$(curl -sS -I --retry 3 --max-time 20 \
    -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
    "https://ghcr.io/v2/${image_repo#ghcr.io/}/manifests/${tag}" |
    tr -d '\r') || die "ghcr.io manifest request failed for ${image_repo}:${tag}"
  code=$(awk 'NR == 1 {print $2}' <<<"$headers")
  [[ "$code" == 200 ]] || die "${image_repo}:${tag} is not published (HTTP ${code:-none})"
  digest=$(awk 'tolower($1) == "docker-content-digest:" {print $2}' <<<"$headers")
  printf '%s\n' "$digest"
}

resolve_digest() {
  local tag=$1 digest
  if [[ -n "${C8S_ATTESTATION_API_RESOLVER:-}" ]]; then
    digest=$("$C8S_ATTESTATION_API_RESOLVER" "${image_repo}:${tag}") ||
      die "resolver failed for ${image_repo}:${tag}"
  else
    digest=$(resolve_ghcr "$tag") || exit 1
  fi
  is_digest "$digest" || die "resolver returned no sha256 digest for ${image_repo}:${tag}: '${digest}'"
  printf '%s\n' "$digest"
}

manifest_attest() {
  local manifest=$1 domain=$2 ref
  [[ -f "$manifest" ]] || die "manifest not found: $manifest"
  ref=$(jq -er --arg d "$domain" '.builds[$d].attestation_rs_ref' "$manifest") ||
    die "manifest has no builds.${domain}.attestation_rs_ref"
  require_sha "$ref" "builds.${domain}.attestation_rs_ref"
  printf '%s\n' "$ref"
}

# Line number of the attestationApi.image component's pinnedDigest.
pinned_line() {
  local values=$1 lines
  [[ -f "$values" ]] || die "values file not found: $values"
  lines=$(awk -v vp="$values_path" '
    /^  - valuePath: / { in_comp = ($3 == vp) }
    in_comp && /^    pinnedDigest: / { print NR }
  ' "$values")
  [[ -n "$lines" ]] || die "$values: no pinnedDigest under valuePath ${values_path}"
  [[ $(wc -l <<<"$lines") -eq 1 ]] || die "$values: more than one pinnedDigest under valuePath ${values_path}"
  printf '%s\n' "$lines"
}

pinned_digest() {
  local values=$1 line digest
  line=$(pinned_line "$values") || exit 1
  digest=$(awk -v n="$line" 'NR == n {print $2}' "$values")
  is_digest "$digest" || die "$values:$line: pinnedDigest is not a sha256 digest: '${digest}'"
  printf '%s\n' "$digest"
}

cmd_check() {
  local manifest=$1 values=$2 domain=$3 attest tag want have
  attest=$(manifest_attest "$manifest" "$domain") || exit 1
  tag=$(image_tag "$attest")
  want=$(resolve_digest "$tag") || exit 1
  have=$(pinned_digest "$values") || exit 1
  if [[ "$have" != "$want" ]]; then
    die "$values pins attestationApi at ${have} but ${image_repo}:${tag} (attestation-rs ${attest}, ${domain}) is ${want}; run: attestation-api-pin.sh stamp --attest ${attest}"
  fi
  echo "attestationApi pinnedDigest matches ${image_repo}:${tag} (${want})"
}

cmd_stamp() {
  local values=$1 attest=$2 tag want have line
  require_sha "$attest" "--attest"
  tag=$(image_tag "$attest")
  want=$(resolve_digest "$tag") || exit 1
  have=$(pinned_digest "$values") || exit 1
  line=$(pinned_line "$values") || exit 1
  if [[ "$have" == "$want" ]]; then
    echo no-drift
    return 0
  fi
  tmp_path=$(mktemp -- "${values}.XXXXXX")
  awk -v n="$line" -v d="$want" 'NR == n {sub(/sha256:[0-9a-f]+/, d)} {print}' "$values" >"$tmp_path"
  [[ $(pinned_digest "$tmp_path" || true) == "$want" ]] || die "stamp did not take effect"
  mv -f -- "$tmp_path" "$values"
  tmp_path=
  echo "stamped ${values}: attestationApi pinnedDigest ${have} -> ${want} (${image_repo}:${tag})"
}

main() {
  [[ $# -ge 1 ]] || usage
  local command=$1
  shift

  local manifest="" values="" attest="" domain=node-image
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --manifest) manifest=${2:-}; shift 2 ;;
      --values) values=${2:-}; shift 2 ;;
      --attest) attest=${2:-}; shift 2 ;;
      --domain) domain=${2:-}; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$values" ]] || usage
  require_command jq

  case "$command" in
    check)
      [[ -n "$manifest" && -z "$attest" ]] || usage
      cmd_check "$manifest" "$values" "$domain"
      ;;
    stamp)
      [[ -n "$attest" ]] || usage
      cmd_stamp "$values" "$attest"
      ;;
    *) usage ;;
  esac
}

main "$@"
