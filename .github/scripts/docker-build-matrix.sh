#!/usr/bin/env bash
# Build the per-image Docker build matrix consumed by the `images` job in
# .github/workflows/docker.yml.
#
# A component image is included when ANY of:
#   - this is a tag push (refs/tags/*)  -> release tags fan out to every image
#   - shared code changed (SHARED=true) -> pkg/**, root internal/**, go.mod, …
#   - the component's own paths changed  (its <X>=true flag)
#
# Inputs (env), each "true"/"false" from the dorny/paths-filter step:
#   SHARED             shared-core || shared-cmdsutil || shared-root
#   C8S, CDS, GET_CERT, RATLS_MESH, NRI_IMAGE_POLICY
#   GITHUB_REF         the triggering ref (for the tag-push fan-out)
#   GITHUB_OUTPUT      step output file; we append `matrix` and `has_images`.
#
# Output (GITHUB_OUTPUT):
#   has_images=true|false
#   matrix={"include":[{binary,image,dockerfile}, …]}

set -euo pipefail

include=()
add_image() {
  include+=("{\"binary\":\"$1\",\"image\":\"$2\",\"dockerfile\":\"$3\"}")
}
add_if_changed() {
  local changed="$1"
  shift
  if [[ "$GITHUB_REF" == refs/tags/* || "$SHARED" == "true" || "$changed" == "true" ]]; then
    add_image "$@"
  fi
}

add_if_changed "$C8S" c8s ghcr.io/lunal-dev/c8s-operator cmd/c8s/Dockerfile
add_if_changed "$CDS" cds ghcr.io/lunal-dev/cds cmd/cds/Dockerfile
add_if_changed "$GET_CERT" get-cert ghcr.io/lunal-dev/get-cert cmd/get-cert/Dockerfile
add_if_changed "$RATLS_MESH" ratls-mesh ghcr.io/lunal-dev/ratls-mesh cmd/ratls-mesh/Dockerfile
add_if_changed "$NRI_IMAGE_POLICY" nri-image-policy ghcr.io/lunal-dev/nri-image-policy cmd/nri-image-policy/Dockerfile

if [[ ${#include[@]} -eq 0 ]]; then
  echo 'has_images=false' >> "$GITHUB_OUTPUT"
  echo 'matrix={"include":[]}' >> "$GITHUB_OUTPUT"
  exit 0
fi

matrix=$(IFS=,; printf '{"include":[%s]}' "${include[*]}")
echo 'has_images=true' >> "$GITHUB_OUTPUT"
echo "matrix=$matrix" >> "$GITHUB_OUTPUT"
