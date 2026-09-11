
set -euo pipefail

include=()
exclude=()
maybe_add() {
  local changed="$1" binary="$2" image="$3" dockerfile="$4"
  if [[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" || "$SHARED" == "true" || "$changed" == "true" ]]; then
    include+=("{\"binary\":\"$binary\",\"image\":\"$image\",\"dockerfile\":\"$dockerfile\"}")
  else
    exclude+=("{\"binary\":\"$binary\",\"image\":\"$image\"}")
  fi
}

maybe_add "$C8S" c8s ghcr.io/confidential-dot-ai/c8s-operator cmd/c8s/Dockerfile
maybe_add "$CDS" cds ghcr.io/confidential-dot-ai/cds cmd/cds/Dockerfile
maybe_add "$GET_CERT" get-cert ghcr.io/confidential-dot-ai/get-cert cmd/get-cert/Dockerfile
maybe_add "$RATLS_MESH" ratls-mesh ghcr.io/confidential-dot-ai/ratls-mesh cmd/ratls-mesh/Dockerfile
maybe_add "$NRI_IMAGE_POLICY" nri-image-policy ghcr.io/confidential-dot-ai/nri-image-policy cmd/nri-image-policy/Dockerfile
maybe_add "$VOLUMED" volumed ghcr.io/confidential-dot-ai/volumed cmd/volumed/Dockerfile

if [[ ${#include[@]} -eq 0 ]]; then
  echo 'has_images=false' >> "$GITHUB_OUTPUT"
  echo 'matrix={"include":[]}' >> "$GITHUB_OUTPUT"
else
  matrix=$(IFS=,; printf '{"include":[%s]}' "${include[*]}")
  echo 'has_images=true' >> "$GITHUB_OUTPUT"
  echo "matrix=$matrix" >> "$GITHUB_OUTPUT"
fi

if [[ ${#exclude[@]} -eq 0 ]]; then
  echo 'has_retag=false' >> "$GITHUB_OUTPUT"
  echo 'retag_matrix={"include":[]}' >> "$GITHUB_OUTPUT"
else
  retag_matrix=$(IFS=,; printf '{"include":[%s]}' "${exclude[*]}")
  echo 'has_retag=true' >> "$GITHUB_OUTPUT"
  echo "retag_matrix=$retag_matrix" >> "$GITHUB_OUTPUT"
fi
