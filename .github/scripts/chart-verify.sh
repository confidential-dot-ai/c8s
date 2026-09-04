#!/usr/bin/env bash
# Lint and render the c8s shape charts for .github/workflows/chart.yml. Per
# chart, two checks in sequence:
#   1. helm lint
#   2. helm template                       (renders cleanly)
#
# The image tags/digests below are CI placeholders: helm must resolve every
# `required`/digest reference for lint+template to pass, but nothing is
# deployed, so opaque dummy values are fine. Each shape gets only the values
# its chart reads: section presence is the shape (kata only in pod,
# attestationApi only in node-cloud/node-metal).
#
# Inputs (env):
#   CHART_DIR   chart directory to lint/template. Default: loop all four
#               shape charts.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

# The vendored copies (charts/c8s-lib, crds/, files/scripts/) are gitignored,
# so lint/template against the in-repo dirs needs them materialized first.
bash internal/helmchart/sync.sh

if [ "${CHART_DIR:-}" ]; then
  chart_dirs=("$CHART_DIR")
else
  chart_dirs=(
    internal/helmchart/pod
    internal/helmchart/node-cloud
    internal/helmchart/node-metal
    internal/helmchart/node-image
  )
fi

# Shared --set flags for every chart. The digests are well-formed but
# arbitrary sha256 placeholders (lint/template only need them to parse).
common_set=(
  --set image.tag=ci
  --set cds.image.tag=ci
  # tls-lb has no default upstream; a c8s-<id> headless-Service address (what
  # `c8s install --upstream` derives, recognized as mesh-wrapped) is the
  # representative configuration.
  --set-string tlsLb.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000
)

# pod: the in-guest policy admits only digest-pinned image references, so the
# chart refuses to render without image.digest (kind=kata_image_digest).
pod_set=(
  --set image.digest=sha256:bbbb000000000000000000000000000000000000000000000000000000000000
)

# node shapes: the NRI allowlist floor pins CDS and the installer image by
# digest. The default policy mode is fail-closed, which requires every
# digest-pinned c8s component to be covered in the allowlist floor or the
# plugin would deny it on its own node; deriveComponents auto-covers them
# from their digests (what `c8s install --resolve-digests` turns on).
node_set=(
  --set ratlsMesh.image.tag=ci
  --set nriImagePolicy.image.tag=ci
  --set nriImagePolicy.image.digest=sha256:aaaa000000000000000000000000000000000000000000000000000000000000
  --set cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001
  --set nriImagePolicy.bootstrapAllowlist.deriveComponents=true
)

for chart_dir in "${chart_dirs[@]}"; do
  case "$(basename "$chart_dir")" in
    pod)
      shape_set=("${common_set[@]}" "${pod_set[@]}")
      ;;
    node-cloud|node-metal)
      shape_set=("${common_set[@]}" "${node_set[@]}" --set attestationApi.image.tag=ci)
      ;;
    node-image)
      shape_set=("${common_set[@]}" "${node_set[@]}")
      ;;
    *)
      shape_set=("${common_set[@]}")
      ;;
  esac

  echo "::group::helm lint ($chart_dir)"
  helm lint "$chart_dir" "${shape_set[@]}"
  echo "::endgroup::"

  # --kube-version: the charts' kubeVersion floor (1.30) is above helm 3.14's
  # default simulated capability (1.29), so template needs it pinned
  # explicitly.
  echo "::group::helm template ($chart_dir)"
  helm template c8s "$chart_dir" \
    --kube-version v1.30.0 \
    --namespace c8s-system \
    "${shape_set[@]}" \
    > /dev/null
  echo "::endgroup::"
done
