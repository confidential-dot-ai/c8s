#!/usr/bin/env bash
# Install ARC on the host cluster: the controller here, then the scale set via
# register.sh, which handles the credential BY REFERENCE (no token in helm
# values — see ../SECURITY.md) and is idempotent. Run AFTER create-host-cluster.sh.
# Prefer a GitHub App / dedicated PAT for GH_RUNNER_TOKEN, not your gh session.
set -euo pipefail
ORG_URL="${ORG_URL:-https://github.com/cifrai}"
: "${GH_RUNNER_TOKEN:?set GH_RUNNER_TOKEN — dedicated credential, see ../SECURITY.md}"
CTX="${KUBE_CONTEXT:-$(kubectl config current-context)}"
SCALE_SET="${SCALE_SET:-confidential-gcp}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

helm install arc \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller \
  -n arc-systems --create-namespace --kube-context "$CTX" --wait

# scale set + secret-by-reference, idempotent
KUBE_CONTEXT="$CTX" ORG_URL="$ORG_URL" SCALE_SET="$SCALE_SET" \
  GH_RUNNER_TOKEN="$GH_RUNNER_TOKEN" MAX_RUNNERS="${MAX_RUNNERS:-3}" \
  bash "$HERE/register.sh"

echo "ARC + $SCALE_SET installed on $CTX (org: $ORG_URL)"
