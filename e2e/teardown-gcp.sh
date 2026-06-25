#!/usr/bin/env bash
# Destroy the ephemeral Confidential GKE cluster. Runs with `if: always()` so a
# failed E2E never leaks a confidential cluster (cost + security).
set -euo pipefail

: "${GCP_PROJECT:?set GCP_PROJECT}"
LOCATION="${GCP_LOCATION:-${GCP_REGION:-us-central1}}"
CLUSTER="${E2E_CLUSTER:-$(cat /tmp/e2e-cluster-name 2>/dev/null || true)}"

if [ -z "${CLUSTER:-}" ]; then
  echo "no cluster recorded; nothing to delete"
  exit 0
fi

echo "::group::teardown $CLUSTER"
gcloud container clusters delete "$CLUSTER" \
  --project "$GCP_PROJECT" --location "$LOCATION" --quiet || true
echo "::endgroup::"
