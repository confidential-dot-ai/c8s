#!/usr/bin/env bash
# Provision an EPHEMERAL Confidential GKE cluster for one E2E run (Model B).
# Parameterized — point at a real CI project via env. Paired with teardown-gcp.sh.
#
# NOTE: confidential-node flags/availability vary by gcloud + GKE version + region.
# Confidential GKE Nodes (SEV-SNP / TDX) are GA on GKE >= 1.32.2; confidential
# H100 on A3 is GA (>= 1.32.2 manual driver / >= 1.33.3 auto). Verify against
# your gcloud version before first run.
set -euo pipefail

: "${GCP_PROJECT:?set GCP_PROJECT}"
# LOCATION may be a zone (cheap: 1 control plane + 1 node) or a region (HA: 3
# nodes). CI uses a region; a quick test uses a zone.
LOCATION="${GCP_LOCATION:-${GCP_REGION:-us-central1}}"
CLUSTER="${E2E_CLUSTER:-conf-e2e-${GITHUB_RUN_ID:-local}}"
CONF_TYPE="${CONF_TYPE:-sev_snp}"        # sev_snp | tdx | sev (legacy, broadest capacity)
MACHINE="${MACHINE:-n2d-standard-4}"     # SEV/SEV-SNP: n2d/c3d ; TDX: c3 ; GPU: a3-highgpu-1g

# sev_snp/tdx need --confidential-node-type; legacy "sev" is just
# --enable-confidential-nodes (Confidential VM / AMD SEV), which has the broadest
# zone capacity — use it when sev_snp stocks out.
EXTRA=()
case "$CONF_TYPE" in
  sev_snp|tdx) EXTRA+=(--confidential-node-type "$CONF_TYPE") ;;
esac

echo "::group::provision $CLUSTER ($CONF_TYPE, $MACHINE) in $GCP_PROJECT/$LOCATION"
gcloud container clusters create "$CLUSTER" \
  --project "$GCP_PROJECT" --location "$LOCATION" \
  ${GKE_VERSION:+--cluster-version "$GKE_VERSION"} \
  --machine-type "$MACHINE" --num-nodes 1 \
  --enable-confidential-nodes \
  "${EXTRA[@]}" \
  --enable-ip-alias --no-enable-basic-auth \
  --labels "e2e=confidential,run=${GITHUB_RUN_ID:-local}" \
  --quiet

gcloud container clusters get-credentials "$CLUSTER" \
  --project "$GCP_PROJECT" --location "$LOCATION"

echo "$CLUSTER" > /tmp/e2e-cluster-name   # teardown reads this
kubectl get nodes -o wide
echo "::endgroup::"
