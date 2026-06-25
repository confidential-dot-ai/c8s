#!/usr/bin/env bash
# Always-on HOST cluster that runs ARC (controller + runner scale sets).
# This is NOT confidential — it only hosts the runners; the confidential clusters
# are the ephemeral ones the runners provision per E2E (Model B). Small + zonal
# to keep cost low (~1x e2-medium). Needs gke-gcloud-auth-plugin locally.
set -euo pipefail
GCP_PROJECT="${GCP_PROJECT:-conf-500518}"
ZONE="${GCP_ZONE:-us-central1-a}"
CLUSTER="${HOST_CLUSTER:-arc-host}"

gcloud container clusters create "$CLUSTER" \
  --project "$GCP_PROJECT" --zone "$ZONE" \
  --machine-type e2-medium --num-nodes 1 \
  --enable-ip-alias --no-enable-basic-auth \
  --labels purpose=arc-host --quiet

gcloud container clusters get-credentials "$CLUSTER" \
  --project "$GCP_PROJECT" --zone "$ZONE"
kubectl get nodes -o wide
echo "host cluster '$CLUSTER' ready (context: gke_${GCP_PROJECT}_${ZONE}_${CLUSTER})"
