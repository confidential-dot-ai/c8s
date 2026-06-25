#!/usr/bin/env bash
# Wire GKE Workload Identity Federation so runner pods on the host cluster can
# create/delete confidential clusters (Model B) with NO static keys: a K8s SA is
# bound to a GCP SA that holds container.admin. Run with kube-context on the host.
set -euo pipefail
GCP_PROJECT="${GCP_PROJECT:-conf-500518}"
ZONE="${GCP_ZONE:-us-central1-a}"
CLUSTER="${HOST_CLUSTER:-arc-host}"
NS="${RUNNER_NS:-arc-runners}"
KSA="${KSA:-arc-e2e}"
GSA="${GSA:-arc-e2e}"
GSA_EMAIL="$GSA@$GCP_PROJECT.iam.gserviceaccount.com"
POOL="$GCP_PROJECT.svc.id.goog"

echo "== 1. enable Workload Identity on cluster + node pool =="
gcloud container clusters update "$CLUSTER" --zone "$ZONE" --project "$GCP_PROJECT" \
  --workload-pool="$POOL" --quiet
gcloud container node-pools update default-pool --cluster "$CLUSTER" --zone "$ZONE" \
  --project "$GCP_PROJECT" --workload-metadata=GKE_METADATA --quiet

echo "== 2. GSA that can manage confidential GKE clusters =="
gcloud iam service-accounts create "$GSA" --project "$GCP_PROJECT" 2>/dev/null || true
for role in roles/container.admin roles/iam.serviceAccountUser; do
  gcloud projects add-iam-policy-binding "$GCP_PROJECT" \
    --member="serviceAccount:$GSA_EMAIL" --role="$role" --condition=None --quiet >/dev/null
done

echo "== 3. KSA bound to GSA (Workload Identity) =="
kubectl create serviceaccount "$KSA" -n "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl annotate serviceaccount "$KSA" -n "$NS" \
  iam.gke.io/gcp-service-account="$GSA_EMAIL" --overwrite
gcloud iam service-accounts add-iam-policy-binding "$GSA_EMAIL" \
  --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:$POOL[$NS/$KSA]" --quiet >/dev/null

echo "== 4. runner scale set uses the KSA =="
helm upgrade confidential-e2e \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n "$NS" --reuse-values \
  --set template.spec.serviceAccountName="$KSA" --wait

echo "WIF wired: pods using $NS/$KSA act as $GSA_EMAIL (container.admin) — no static keys."
