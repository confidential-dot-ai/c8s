#!/usr/bin/env bash
# Install ARC (Model A: orchestrator on the cluster, jobs launch confidential
# SNP KubeVirt VMs) onto a Rancher-managed RKE2 bare-metal cluster.
#
# Why this isn't a plain `helm install`: the Rancher proxy caps request body
# size, and the controller chart's helm release secret (bundled CRDs) exceeds it
# ("request body too large" on POST secrets). We bypass it by applying CRDs
# individually and rendering manifests with `helm template | kubectl apply
# --server-side` (no oversized release secret). Run against the Rancher kubeconfig.
set -euo pipefail

KUBECONFIG="${KUBECONFIG:?point at the Rancher kubeconfig (e.g. github-runner.yaml)}"
ORG_URL="${ORG_URL:-https://github.com/cifrai}"        # MUST back PRIVATE repos
SCALE_SET="${SCALE_SET:-confidential-bm}"              # runs-on: <this>; unique per cluster!
GH_TOKEN="${GH_RUNNER_TOKEN:-$(gh auth token)}"        # needs admin:org for org reg
CHART_VER="${CHART_VER:-0.14.2}"
WORK="$(mktemp -d)"

echo "== namespaces (RKE2 enforces restricted PSA; runners need privileged) =="
for ns in arc-systems arc-runners; do
  kubectl create ns "$ns" --dry-run=client -o yaml | kubectl apply -f -
done
kubectl label ns arc-systems arc-runners pod-security.kubernetes.io/enforce=privileged --overwrite

echo "== controller: CRDs individually, then template|apply (proxy-safe) =="
helm pull oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller \
  --version "$CHART_VER" --untar -d "$WORK"
kubectl apply --server-side -f "$WORK"/gha-runner-scale-set-controller/crds/
helm template arc "$WORK"/gha-runner-scale-set-controller -n arc-systems | kubectl apply --server-side -f -
kubectl -n arc-systems rollout status deploy/arc-gha-rs-controller --timeout=180s

echo "== scale set $SCALE_SET -> $ORG_URL (template|apply; explicit controller SA skips the cluster lookup) =="
helm template "$SCALE_SET" \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version "$CHART_VER" -n arc-runners \
  --set githubConfigUrl="$ORG_URL" \
  --set githubConfigSecret.github_token="$GH_TOKEN" \
  --set controllerServiceAccount.name=arc-gha-rs-controller \
  --set controllerServiceAccount.namespace=arc-systems \
  --set minRunners=0 --set maxRunners=2 | kubectl apply --server-side -f -

echo "== bind runner pods to the KubeVirt SA (see kubevirt-rbac.yaml) =="
kubectl apply -f "$(dirname "$0")/kubevirt-rbac.yaml"
kubectl -n arc-runners patch autoscalingrunnerset "$SCALE_SET" --type=merge \
  -p '{"spec":{"template":{"spec":{"serviceAccountName":"bm-e2e"}}}}'

echo "done. listener: kubectl -n arc-systems get pods | grep listener"
echo "repos using '$SCALE_SET' must be PRIVATE (see ../OPEN-SOURCE.md)."
