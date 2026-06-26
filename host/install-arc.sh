#!/usr/bin/env bash
# Install ARC (controller + org-wide confidential runner scale set) on the host
# cluster. Run AFTER create-host-cluster.sh (kube-context already points at it).
# Org scope uses a GitHub App in production (see ../org-setup.md); this accepts a
# token via GH_RUNNER_TOKEN for a quick bring-up.
set -euo pipefail
ORG_URL="${ORG_URL:-https://github.com/cifrai}"
: "${GH_RUNNER_TOKEN:?set GH_RUNNER_TOKEN (admin:org) — e.g. \$(gh auth token)}"
CTX="${KUBE_CONTEXT:-$(kubectl config current-context)}"

helm install arc \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller \
  -n arc-systems --create-namespace --kube-context "$CTX" --wait

helm install confidential-e2e \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n arc-runners --create-namespace --kube-context "$CTX" \
  --set githubConfigUrl="$ORG_URL" \
  --set githubConfigSecret.github_token="$GH_RUNNER_TOKEN" \
  --set minRunners=0 --set maxRunners=3 --wait   # 0=scale-to-zero; set 1 for a warm pool

echo "ARC + confidential-e2e installed on $CTX (org: $ORG_URL)"
kubectl --context "$CTX" -n arc-runners get autoscalingrunnerset
