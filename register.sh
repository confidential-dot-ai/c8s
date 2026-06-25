#!/usr/bin/env bash
# Register the self-hosted runner scale set with GitHub.
# The ARC *controller* is already installed (see ../README). This is the one
# step that touches your GitHub account, so it's separate and explicit.
#
# Needs: a repo (or org) URL and a token. A classic PAT with `repo` scope works
# for repo-level; a GitHub App is preferred for org/enterprise + production.
#
#   GITHUB_CONFIG_URL=https://github.com/<you>/<repo> \
#   GITHUB_PAT=ghp_xxx \
#   ./register.sh
#
# `runs-on: confidential-builders` in the workflow targets this scale set.
set -euo pipefail
: "${GITHUB_CONFIG_URL:?set GITHUB_CONFIG_URL=https://github.com/<you>/<repo>}"
: "${GITHUB_PAT:?set GITHUB_PAT=<classic PAT with repo scope>}"
NAME="${NAME:-confidential-builders}"
NS="${NS:-arc-runners}"

helm install "$NAME" \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --namespace "$NS" --create-namespace \
  --set githubConfigUrl="$GITHUB_CONFIG_URL" \
  --set githubConfigSecret.github_token="$GITHUB_PAT" \
  --set minRunners=0 --set maxRunners=3 \
  --set containerMode.type="kubernetes"

echo "Registered scale set '$NAME' in ns '$NS'. Runners are ephemeral (min 0)."
echo "Verify: kubectl -n $NS get pods,autoscalingrunnerset"
echo "Then push the workflow and watch a runner pod spin up per job."
