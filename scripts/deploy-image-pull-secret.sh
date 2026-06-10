#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   IMAGE_PULL_SECRET=ghp_xxx ./deploy-image-pull-secret.sh
#
# Optional overrides:
#   GITHUB_USERNAME  - registry username (default: your git config user, fallback "x-access-token")
#   SECRET_NAME      - name of the k8s secret (default: ghcr-pull-secret)
#   REGISTRY         - registry server (default: ghcr.io)
#   NAMESPACE        - the namespace to install the secret (default: default)

: "${IMAGE_PULL_SECRET:?IMAGE_PULL_SECRET is not set. Usage: IMAGE_PULL_SECRET=ghp_xxx $0}"

SECRET_NAME="${SECRET_NAME:-ghcr-pull-secret}"
REGISTRY="${REGISTRY:-ghcr.io}"
GITHUB_USERNAME="${GITHUB_USERNAME:-$(git config user.name 2>/dev/null || echo x-access-token)}"
NAMESPACE="${NAMESPACE:-default}"

# Idempotent: render the secret and apply it, so re-runs update in place
kubectl create secret docker-registry "${SECRET_NAME}" \
  --namespace "${NAMESPACE}" \
  --docker-server="${REGISTRY}" \
  --docker-username="${GITHUB_USERNAME}" \
  --docker-password="${IMAGE_PULL_SECRET}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Secret '${SECRET_NAME}' applied in namespace '${NAMESPACE}' for ${REGISTRY}"
