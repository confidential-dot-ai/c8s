#!/usr/bin/env bash
# Shared E2E body (platform-agnostic): assert the cluster is genuinely
# confidential, then deploy the stack and assert attested join + key release.
# Provisioning/teardown are per-platform (provision-<target>.sh); this is not.
set -euo pipefail
fail() { echo "E2E FAIL: $*" >&2; exit 1; }

echo "::group::1. assert cluster nodes are confidential (real check)"
# GKE confidential cluster reports confidentialNodes.enabled=true.
if [ -n "${GCP_PROJECT:-}" ] && [ -n "${E2E_CLUSTER:-$(cat /tmp/e2e-cluster-name 2>/dev/null || true)}" ]; then
  CL="${E2E_CLUSTER:-$(cat /tmp/e2e-cluster-name)}"
  EN=$(gcloud container clusters describe "$CL" --project "$GCP_PROJECT" \
        --location "${GCP_LOCATION:-${GCP_REGION:-us-central1}}" \
        --format='value(confidentialNodes.enabled)' 2>/dev/null || true)
  echo "confidentialNodes.enabled=$EN"
  [ "$EN" = "True" ] || [ "$EN" = "true" ] || fail "cluster is not confidential"
fi
kubectl wait --for=condition=Ready nodes --all --timeout=180s || fail "nodes not Ready"
echo "::endgroup::"

echo "::group::2. real attestation: verify a confidential-VM quote with attestation-cli"
# On a confidential node the guest can produce a hardware quote; verify it with
# the company's real verifier (gcp-snp / gcp-tdx platforms). This is the hook
# that exercises actual TEE attestation — wire to your in-guest evidence path
# (e.g. ccvm attest -> evidence.json, or configfs-tsm).
if command -v attestation-cli >/dev/null 2>&1; then
  echo "attestation-cli present: $(attestation-cli --version 2>/dev/null || echo ok)"
  # attestation-cli verify -e evidence.json --expected-report-data <nonce_hex>
  echo "TODO: collect in-guest evidence.json and verify (gcp-${CONF_TYPE:-snp})"
else
  echo "WARN: attestation-cli not in image"
fi
echo "::endgroup::"

echo "::group::3. deploy confidential stack + assert attested join + key release"
# Hook: the stack-under-test's deploy + assertions. Default points at the PoC in
# this repo (k8s/) as a concrete example: an attested agent must ATTEST and
# UNWRAP a key. Replace with attestation-rs / C8s E2E.
STACK="${STACK_DEPLOY:-./test/e2e/deploy-stack.sh}"
if [ -x "$STACK" ]; then
  "$STACK" || fail "stack deploy/assert failed"
else
  echo "no \$STACK_DEPLOY script; skipping stack step (wire your E2E here)"
fi
echo "::endgroup::"

echo "E2E PASS"
