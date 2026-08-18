#!/usr/bin/env bash
# Tripwire for the tdx-metal-e2e lane: the CVM boot attaches a bait cloud-init
# disk, and with the node image's datasource pin the measured baked seed is the
# only cloud-init input, so the node must register under the baked hostname.
# The bait name means host user-data executed as root. Reads the guest cluster
# through /tmp/guest.kubeconfig.

set -euo pipefail
NODE=""
for _ in $(seq 1 30); do
  NODE=$(KUBECONFIG=/tmp/guest.kubeconfig kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [ -n "$NODE" ]; then break; fi
  sleep 10
done
echo "registered node name: $NODE"
case "$NODE" in
  c8s-node) ;;
  cidata-bait)
    echo "::error title=SECURITY REGRESSION::host-supplied cidata user-data reached cloud-init in the attested node CVM"
    exit 1 ;;
  *) echo "::error::node name '$NODE' is neither the baked c8s-node nor the cidata bait — first-boot initialisation changed; update this tripwire"; exit 1 ;;
esac
