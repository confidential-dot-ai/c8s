#!/usr/bin/env bash
# node-guest-image invariants gate, run by the node-guest-image-lint workflow.
# Runs from the repo root against the pinned confos checkout at ./confos.
#
# Inputs (env):
#   CONFOS_REF   pinned confos ref the workflow resolved; names the pass line.

set -euo pipefail

: "${CONFOS_REF:?CONFOS_REF must be set}"
ngi=node-guest-image

# kernel/c8s.config must be a superset of confos kernel/gpu.config:
# only one --kernel-config-fragment is accepted per build, so the
# c8s fragment duplicates the gpu lines verbatim. Catch drift when
# gpu.config changes under the pinned CONFOS_REF.
missing=$(grep -E '^CONFIG_|^# CONFIG_.* is not set$' confos/kernel/gpu.config \
          | grep -vFxf "$ngi/kernel/c8s.config" || true)
if [ -n "$missing" ]; then
  echo "::error::$ngi/kernel/c8s.config must contain every effective line of confos kernel/gpu.config; missing:"
  echo "$missing"
  exit 1
fi

# c8s-dev.config (C8S_DEV=1 demo builds) is the union of c8s.config
# and confos dev.config, committed verbatim for the same one-fragment
# reason.
for src in "$ngi/kernel/c8s.config" confos/kernel/dev.config; do
  missing=$(grep -E '^CONFIG_|^# CONFIG_.* is not set$' "$src" \
            | grep -vFxf "$ngi/kernel/c8s-dev.config" || true)
  if [ -n "$missing" ]; then
    echo "::error::$ngi/kernel/c8s-dev.config must contain every effective line of $src; missing:"
    echo "$missing"
    exit 1
  fi
done

# The baked NRI floor is a template whose always_allow entries are
# @-tokens the sync fills with ref-resolved digests; a hardcoded
# sha256 would bake a stale digest the fail-closed floor can't
# reconcile with the ref. The marked block is exempt: systemfloor
# generates it from the pinned RKE2 airgap bundles (see mkosi.sync).
policy="$ngi/c8s/image-policy.yaml.in"
[ -f "$policy" ] || { echo "::error::NRI floor template $policy not found"; exit 1; }
if sed '/# BEGIN rke2 system floor/,/# END rke2 system floor/d' "$policy"               | grep -qE '^[[:space:]]*"sha256:[a-f0-9]{64}"[[:space:]]*:'; then
  echo "::error::$policy has a hardcoded always_allow digest outside the generated system floor; use @NRI_DIGEST@/@CDS_DIGEST@ tokens (rendered from C8S_REF by mkosi.sync)"
  exit 1
fi

# The c8s node is normally nested in an outer RKE2 cluster: its pod
# CIDR must not fall back to the outer cluster's default, and
# Cilium's pool must exactly match the RKE2 server setting or pods
# receive unroutable IPs.
rke2_config="$ngi/c8s/mkosi.extra/etc/rancher/rke2/config.yaml"
cilium_config="$ngi/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/rke2-cilium-config.yaml"
rke2_pod_cidr=$(sed -n 's/^cluster-cidr:[[:space:]]*//p' "$rke2_config")
cilium_pod_cidr=$(sed -n '/clusterPoolIPv4PodCIDRList:/,/^[^[:space:]]/s/^[[:space:]]*-[[:space:]]*//p' "$cilium_config" | head -n 1)
if [ -z "$rke2_pod_cidr" ] || [ "$rke2_pod_cidr" = "10.42.0.0/16" ]; then
  echo "::error::c8s RKE2 cluster-cidr must be explicit and must not overlap the outer RKE2 default"
  exit 1
fi
if [ "$rke2_pod_cidr" != "$cilium_pod_cidr" ]; then
  echo "::error::c8s RKE2 cluster-cidr ($rke2_pod_cidr) must match Cilium IPAM ($cilium_pod_cidr)"
  exit 1
fi

# The rke2-role drop-ins only bind if mkosi.sync keeps staging the
# rke2 tarball's units under /usr/local (systemd's search path);
# the systemd harness installs its fakes at the same prefix.
if ! grep -q 'tar -xzf .* -C "\$STAGE_DIR/usr/local"' "$ngi/c8s/mkosi.sync"; then
  echo "::error::mkosi.sync no longer stages rke2 under /usr/local; rke2-role drop-ins and the systemd harness depend on that unit dir"
  exit 1
fi

# The node image disables cloud-init, so the build bakes no seed.
# tests/cloud-init-disabled.sh owns the marker invariant itself.
if grep -q -- '--cloud-init' "$ngi/build"; then
  echo "::error::$ngi/build bakes a cloud-init seed; the node image disables cloud-init instead"
  exit 1
fi
# tdx-metal-e2e.yml is vendored from confidential-ci; the bait +
# tripwire are a c8s-local patch until the source takes the same
# edit — a re-vendor would silently delete them.
for marker in 'hostname: cidata-bait' 'assert the host cidata disk is inert'; do
  if ! grep -qF "$marker" .github/workflows/tdx-metal-e2e.yml; then
    echo "::error::tdx-metal-e2e.yml lost '$marker': re-vendoring dropped the cidata bait/tripwire — re-apply the c8s-local patch"
    exit 1
  fi
done

echo "all node-guest-image invariants hold at CONFOS_REF $CONFOS_REF"
