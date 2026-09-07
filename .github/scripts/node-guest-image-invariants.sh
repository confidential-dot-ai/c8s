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

# The locked image must keep the kubelet debugging handlers off (no kubectl
# exec/attach/logs for the kubeconfig holder); only the C8S_DEV=1 build may
# turn them back on, and only through the sync-rendered drop-in.
if ! grep -qxF '  - enable-debugging-handlers=false' "$rke2_config"; then
  echo "::error::$rke2_config must pin kubelet-arg enable-debugging-handlers=false"
  exit 1
fi
if grep -rq 'enable-debugging-handlers=true' "$ngi/c8s/mkosi.extra"; then
  echo "::error::a baked file re-enables the kubelet debugging handlers; only mkosi.sync may, for dev=1"
  exit 1
fi
if ! grep -q -- '--sync-input "dev=\${C8S_DEV:-0}"' "$ngi/build" \
   || ! grep -q 'SYNC_INPUTS/dev' "$ngi/c8s/mkosi.sync"; then
  echo "::error::the dev sync-input must flow from $ngi/build (C8S_DEV) into mkosi.sync"
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
# 'serial: confai-scratch' rides along: scratch-enforce powers the e2e VM off without it.
# 'wait for the baked chart install' is a second c8s-local patch: the node
# image now installs the c8s chart itself at boot (baked HelmChart c8s), so
# the lane waits on helm-install-c8s instead of running `c8s install`
# (which now refuses against a baked cluster — preflightNotBakedNode).
for marker in 'hostname: cidata-bait' 'assert the host cidata disk is inert' 'serial: confai-scratch' \
              'wait for the baked chart install' 'job/helm-install-c8s'; do
  if ! grep -qF "$marker" .github/workflows/tdx-metal-e2e.yml; then
    echo "::error::tdx-metal-e2e.yml lost '$marker': re-vendoring dropped a c8s-local patch — re-apply it"
    exit 1
  fi
done

# scratch-enforce keys on the initrd's dm mapping name; a confos rename
# would power off every healthy node. Pin the contract at the pinned ref.
if ! grep -qF '"$SCRATCH_DEV" scratch' confos/mkosi/initrd/mkosi.extra/init; then
  echo "::error::confos initrd no longer opens the scratch disk as dm 'scratch'; scratch-enforce.sh gates on that name — update both together"
  exit 1
fi

# The scratch floor is prose in the README and a sector count in the gate;
# a bump must touch both.
if ! grep -qF 'MIN_SECTORS=125000000' "$ngi/c8s/mkosi.extra/usr/local/bin/scratch-enforce.sh" \
   || ! grep -qF 'at least 64G' "$ngi/README.md"; then
  echo "::error::scratch floor drifted: scratch-enforce.sh MIN_SECTORS (64G = 125000000 sectors) and the README's 'at least 64G' must move together"
  exit 1
fi

# psa-config.yaml exempts only the platform namespaces that need privileged
# pods, and the baked policy that stops tenants relabelling their namespaces
# keeps naming `restricted`, denying, and failing closed.
psa="$ngi/c8s/mkosi.extra/etc/rancher/rke2/psa-config.yaml"
vap="$ngi/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/psa-level-policy.yaml"
exempt=$(sed -n '/^[[:space:]]*namespaces:/,/^[[:space:]]*[^[:space:]-]/s/^[[:space:]]*-[[:space:]]*//p' "$psa")
if [ "$exempt" != "$(printf 'kube-system\nlocal-path-storage')" ]; then
  echo "::error::$psa must exempt exactly kube-system and local-path-storage from restricted PodSecurity; got: $(echo "$exempt" | tr '\n' ' ')"
  exit 1
fi
if ! grep -q 'enforce: "restricted"' "$psa"; then
  echo "::error::$psa must default to enforce: restricted"
  exit 1
fi
if ! grep -q "== 'restricted'" "$vap" || ! grep -q "== 'latest'" "$vap"; then
  echo "::error::$vap must pin the enforce label to restricted and enforce-version to latest"
  exit 1
fi
if ! grep -q 'failurePolicy: Fail' "$vap"; then
  echo "::error::$vap must fail closed (failurePolicy: Fail)"
  exit 1
fi
if ! grep -q 'resources: \["namespaces", "namespaces/status", "namespaces/finalize"\]' "$vap" \
   || ! grep -q 'operations: \["CREATE", "UPDATE"\]' "$vap"; then
  echo "::error::$vap must match namespace CREATE and UPDATE on the resource and its status/finalize subresources, which also carry labels"
  exit 1
fi
if ! grep -q '^    - Deny$' "$vap"; then
  echo "::error::$vap binding must deny, not warn or audit"
  exit 1
fi

# The baked chart install (c8s-chart.<platform>.yaml.in -> c8s-chart.yaml at
# build time, node-guest-image/c8s/mkosi.sync render_chart_helmchart) must
# never be createNamespace: true, on either platform's golden file —
# c8s-namespace.yaml bakes c8s-system with the privileged PSA labels ahead of
# the HelmChart, following local-path-storage's precedent (baked namespace,
# not chart-managed), and a createNamespace: true HelmChart would create it
# WITHOUT those labels, letting restricted PodSecurity deny the chart's own
# privileged pods on first install. Both golden files are generated by
# cmd/c8s's TestNodeChartGoldenFiles (go test ./cmd/c8s/ -run
# TestNodeChartGoldenFiles, already run as part of `go test ./...` in CI) —
# this script only checks the checked-in result, not regenerate-and-diff.
for platform in tdx snp; do
  chart_tmpl="$ngi/c8s/c8s-chart.${platform}.yaml.in"
  [ -f "$chart_tmpl" ] || { echo "::error::baked chart template $chart_tmpl not found"; exit 1; }
  if ! grep -qE '^\s*createNamespace:\s*false\s*$' "$chart_tmpl"; then
    echo "::error::$chart_tmpl must set createNamespace: false — c8s-namespace.yaml bakes the namespace with its privileged PSA labels instead"
    exit 1
  fi

  # The template must stay outside mkosi.extra (rendered, not raw-baked) —
  # same reasoning as the NRI floor template check above: a raw copy under
  # mkosi.extra would ship literal @TOKEN@ placeholders no HelmChart
  # controller can parse, and never get the resolved digests mkosi.sync
  # substitutes.
  if find "$ngi/c8s/mkosi.extra" -name "c8s-chart.${platform}.yaml.in" 2>/dev/null | grep -q .; then
    echo "::error::c8s-chart.${platform}.yaml.in must not live under mkosi.extra — it is a template mkosi.sync renders, not a file to bake raw"
    exit 1
  fi
done

# c8s-namespace.yaml (baked ahead of the chart) must match namespaceManifest()
# in cmd/c8s/install.go — the same privileged PodSecurity labels a live
# install applies to its release namespace, so the chart's own privileged
# pods (nri-image-policy's baked installer pins, attestation-api, ratls-mesh)
# admit in c8s-system before any operator-driven relabel could run. Asserted
# by cmd/c8s's TestBakedNamespaceMatchesNamespaceManifest (go test ./cmd/c8s/
# -run TestBakedNamespaceMatchesNamespaceManifest, already run as part of
# `go test ./...` in CI) — this script only checks the file exists.
c8s_ns="$ngi/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/c8s-namespace.yaml"
[ -f "$c8s_ns" ] || { echo "::error::baked namespace manifest $c8s_ns not found"; exit 1; }

# c8s-chart-values.service must actually run: the preset creates the
# .requires symlink that makes rke2-server block on it (the gpu-cc-enforce.service
# precedent) — enabled in the preset alone, with no matching RequiredBy=, is
# a unit nothing waits on.
preset="$ngi/c8s/mkosi.extra/usr/lib/systemd/system-preset/50-rke2.preset"
values_svc="$ngi/c8s/mkosi.extra/etc/systemd/system/c8s-chart-values.service"
[ -f "$values_svc" ] || { echo "::error::$values_svc not found"; exit 1; }
if ! grep -qxF 'enable c8s-chart-values.service' "$preset"; then
  echo "::error::$preset must enable c8s-chart-values.service"
  exit 1
fi
if ! grep -qF 'RequiredBy=rke2-server.service' "$values_svc"; then
  echo "::error::$values_svc must be RequiredBy=rke2-server.service, or the preset's enable is a no-op nothing blocks on"
  exit 1
fi
if ! grep -qF 'ConditionPathExists=/run/confos/role-server' "$values_svc"; then
  echo "::error::$values_svc must gate on /run/confos/role-server — agent boots have no server manifests dir to write into"
  exit 1
fi

# Phase 0b: c8s-chart-values.sh mounts the optional opkeydata values.yaml
# fragment the same locked-down way rke2-role.sh mounts joindata —
# iso9660, read-only, and nodev/nosuid/noexec so a host-controlled disk
# gets no more than a plain file read out of the mount.
values_sh="$ngi/c8s/mkosi.extra/usr/local/bin/c8s-chart-values.sh"
[ -f "$values_sh" ] || { echo "::error::$values_sh not found"; exit 1; }
if ! grep -qE 'mount -t iso9660 -o ro,nodev,nosuid,noexec .*OPKEYDATA_DEV.*OPKEYDATA_MNT' "$values_sh"; then
  echo "::error::$values_sh must mount opkeydata with '-t iso9660 -o ro,nodev,nosuid,noexec', the same options rke2-role.sh uses for joindata"
  exit 1
fi
if ! grep -qE '^\s*timeout 10 mount' "$values_sh"; then
  echo "::error::$values_sh must bound the opkeydata mount with 'timeout 10', or a wedged host-controlled disk hangs the boot"
  exit 1
fi

echo "all node-guest-image invariants hold at CONFOS_REF $CONFOS_REF"
