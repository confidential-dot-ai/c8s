#!/usr/bin/env bash
# node-guest-image invariants gate, run by the node-guest-image-lint workflow.
# Runs from the repo root against the pinned confos checkout at ./confos.
#
# Inputs (env):
#   CONFOS_REF   pinned confos ref the workflow resolved; names the pass line.
#   EXPECT_IMMUTABLE_ROOT  1 once CONFOS_REF carries confos's immutable root
#                (state.d in its initrd); makes its absence an error.

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
# 'serial: confai-scratch' rides along: scratch-enforce powers the e2e VM off without it.
for marker in 'hostname: cidata-bait' 'assert the host cidata disk is inert' 'serial: confai-scratch'; do
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

# confos's root is immutable; the profile declares the directories it
# writes at runtime in usr/lib/confai/state.d, one path per line, read the
# way the confos initrd reads them (whole line = one path, CR stripped,
# leading slash tolerated). Each must exist in the built image or the
# initrd refuses to boot: accepted if baked under mkosi.extra or created
# under mkosi.sync's stage tree.
state_confs=$(ls "$ngi"/c8s/mkosi.extra/usr/lib/confai/state.d/*.conf 2>/dev/null || true)
if [ -z "$state_confs" ]; then
  echo "::error::no state.d/*.conf under $ngi/c8s/mkosi.extra/usr/lib/confai — the immutable root needs the profile's writable dirs declared"
  exit 1
fi
state_dirs=""
while read -r d || [ -n "$d" ]; do
  d="${d%$'\r'}"; d="${d#/}"
  case "$d" in "" | \#*) continue ;; esac
  if [ ! -d "$ngi/c8s/mkosi.extra/$d" ] && ! grep -qE "\"\\\$STAGE_DIR/$d(/|\")" "$ngi/c8s/mkosi.sync"; then
    echo "::error::state.d declares '$d', which is neither baked under $ngi/c8s/mkosi.extra nor created under mkosi.sync's \$STAGE_DIR; the confos initrd refuses to boot an image whose state.d names a missing dir"
    exit 1
  fi
  state_dirs="$state_dirs $d"
done < <(cat $state_confs)

# Every runtime write outside confos's own state dirs must sit under a
# declared entry or it surfaces as EROFS mid-boot. Writers are gathered
# mechanically: absolute /etc|/opt|/usr|/srv|/boot literals on write lines
# in the profile's scripts (and the tests' FRAG* mirrors), tmpfiles.d
# create/write entries, and hostPath / local-path "paths" in the baked
# manifests. Reads that share a line with a write verb can trip this; that
# is the cheap side to err on.
covered() {
  case "$1" in /var|/var/*|/home|/home/*|/root|/root/*|/tmp|/tmp/*|/run|/run/*) return 0 ;; esac
  for d in $state_dirs; do case "$1" in "/$d"|"/$d"/*) return 0 ;; esac; done
  return 1
}
writes=$( {
  grep -hE '(>|tee |mkdir |install |cp |mv |touch |rm |^FRAG[A-Z]*=)' \
       "$ngi"/c8s/mkosi.extra/usr/local/bin/*.sh "$ngi"/tests/lib.sh \
    | grep -vE '^[[:space:]]*#' | grep -oE '/(etc|opt|usr|srv|boot)/[A-Za-z0-9_./-]+' || true
  grep -hE '^[dDfFwLpc]\+? ' "$ngi"/c8s/mkosi.extra/etc/tmpfiles.d/*.conf \
    | awk '{print $2}' | grep -E '^/(etc|opt|usr|srv|boot)/' || true
  grep -hoE '(path: *|"paths":\[")/(etc|opt|usr|srv|boot)/[A-Za-z0-9_./-]+' \
       "$ngi"/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/*.yaml \
    | grep -oE '/(etc|opt|usr|srv|boot)/.*' || true
} | sort -u )
for w in $writes; do
  if ! covered "$w"; then
    echo "::error::$w is written at runtime (scripts / tmpfiles.d / baked manifests) but no state.d entry ($state_dirs) makes it writable under the immutable root"
    exit 1
  fi
done

# confos side. The parser this lint mirrors is pinned like the dm name
# above. Until CONFOS_REF carries the immutable root the declaration is
# inert (warning only); the bump PR sets EXPECT_IMMUTABLE_ROOT=1 in
# node-guest-image-lint.yml so a later confos drop of state.d fails here
# instead of reading as "older confos".
init=confos/mkosi/initrd/mkosi.extra/init
if grep -qF '/usr/lib/confai/state.d' "$init"; then
  for pin in '[ -d "/sysroot/$dir" ]' 'while read -r dir || [ -n "$dir" ]'; do
    if ! grep -qF "$pin" "$init"; then
      echo "::error::confos initrd changed how it reads state.d (missing: $pin); update this lint's parser to match, then re-pin"
      exit 1
    fi
  done
elif [ "${EXPECT_IMMUTABLE_ROOT:-0}" = 1 ]; then
  echo "::error::EXPECT_IMMUTABLE_ROOT=1 but confos at CONFOS_REF $CONFOS_REF has no state.d in its initrd"
  exit 1
else
  echo "::warning::confos at CONFOS_REF $CONFOS_REF predates the immutable root (no state.d in its initrd): the state.d declaration is inert until the ref is bumped — then set EXPECT_IMMUTABLE_ROOT=1 in node-guest-image-lint.yml"
fi

# The scratch floor is prose in the README and a sector count in the gate;
# a bump must touch both.
if ! grep -qF 'MIN_SECTORS=125000000' "$ngi/c8s/mkosi.extra/usr/local/bin/scratch-enforce.sh" \
   || ! grep -qF 'at least 64G' "$ngi/README.md"; then
  echo "::error::scratch floor drifted: scratch-enforce.sh MIN_SECTORS (64G = 125000000 sectors) and the README's 'at least 64G' must move together"
  exit 1
fi

echo "all node-guest-image invariants hold at CONFOS_REF $CONFOS_REF"
