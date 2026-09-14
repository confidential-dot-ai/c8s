#!/usr/bin/env bash
# node-guest-image invariants gate, run by the node-guest-image-lint workflow.
# Runs from the repo root against the pinned confos checkout at ./confos.
#
# Inputs (env):
#   CONFOS_REF   pinned confos ref the workflow resolved; names the pass line.
#   EXPECT_IMMUTABLE_ROOT  defaults to 1; requires state.d in confos's initrd.
#                Set to 0 only when inspecting a legacy confos checkout.

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

# CONFIG_MODULES=y is a c8s-only widening (the base kernel compiles modules
# out, which is why confos's 99-kspp-hardening.conf omits the key). The
# profile must therefore latch kernel.modules_disabled itself: the gpu
# profile's latch is absent from the GPU-less composition.
latch="$ngi/c8s/mkosi.extra/etc/systemd/system/c8s-modules-latch.service"
preset="$ngi/c8s/mkosi.extra/usr/lib/systemd/system-preset/50-rke2.preset"
if grep -qx 'CONFIG_MODULES=y' "$ngi/kernel/c8s.config"; then
  if ! grep -qF 'kernel.modules_disabled=1' "$latch"; then
    echo "::error::$ngi/kernel/c8s.config sets CONFIG_MODULES=y, so $latch must set kernel.modules_disabled=1"
    exit 1
  fi
  if ! grep -qx 'enable c8s-modules-latch.service' "$preset"; then
    echo "::error::$preset must enable c8s-modules-latch.service; an unenabled latch never runs"
    exit 1
  fi
  if ! grep -qx 'RequiredBy=rke2-server.service rke2-agent.service' "$latch"; then
    echo "::error::$latch must be RequiredBy the rke2 pair so rke2 cannot start with modules still loadable"
    exit 1
  fi
fi

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
# The shared TDX lifecycle originated in confidential-ci, with c8s-local
# cidata, AppArmor and private-import checks. Preserve them on re-vendor.
# Exact-source checkout/evidence stay in the automatic-only wrapper:
# staged testing must not gain a path to that privileged checkout boundary.
# 'serial: confai-scratch' rides along: scratch-enforce powers the e2e VM off without it.
tdx_runtime=.github/actions/tdx-metal-e2e/action.yml
for marker in 'hostname: cidata-bait' 'assert the host cidata disk is inert' 'serial: confai-scratch' \
              'bash node-guest-image/tests/apparmor-runtime-test.sh' \
              'import the exact published image into a private root PVC' \
              'bash .github/scripts/tdx-image-acceptance.sh pvc'; do
  if ! grep -qF "$marker" "$tdx_runtime"; then
    echo "::error::$tdx_runtime lost '$marker': re-vendoring dropped a c8s-local patch — re-apply it"
    exit 1
  fi
done
for marker in 'image_acceptance_artifact:' 'bash .github/scripts/tdx-image-acceptance.sh validate'; do
  if ! grep -qF "$marker" .github/workflows/tdx-image-acceptance.yml; then
    echo "::error::tdx-image-acceptance.yml lost '$marker': exact-image evidence is required"
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
  # Numeric descriptor duplication does not write a filesystem path. Remove
  # only that token; keep other redirects and write verbs on the same line.
  sed -E 's/[0-9]*[<>]&[0-9]+([[:space:];|&()]|$)/\1/g' \
      "$ngi"/c8s/mkosi.extra/usr/local/bin/*.sh "$ngi"/tests/lib.sh \
    | grep -E '(>|tee |mkdir |install |cp |mv |touch |rm |^FRAG[A-Z]*=)' \
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
# above. Missing immutable-root support fails by default, including local
# runs; the explicit compatibility override only supports legacy inspection.
init=confos/mkosi/initrd/mkosi.extra/init
if grep -qF '/usr/lib/confai/state.d' "$init"; then
  for pin in '[ -d "/sysroot/$dir" ]' 'while read -r dir || [ -n "$dir" ]'; do
    if ! grep -qF "$pin" "$init"; then
      echo "::error::confos initrd changed how it reads state.d (missing: $pin); update this lint's parser to match, then re-pin"
      exit 1
    fi
  done
elif [ "${EXPECT_IMMUTABLE_ROOT:-1}" = 1 ]; then
  echo "::error::EXPECT_IMMUTABLE_ROOT=1 but confos at CONFOS_REF $CONFOS_REF has no state.d in its initrd"
  exit 1
else
  echo "::warning::EXPECT_IMMUTABLE_ROOT=$EXPECT_IMMUTABLE_ROOT permits confos at CONFOS_REF $CONFOS_REF without state.d in its initrd; the profile's state.d declaration is inert"
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
psa_gate="$ngi/c8s/mkosi.extra/usr/local/bin/psa-ready.sh"
cred_release="$ngi/c8s/mkosi.extra/etc/systemd/system/cred-release.service"
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
if [ ! -x "$psa_gate" ]; then
  echo "::error::$psa_gate must be executable"
  exit 1
fi
if ! grep -qxF 'ExecStartPre=/usr/local/bin/psa-ready.sh' "$cred_release"; then
  echo "::error::$cred_release must keep credential release behind the measured PodSecurity readiness gate"
  exit 1
fi
for required in \
  'get validatingadmissionpolicy "$policy"' \
  'get validatingadmissionpolicybinding "$policy"' \
  '--as="$probe_user" create --dry-run=server' \
  'probe_namespace restricted' \
  'probe_namespace privileged'; do
  if ! grep -qF -- "$required" "$psa_gate"; then
    echo "::error::$psa_gate is missing required live admission probe: $required"
    exit 1
  fi
done

# Check requested and resolved settings, including CONFIG_LSM and duplicates.
# The build uses the same checker on its .config; apparmor-enforce.service
# separately gates RKE2 on the booted LSM/parser.
for config in c8s.config c8s-dev.config config-x86_64-c8s.snapshot; do
  bash "$ngi/check-apparmor-config.sh" "$ngi/kernel/$config"
done
grep -qE '^\s*apparmor\s*$' "$ngi/c8s/mkosi.conf" \
  || { echo "::error::$ngi/c8s/mkosi.conf must ship the apparmor package (apparmor_parser)"; exit 1; }
grep -qFx 'disable apparmor.service' "$ngi/c8s/mkosi.extra/usr/lib/systemd/system-preset/50-rke2.preset" \
  || { echo "::error::50-rke2.preset must disable apparmor.service (only the parser is wanted)"; exit 1; }

echo "all node-guest-image invariants hold at CONFOS_REF $CONFOS_REF"
