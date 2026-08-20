# shellcheck shell=sh
# c8s host sweep — run by `c8s uninstall` as a privileged init container on
# every linux node (a short-lived kubectl-applied DaemonSet; see
# cmd/c8s/uninstall.go).
#
# `helm uninstall` already drives the supported cleanup: the kata-deploy
# preStop removes /opt/kata and deregisters the runtime, the chart's
# pre-delete hooks remove the NRI plugin and volumed mappings, and the mesh's
# preStop strips its traffic interception. Every one of those is best-effort:
# hooks need a release healthy enough to run them, a preStop is bounded by
# the pod's termination grace period (and the runtime restart it triggers can
# kill the pod mid-cleanup), the mesh preStop deliberately keeps its
# fail-closed guard, and none of them knows about the c8s-side artifacts
# (pulled guest images, the RKE2 containerd-prep template). This sweep is the
# idempotent last word and runs on every uninstall, whatever the release's
# shape: leftovers may come from a previous install of a different shape,
# which this release's values cannot see.
#
# Baked node image exception: on the c8s node image the NRI plugin, its floor
# config, the containerd drop-in, and the managed RKE2 containerd template
# are baked into the measured image at the same paths the chart uses. They
# are node-image state, not release state — deleting them strips the node's
# fail-closed image admission until reimage — so the NRI and template steps
# below are skipped when the baked-only nri-node-ip.service unit exists.
#
# Fatal vs warn: containerd config removal, the runtime restart, the nydus
# unit, and the guest-dir steps fail the sweep (the CLI then keeps the
# DaemonSet so its logs survive). Per-object netfilter failures warn and
# continue; a host with no iptables at all fails the sweep at the end, after
# every other step ran.
#
# Env (all required unless noted; set by `c8s uninstall` from the release's
# computed values):
#   HOST_CONTAINERD_DIR    — host containerd config directory (kata.distro)
#   GUEST_IMAGE_DIR        — dir the kata-image-puller pulled kata-guest-base
#                            into (kata.guestImage.hostPath)
#   GUEST_IMAGE_DIR_NVIDIA — GPU guest image dir (kata.gpu.guestImage.hostPath);
#                            empty only for a pre-GPU release = skip
#   RKE2_PREP              — "true" when the install ran the RKE2 containerd-prep
#                            initContainer whose template/lock this sweep owns
#   RESTART_COMMAND        — host runtime restart, run detached via systemd-run
#   NRI_CONTAINERD_DIR     — containerd config dir the NRI installer targeted
#                            (nriImagePolicy.distro)
#   NRI_PLUGIN_DIR         — NRI plugin directory (nriImagePolicy.hostPaths.pluginDir)
#   NRI_PLUGIN_FILENAME    — plugin filename inside it (nriImagePolicy.pluginFilename)
#   NRI_CONFIG_DIR         — plugin config dir (nriImagePolicy.hostPaths.configDir)
#   NRI_RUNTIME_DIR        — plugin runtime dir (nriImagePolicy.hostPaths.runtimeDir)
#   NRI_CACHE_DIR          — plugin cache dir (nriImagePolicy.hostPaths.cacheDir)
set -eu

echo "==> c8s host sweep starting"

# Independent guard mirroring cmd/c8s/uninstall.go's validateSweepPath: the
# GUEST_IMAGE_DIR* values come from Helm release values and are deleted with
# `rm -rf /host<dir>`, so a hostile or malformed value ("", "/", "..", "/host")
# would otherwise destroy the mounted host filesystem. Refuse to sweep anything
# that is not a dedicated c8s guest-image directory strictly under /var/lib/c8s.
assert_safe_guest_dir() {
  case "$1" in
    */../* | *..) echo "refusing to sweep guest image dir containing '..': '$1'" >&2; exit 1 ;;
  esac
  case "$1" in
    /var/lib/c8s/?*) : ;;
    *) echo "refusing to sweep unsafe guest image dir (must be under /var/lib/c8s): '$1'" >&2; exit 1 ;;
  esac
}

CONTAINERD_DIR="/host${HOST_CONTAINERD_DIR}"
NRI_CONTAINERD_DIR_HOST="/host${NRI_CONTAINERD_DIR}"
config_changed=0
sweep_failed=0

baked_node=0
if [ -f /host/etc/systemd/system/nri-node-ip.service ]; then
  baked_node=1
  echo "c8s node image detected — the baked NRI stack and managed containerd template are image state; leaving them"
fi

# == Phase 1: containerd configuration =======================================
# Everything that needs a runtime restart is removed first, the restart runs
# once (phase 2), and only then are host artifacts deleted (phase 3): with
# the registration gone, no interruption can leave the fail-closed NRI
# validator requiring a plugin whose binary is already deleted.

# 1. kata-deploy's containerd runtime drop-in. Still present only when the
#    preStop cleanup was cut short — remove it from whichever schema-versioned
#    drop-in dir it landed in; the restart below deregisters the runtimes.
#    The `imports` line referencing the drop-in dir is left alone: with no
#    matching files the glob is inert, kata-deploy owns that edit on k8s, and
#    on RKE2 the next config regen drops it once the managed template (step 3)
#    is gone.
for d in config-v3.toml.d config.toml.d; do
  for n in kata-deploy.toml zz-c8s-kata-annotations.toml; do
    f="${CONTAINERD_DIR}/${d}/${n}"
    if [ -f "$f" ]; then
      rm -f "$f"
      config_changed=1
      echo "containerd drop-in removed: $f"
    fi
  done
done

# 2. The NRI image-policy's containerd registration: the standalone drop-in
#    (rke2), or the sentinel-delimited block in config.toml (k8s patch mode).
#    Mirrors the chart's files/scripts/uninstall.sh.
if [ "$baked_node" = "0" ]; then
  for d in config-v3.toml.d config.toml.d; do
    f="${NRI_CONTAINERD_DIR_HOST}/${d}/nri-image-policy.toml"
    if [ -f "$f" ]; then
      rm -f "$f"
      config_changed=1
      echo "containerd drop-in removed: $f"
    fi
  done
  MARK_BEGIN='# BEGIN c8s-nri-image-policy (managed)'
  MARK_END='# END c8s-nri-image-policy (managed)'
  main_config="${NRI_CONTAINERD_DIR_HOST}/config.toml"
  if [ -f "$main_config" ] && grep -qF "$MARK_BEGIN" "$main_config"; then
    awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
      $0==b { skip=1; next }
      $0==e { skip=0; next }
      !skip { print }
    ' "$main_config" > "$main_config.tmp"
    mv -f "$main_config.tmp" "$main_config"
    echo "containerd config block removed from $main_config"
    config_changed=1
  fi
fi

# 3. RKE2 containerd-prep leftovers: the sentinel-marked managed template
#    (which would re-add the drop-in import on every RKE2 config regen) and
#    the prep lock file. Only a sentinel-marked template is removed — an
#    operator-owned template is never touched, and a legacy pre-sentinel
#    template is left for the prep's own next-install self-repair rather than
#    deleted on content guesswork. On a baked node image the template is
#    image state (same sentinel by design) and stays.
if [ "${RKE2_PREP}" = "true" ]; then
  if [ "$baked_node" = "0" ]; then
    SENTINEL='c8s-containerd-prep:managed-template'
    for t in config-v3.toml.tmpl config.toml.tmpl; do
      f="${CONTAINERD_DIR}/${t}"
      [ -f "$f" ] || continue
      if grep -qF "$SENTINEL" "$f"; then
        rm -f "$f"
        echo "managed containerd template removed: $f"
      else
        echo "leaving ${t}: not the c8s-managed template"
      fi
    done
  fi
  rm -f "${CONTAINERD_DIR}/.c8s-containerd-prep.lock"
fi

# == Phase 2: one runtime restart ============================================
# Detached via systemd-run: restarting rke2/containerd kills this pod's own
# shim, and a restart in the pod's process tree dies with it mid-restart,
# which on a sole control-plane node can wedge the rke2 bootstrap.
if [ "$config_changed" = "1" ]; then
  echo "restarting containerd (detached via systemd-run): ${RESTART_COMMAND}"
  # shellcheck disable=SC2086
  nsenter -t 1 -m -u -i -n -p -- \
    systemd-run --collect --description="c8s host sweep containerd restart" \
    sh -c "${RESTART_COMMAND}"
fi

# == Phase 3: host artifacts =================================================

# 4. nydus-for-kata-tee: kata-deploy's EXPERIMENTAL_SETUP_SNAPSHOTTER
#    installs this host unit; its own cleanup removes it only when the
#    preStop completes. Stop it while its binary under /opt/kata still
#    exists. /var/lib/nydus-for-kata-tee stays on purpose: containerd's
#    meta.db keeps nydus snapshot records, and wiping the backend behind
#    them makes the next install's pulls fail with "target snapshot already
#    exists" (see kata-deploy's uninstall_nydus_snapshotter).
NYDUS_UNIT=/host/etc/systemd/system/nydus-for-kata-tee.service
if [ -f "$NYDUS_UNIT" ]; then
  nsenter -t 1 -m -u -i -n -p -- systemctl disable --now nydus-for-kata-tee.service
  rm -f "$NYDUS_UNIT"
  nsenter -t 1 -m -u -i -n -p -- systemctl daemon-reload
  echo "nydus-for-kata-tee.service removed"
else
  echo "nydus-for-kata-tee.service already absent"
fi

# 5. The kata-static payload (runtime, shim, QEMU/CLH, guest kernel + images)
#    and the per-shim symlinks kata-deploy installs beside it. /opt/kata also
#    carries the image-puller's <cfg>.upstream snapshot, so that goes too.
if [ -d /host/opt/kata ]; then
  rm -rf /host/opt/kata
  echo "/opt/kata removed"
else
  echo "/opt/kata already absent"
fi
rm -f /host/usr/local/bin/containerd-shim-kata-*-v2

# 6. The guest image dirs (multi-GB; nothing else cleans them up). Presence-
#    gated: a non-kata release never wrote these, so an absent custom path is
#    a no-op while an existing unsafe one still fails closed.
sweep_guest_dir() {
  dir="${1%/}"
  if [ ! -d "/host${dir}" ]; then
    echo "guest image dir already absent: ${dir}"
    return 0
  fi
  assert_safe_guest_dir "$dir"
  rm -rf "/host${dir}"
  echo "guest image dir removed: ${dir}"
}

sweep_guest_dir "${GUEST_IMAGE_DIR}"
GUEST_IMAGE_DIR_NVIDIA="${GUEST_IMAGE_DIR_NVIDIA:-}"
if [ -n "${GUEST_IMAGE_DIR_NVIDIA}" ]; then
  sweep_guest_dir "${GUEST_IMAGE_DIR_NVIDIA}"
fi

# 7. The NRI plugin's host artifacts: the binary, its boot config, the health
#    socket dir, and the allowlist cache. The rm -rf targets must carry the
#    plugin's own directory name — the values come from the release and a
#    bare parent dir (/var/run, /var/lib) is never deleted.
if [ "$baked_node" = "0" ]; then
  plugin_glob_dir="/host${NRI_PLUGIN_DIR}"
  if [ -d "$plugin_glob_dir" ]; then
    exact="${plugin_glob_dir}/${NRI_PLUGIN_FILENAME}"
    if [ -f "$exact" ]; then
      rm -f "$exact"
      echo "NRI plugin removed: $exact"
    fi
    for f in "$plugin_glob_dir"/*-nri-image-policy; do
      [ -f "$f" ] || continue
      rm -f "$f"
      echo "NRI plugin removed: $f"
    done
  fi
  rm -f "/host${NRI_CONFIG_DIR}/image-policy.yaml"
  case "$NRI_RUNTIME_DIR" in
    */nri-image-policy) rm -rf "/host${NRI_RUNTIME_DIR}" ;;
    *) [ ! -e "/host${NRI_RUNTIME_DIR}" ] || echo "leaving NRI runtime dir with a custom name: ${NRI_RUNTIME_DIR}" ;;
  esac
  case "$NRI_CACHE_DIR" in
    */nri-image-policy) rm -rf "/host${NRI_CACHE_DIR}" ;;
    *) [ ! -e "/host${NRI_CACHE_DIR}" ] || echo "leaving NRI cache dir with a custom name: ${NRI_CACHE_DIR}" ;;
  esac
fi

# 8. RATLS-MESH netfilter state. The mesh's preStop removes only the traffic
#    interception (--keep-guard keeps the fail-closed filter chains and their
#    ipsets by design), and a mesh pod that never ran preStop leaves
#    everything — including the OUTPUT redirect that sends host-originated
#    pod traffic to a dead proxy port. Names are the mesh's fixed contract
#    (internal/cmds/ratlsmesh/iptables.go; pinned by a Go test). Both address
#    families; jumps before chains, chains before ipsets (a referenced object
#    cannot be deleted). Prefers the nft frontend the mesh always wrote.
# shellcheck disable=SC2016
mesh_cleanup_script='
set -u
ipt4=""
ipt6=""
for b in iptables-nft iptables; do
  if command -v "$b" >/dev/null 2>&1; then ipt4="$b"; break; fi
done
for b in ip6tables-nft ip6tables; do
  if command -v "$b" >/dev/null 2>&1; then ipt6="$b"; break; fi
done
if [ -z "$ipt4" ] && [ -z "$ipt6" ]; then
  echo "ERROR: no iptables/ip6tables on this host — cannot sweep RATLS-MESH netfilter state" >&2
  exit 1
fi

clean_family() {
  B="$1"
  while "$B" -t nat -D OUTPUT -j RATLS-MESH 2>/dev/null; do :; done
  while "$B" -t nat -D PREROUTING -j RATLS-MESH-PREROUTING 2>/dev/null; do :; done
  while "$B" -t filter -D FORWARD -j RATLS-MESH-CW 2>/dev/null; do :; done
  while "$B" -t filter -D FORWARD -j RATLS-MESH-CW-EGRESS 2>/dev/null; do :; done
  for spec in nat:RATLS-MESH nat:RATLS-MESH-PREROUTING filter:RATLS-MESH-CW filter:RATLS-MESH-CW-EGRESS filter:RATLS-MESH-GUEST-IN filter:RATLS-MESH-GUEST-OUT
  do
    t=${spec%%:*}
    c=${spec#*:}
    if "$B" -t "$t" -L "$c" -n >/dev/null 2>&1; then
      if "$B" -t "$t" -F "$c" && "$B" -t "$t" -X "$c"; then
        echo "$B $t chain removed: $c"
      else
        echo "warning: could not remove $B $t chain $c" >&2
      fi
    fi
  done
}
[ -z "$ipt4" ] || clean_family "$ipt4"
[ -z "$ipt6" ] || clean_family "$ipt6"

if command -v ipset >/dev/null 2>&1; then
  for s in RATLS-MESH-PODS RATLS-MESH-PODS6 RATLS-MESH-LOCAL-PODS RATLS-MESH-LOCAL-PODS6 RATLS-MESH-CW-PODS RATLS-MESH-CW-PODS6
  do
    for n in "$s" "$s-TMP"; do
      ipset destroy "$n" 2>/dev/null && echo "ipset removed: $n" || true
    done
  done
else
  echo "warning: no ipset on this host — any RATLS-MESH-* ipsets are left in place" >&2
fi
exit 0
'

if ! nsenter -t 1 -m -u -i -n -p -- sh -c "$mesh_cleanup_script"; then
  echo "ERROR: RATLS-MESH netfilter sweep failed — stale chains redirect host-originated pod traffic to a dead port" >&2
  sweep_failed=1
fi

if [ "$sweep_failed" = "1" ]; then
  echo "==> c8s host sweep finished WITH FAILURES (see above)" >&2
  exit 1
fi
echo "==> c8s host sweep finished"
