#!/bin/sh
# Pull the kata-guest-base rootfs image (hardened kernel + dm-verity
# rootfs) into the host kata-images dir and rewrite the kata-qemu-snp
# runtime config so kata-runtime boots our kernel + verity rootfs for
# every kata-qemu-snp pod (measured direct-kernel boot, no IGVM).
#
# Pure POSIX shell, kept as a standalone file (templated into the
# kata-image-puller ConfigMap via .Files.Get) so it gets shellcheck.
# All configuration comes from the environment, set on the puller
# initContainer from .Values.kata.guestImage.* — there is no helm
# interpolation inside this script.
#
#   REGISTRY        guest-image registry (e.g. ghcr.io/confidential-dot-ai)   [required]
#   TAG             kata-guest-base tag                             [required]
#   HOST_IMG_DIR    /host-prefixed dir the puller writes into       [required]
#   REGISTRY_AUTH   in-guest workload registry auth source (file://
#                   baked path or kbs:// URI); empty = anonymous    [optional]
#   ORAS_INSECURE   "true" to pull over plain HTTP (local mirror)   [optional]
set -eu

: "${REGISTRY:?REGISTRY must be set (kata.guestImage.repository)}"
: "${TAG:?TAG must be set (kata.guestImage.tag)}"
: "${HOST_IMG_DIR:?HOST_IMG_DIR must be set (/host + kata.guestImage.hostPath)}"
REGISTRY_AUTH="${REGISTRY_AUTH:-}"
# --plain-http makes oras talk to an insecure (HTTP, no TLS) registry — for
# local / in-cluster mirrors only. Empty for a normal TLS registry.
ORAS_OPTS=""
[ "${ORAS_INSECURE:-false}" = "true" ] && ORAS_OPTS="--plain-http"
HOST_KATA_DIR="${HOST_KATA_DIR:-/host/opt/kata}"
KATA_CONFIG_DIR="${HOST_KATA_DIR}/share/defaults/kata-containers"

echo "==> c8s-kata-image-puller: registry=${REGISTRY} tag=${TAG}"

mkdir -p "${HOST_IMG_DIR}" "${KATA_CONFIG_DIR}"

out_dir="${HOST_IMG_DIR}/base"
mkdir -p "${out_dir}"

echo "==> Pulling kata-guest-base:${TAG}"
# oras pull is content-addressable: re-running with the same
# digest is a no-op once the artifact is in the local cache.
# We cd into the target dir so the pulled files land there
# (oras unpacks the artifact's contents into CWD).
# shellcheck disable=SC2086  # ORAS_OPTS is a controlled single flag ("" or --plain-http)
( cd "${out_dir}" && oras pull ${ORAS_OPTS} "${REGISTRY}/kata-guest-base:${TAG}" )

# Sanity: the artifact must contain the kernel, the verity rootfs
# image, and the verity params + rootfs-type sidecars. Fail loudly —
# silently writing a config that points at a missing file (or, worse,
# one with empty verity params, which would DISABLE dm-verity and drop
# the rootfs out of the measurement) leaves the runtime broken or
# insecure in a way that only surfaces at pod start.
for required in vmlinuz kata-rootfs.img kernel_verity_params rootfs_type; do
    if [ ! -f "${out_dir}/${required}" ]; then
        echo "ERROR: ${out_dir}/${required} missing after oras pull" >&2
        exit 1
    fi
done

# Verity params + rootfs type come from the build (these sidecars
# mirror manifest.json). kernel_verity_params is load-bearing: an
# empty value would make kata boot WITHOUT dm-verity (rootfs no longer
# measured / tamper-evident), so refuse anything but a real root_hash.
KVP="$(tr -d '\n' < "${out_dir}/kernel_verity_params")"
RFT="$(tr -d '\n' < "${out_dir}/rootfs_type")"
case "${KVP}" in
    root_hash=*) ;;
    *) echo "ERROR: kernel_verity_params is not a 'root_hash=…' string: '${KVP}'" >&2; exit 1 ;;
esac
[ -n "${RFT}" ] || RFT=ext4

# Translate /host<...> back to the on-host absolute path the
# kata configuration TOML will reference. The puller pod sees
# the host root at /host; kata-runtime running on the host
# sees the same files without the prefix.
host_out_dir="${out_dir#/host}"

# kata-deploy installs the qemu-snp config as a REGULAR FILE under
# runtimes/qemu-snp/ and a convenience SYMLINK to it at this parent dir.
# containerd's ConfigPath (emitted by kata-deploy's own install) points
# at the runtimes/qemu-snp/ file — confirmed with `containerd config
# dump`: ConfigPath = .../runtimes/qemu-snp/configuration-qemu-snp.toml.
# So we patch that file directly. Patching the parent symlink path is a
# silent no-op: sed/mv there replaces the symlink with a regular file and
# leaves the runtimes/ file (the one the runtime loads) untouched, so the
# pod fails at sandbox creation with the stock shared_fs="none"/no-guest-
# pull `failed to mount .../rootfs ENOENT`. Targeting runtimes/ directly
# is also robust to a parent symlink that a prior run already clobbered
# into a stale regular file. See bare-metal-infra-management
# docs/kata.md "TOML editing gotchas".
cfg_target="${KATA_CONFIG_DIR}/runtimes/qemu-snp/configuration-qemu-snp.toml"
if [ ! -f "${cfg_target}" ]; then
    echo "ERROR: ${cfg_target} missing — has kata-deploy finished?" >&2
    exit 1
fi
src_cfg="${cfg_target}.upstream"
if [ ! -f "${src_cfg}" ]; then
    # First run — snapshot kata-deploy's default once so subsequent
    # runs re-derive from the pristine base.
    cp "${cfg_target}" "${src_cfg}"
fi

echo "  Writing ${cfg_target}"
# Point kata-qemu-snp at our kata-native parts and pin the knobs that
# make the boot work + keep the SNP measurement stable. Everything else
# (qemu path, SNP firmware/AMDSEV.fd, machine type) stays at
# kata-deploy's stock SNP defaults.
#
#   kernel/image          -> our hardened vmlinuz + dm-verity rootfs image
#   rootfs_type           -> ext4 (matches the osbuilder measured image;
#                            value comes from the build's rootfs_type sidecar)
#   kernel_verity_params  -> our root_hash/salt/blocks; kata builds the
#                            dm-verity table from this and folds the hash
#                            into the kernel-hashes SNP launch measurement
#   shared_fs = none      -> no virtio-fs into the confidential guest
#   default_vcpus/maxvcpus = 1 -> pin the boot-time VMSA count so the SNP
#                            launch digest is stable across pods (the one
#                            genuinely per-VM input to the measurement)
sed -e "s|^kernel = .*|kernel = \"${host_out_dir}/vmlinuz\"|" \
    -e "s|^image = .*|image = \"${host_out_dir}/kata-rootfs.img\"|" \
    -e "s|^rootfs_type = .*|rootfs_type = \"${RFT}\"|" \
    -e "s|^kernel_verity_params = .*|kernel_verity_params = \"${KVP}\"|" \
    -e 's|^shared_fs = .*|shared_fs = "none"|' \
    -e 's|^default_vcpus = .*|default_vcpus = 1|' \
    -e 's|^default_maxvcpus = .*|default_maxvcpus = 1|' \
    "${src_cfg}" > "${cfg_target}.c8s-tmp"

# experimental_force_guest_pull = true. With shared_fs="none" there is
# no host-share path for the container rootfs, so the kata-agent
# (image-rs, confidential build) pulls the workload OCI image inside
# the guest over its virtio-net interface. Without this, the kata-shim
# fails with `failed to mount /run/kata-containers/shared/containers/
# <id>/rootfs ... ENOENT`. Mirrors bare-metal-infra-management's kata
# role (docs/kata-cc-mode.md). It's a [runtime]-section key; stock SNP
# variants omit it, so replace-if-present else insert under [runtime].
if grep -qE '^[[:space:]]*#?[[:space:]]*experimental_force_guest_pull[[:space:]]*=' "${cfg_target}.c8s-tmp"; then
    sed -i -E 's|^[[:space:]]*#?[[:space:]]*experimental_force_guest_pull[[:space:]]*=.*|experimental_force_guest_pull = true|' "${cfg_target}.c8s-tmp"
elif grep -qE '^\[runtime\]' "${cfg_target}.c8s-tmp"; then
    sed -i '/^\[runtime\]/a experimental_force_guest_pull = true' "${cfg_target}.c8s-tmp"
else
    printf '\n[runtime]\nexperimental_force_guest_pull = true\n' >> "${cfg_target}.c8s-tmp"
fi

# In-guest registry auth. The kata-agent reads `agent.image_registry_auth`
# off the guest kernel cmdline and hands the referenced credentials to the
# in-guest CDH for guest-pull (kata's own
# k8s-guest-pull-image-authenticated test wires it the same way). The value
# is a file:// path baked into the measured rootfs (TEST — bakes creds into
# the dm-verity image) or a kbs:// resource URI (production: the CDH fetches
# it from the KBS after attestation). Appended to kernel_params, which rides
# in the kernel-hashes SNP launch measurement: the value is a deterministic
# URI (not the secret itself), so the launch digest stays stable. We derive
# from the pristine upstream each run, so appending once is idempotent.
if [ -n "${REGISTRY_AUTH}" ]; then
    if grep -qE '^kernel_params = ' "${cfg_target}.c8s-tmp"; then
        sed -i -E "s|^kernel_params = \"(.*)\"|kernel_params = \"\\1 agent.image_registry_auth=${REGISTRY_AUTH}\"|" "${cfg_target}.c8s-tmp"
    else
        echo "ERROR: no kernel_params line in ${cfg_target} to attach agent.image_registry_auth to" >&2
        exit 1
    fi
fi

mv -f "${cfg_target}.c8s-tmp" "${cfg_target}"

# Restore kata-deploy's expected layout: the parent path is a relative
# symlink to the runtimes/ file we just patched. A prior puller version
# (or an in-place rewrite of the parent path) may have clobbered the
# symlink into a stale regular file; recreate it so anything resolving
# the parent path also sees the patched config.
ln -sf "runtimes/qemu-snp/configuration-qemu-snp.toml" \
    "${KATA_CONFIG_DIR}/configuration-qemu-snp.toml"

echo "==> c8s-kata-image-puller: done"
