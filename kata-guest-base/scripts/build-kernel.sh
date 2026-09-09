#!/usr/bin/env bash
# Build the guest kernel and capture its resolved config before checking drift.
set -euo pipefail

CONFOS_DIR="$(realpath "${1:?confos checkout required}")"
IMAGE_DIR="$(realpath "${2:?guest image directory required}")"
KERNEL_FRAGMENT="${IMAGE_DIR}/kernel/container.config"
KERNEL_SNAPSHOT="${IMAGE_DIR}/kernel/config-x86_64.snapshot"
# confos writes the resolved config beside the fragment. Keep it separate
# from the committed snapshot so cached output cannot replace the drift baseline.
CONFOS_SNAPSHOT="${IMAGE_DIR}/kernel/config-x86_64-container.snapshot"
VMLINUZ_OUT="${3:-${IMAGE_DIR}/output}/vmlinuz"
die() { echo "FATAL: $*" >&2; exit 1; }
[[ -f "$KERNEL_FRAGMENT" ]] || die "kernel fragment missing: $KERNEL_FRAGMENT"
mkdir -p "$(dirname "$VMLINUZ_OUT")"

[[ -d "${CONFOS_DIR}" ]] || die "confos checkout not found at ${CONFOS_DIR} (set CONFOS_DIR)."
CONFOS_BIN="${CONFOS_BIN:-${CONFOS_DIR}/target/release/confos}"
if [[ ! -x "${CONFOS_BIN}" ]]; then
    echo "    building confos (cargo build --release)"
    ( cd "${CONFOS_DIR}" && cargo build --release )
fi
( cd "${CONFOS_DIR}" && "${CONFOS_BIN}" kernel \
    --kernel-config-fragment "${KERNEL_FRAGMENT}" )
CONFOS_VMLINUZ="${CONFOS_DIR}/output/kernel/vmlinuz"
[[ -f "${CONFOS_VMLINUZ}" ]] || die "confos did not produce ${CONFOS_VMLINUZ}"
install -m 0644 "${CONFOS_VMLINUZ}" "${VMLINUZ_OUT}"

[[ -f "${CONFOS_SNAPSHOT}" ]] || die "confos did not produce ${CONFOS_SNAPSHOT} — cannot capture the resolved-config snapshot."
snapshot_drift=0
if [[ -f "${KERNEL_SNAPSHOT}" ]] && ! cmp -s "${CONFOS_SNAPSHOT}" "${KERNEL_SNAPSHOT}"; then
    snapshot_drift=1
    committed_sha="$(sha256sum "${KERNEL_SNAPSHOT}" | awk '{print $1}')"
fi
install -m 0644 "${CONFOS_SNAPSHOT}" "${KERNEL_SNAPSHOT}"
echo "    snapshot: ${KERNEL_SNAPSHOT} (sha256 $(sha256sum "${KERNEL_SNAPSHOT}" | awk '{print $1}'))"
if [[ "${CHECK_SNAPSHOT:-0}" == "1" && "${snapshot_drift}" == "1" ]]; then
    die "resolved kernel config drifted from the committed snapshot.
   committed ${KERNEL_SNAPSHOT}: ${committed_sha}
   resolved  (this build):       $(sha256sum "${KERNEL_SNAPSHOT}" | awk '{print $1}')
   confos's baseline (CONFOS_REF) or kernel/container.config changed without
   re-committing kata-guest-base/kernel/config-x86_64.snapshot. Re-resolve and
   commit it (run the 'Kernel config snapshot' workflow, or a local build), or
   revert the change that moved it. Failing before osbuilder + the GHCR push."
fi
