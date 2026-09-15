#!/bin/sh
# gpu-cc-enforce: refuse to bring up a node CVM whose passed-through NVIDIA
# GPUs are not in confidential-compute (CC) mode.
#
# confos's nvidia-cc-ready sets the CC ready state but never fails: on a
# non-CC GPU it logs and exits 0, and the baked device plugin then advertises
# a GPU whose memory the host can read. The c8s node is confidential-only, so
# the unit that runs this script fails the boot instead (FailureAction powers
# the VM off; rke2 Requires= it and never starts).
#
# The gate is CC status per GPU, not the ready state: a CC GPU left un-readied
# is unusable for CUDA but still protected, and nvidia-cc-ready already logs
# that case loudly. nvidia-smi itself failing is fatal: a driver that is not
# up cannot vouch for anything.
#
# PCI presence (vendor 0x10de) mirrors gpu-node-label.sh so a GPU-less boot
# of the same image is a clean no-op.
set -eu

fail() {
    echo "gpu-cc-enforce: $1 — refusing to start the node (GPU memory would be unprotected). Enable GPU CC mode on the host (nvidia_gpu_tools.py --set-cc-mode=on)." >&2
    exit 1
}

present=0
for vendor in /sys/bus/pci/devices/*/vendor; do
    [ -e "$vendor" ] || continue
    if [ "$(cat "$vendor")" = "0x10de" ]; then
        present=1
        break
    fi
done
if [ "$present" = 0 ]; then
    echo "gpu-cc-enforce: no NVIDIA GPU present; nothing to enforce"
    exit 0
fi

status=$(nvidia-smi conf-compute -f 2>&1) || fail "nvidia-smi conf-compute -f failed: $status"

# Driver 595 prints "CC status: ON"; older drivers "CC feature: ON". One line
# per GPU with -i, one aggregate line without; either way every line must be
# on, and at least one must exist.
lines=$(printf '%s\n' "$status" | grep -iE 'cc (feature|status)[[:space:]]*:' || true)
[ -n "$lines" ] || fail "cannot parse CC status from nvidia-smi: $status"
if printf '%s\n' "$lines" | grep -qviE ':[[:space:]]*(on|enabled)[[:space:]]*$'; then
    fail "GPU not in CC mode ($lines)"
fi

echo "gpu-cc-enforce: all NVIDIA GPUs in CC mode"
