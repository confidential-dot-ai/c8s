#!/bin/sh
# Label this node when an NVIDIA GPU is actually attached.
#
# Every published node image carries the GPU userspace and the baked
# nvidia-device-plugin DaemonSet, but GPU presence is a launch-time choice.
# The DaemonSet selects on this label; without it the plugin lands on
# GPU-less nodes where FAIL_ON_INIT_ERROR cannot save it — the
# cdi-annotations strategy hard-fails generating a CDI spec with no driver
# loaded, and the pod crashloops forever.
#
# Detection is PCI presence, not /dev/nvidia*: the device nodes only exist
# once the driver has loaded, and this runs before rke2 starts.
set -eu

FRAGMENT=/etc/rancher/rke2/config.yaml.d/20-gpu-node-label.yaml

# Clean slate: a relaunch without the GPU must not inherit the label.
rm -f "$FRAGMENT"

for vendor in /sys/bus/pci/devices/*/vendor; do
    [ -e "$vendor" ] || continue
    if [ "$(cat "$vendor")" = "0x10de" ]; then
        mkdir -p /etc/rancher/rke2/config.yaml.d
        printf 'node-label+:\n  - "confidential.ai/gpu=true"\n' > "$FRAGMENT"
        exit 0
    fi
done
exit 0
