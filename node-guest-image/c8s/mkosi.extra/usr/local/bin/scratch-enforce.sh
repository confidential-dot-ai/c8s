#!/bin/sh
# scratch-enforce: refuse to bring up a node CVM that booted without its
# confai-scratch write-storage disk — the initrd's silent fallback is a 2G
# tmpfs rootfs upper the node later wedges on (see ../README.md "Launch
# requirements"). The unit running this fails the boot instead.
#
# The gate is what the initrd actually did, not disk presence: on success
# the rootfs upper sits on a plain-mode dm mapping named "scratch". Sysfs,
# not /dev/mapper — the dm state needs no udev.
set -eu

fail() {
    echo "scratch-enforce: $1 — refusing to start the node (the rootfs upper is a 2G RAM tmpfs and rke2 wedges when it fills). Attach a virtio-blk disk with serial=confai-scratch, >=64G." >&2
    exit 1
}

for name in /sys/block/dm-*/dm/name; do
    [ -e "$name" ] || continue
    if [ "$(cat "$name")" = "scratch" ]; then
        echo "scratch-enforce: rootfs upper is on the encrypted scratch disk"
        exit 0
    fi
done
fail "initrd fell back to the tmpfs overlay (no dm device named scratch)"
