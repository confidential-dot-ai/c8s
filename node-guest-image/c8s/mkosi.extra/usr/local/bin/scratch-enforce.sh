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
    echo "scratch-enforce: $1 — refusing to start the node. Attach a virtio-blk disk with serial=confai-scratch, >=64G." >&2
    exit 1
}

# The 64G floor in 512-byte sectors, decimal so a 64GB or 64GiB disk both
# pass; the hazard is a toy disk that re-creates the wedge with more rope.
MIN_SECTORS=125000000

for name in /sys/block/dm-*/dm/name; do
    [ -e "$name" ] || continue
    [ "$(cat "$name")" = "scratch" ] || continue
    sectors=$(cat "$(dirname "$(dirname "$name")")/size" 2>/dev/null || echo 0)
    if [ "$sectors" -lt "$MIN_SECTORS" ]; then
        fail "scratch disk too small ($((sectors / 2048)) MiB, need >=64G)"
    fi
    echo "scratch-enforce: rootfs upper is on the encrypted scratch disk"
    exit 0
done
fail "initrd fell back to the tmpfs overlay (no dm device named scratch)"
