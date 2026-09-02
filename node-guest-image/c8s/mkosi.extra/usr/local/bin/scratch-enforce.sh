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

# 64G in 512-byte sectors — decimal, so a 64GB or 64GiB disk both pass.
MIN_SECTORS=125000000

for d in /sys/block/dm-*; do
    [ -e "$d/dm/name" ] || continue
    [ "$(cat "$d/dm/name")" = "scratch" ] || continue
    # An unreadable or empty size must fail closed: a non-number would only
    # make [ complain, and set -e ignores a failed if condition.
    sectors=$(cat "$d/size" 2>/dev/null || true)
    case "$sectors" in ''|*[!0-9]*) sectors=0 ;; esac
    if [ "$sectors" -lt "$MIN_SECTORS" ]; then
        fail "scratch disk too small ($((sectors / 2048)) MiB, need >=64G)"
    fi
    echo "scratch-enforce: rootfs upper is on the encrypted scratch disk"
    exit 0
done
fail "initrd fell back to the tmpfs overlay (no dm device named scratch)"
