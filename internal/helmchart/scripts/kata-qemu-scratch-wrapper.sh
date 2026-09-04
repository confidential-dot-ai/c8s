#!/bin/bash
# PROTOTYPE kata qemu wrapper. It attaches two kinds of disk to a guest:
#
#  1. a per-VM ephemeral scratch disk, so the in-guest confidential image store
#     (extra/usr/local/lib/c8s/scratch-setup.sh) can unpack large images to
#     encrypted disk instead of RAM;
#  2. this pod's encrypted volumes (docs/volumes.md), so the in-guest volumed
#     can open them. kata-agent always mounts a block storage it is handed, and
#     these carry ciphertext it cannot mount, so they must reach the guest as
#     bare devices rather than through kata's direct-volume assignment.
#
# Kata has no native per-sandbox disk knob for either, so we intercept the qemu
# launch: set [hypervisor.qemu] path = <this script> in the kata-qemu-tdx
# config. Each disk is found in the guest by its virtio serial
# (/sys/block/<dev>/serial), and carries only ciphertext — the host cannot read
# either one.
#
# Which volumes to attach comes from the pod's host-written annotation, which is
# a selector and not a trust input: naming another tenant's device attaches
# ciphertext the host already holds, and the guest still cannot open it without
# the key CDS releases against the allowlist grant (docs/volumes.md, "The serial
# is a selector, not a trust input"). Devices are attached read-write: a mutable
# volume exists to be written, and the host cannot tell one from immutable —
# the mode lives in the key blob, which the host never sees. An immutable
# volume's writes are refused in the guest, at its dm-crypt mapping.
#
# PRODUCTION NOTE: still a prototype. The clean version attaches the disks from
# the kata runtime (or a CDI device) rather than wrapping qemu. Tunables via env:
# CONFAI_REAL_QEMU, CONFAI_SCRATCH_DIR, CONFAI_SCRATCH_SIZE, CONFAI_GC_GRACE_SECS,
# CONFAI_BUNDLE_ROOTS, CONFAI_SYS_BLOCK.
set -euo pipefail

QEMU="${CONFAI_REAL_QEMU:-/opt/kata/bin/qemu-system-x86_64}"
SDIR="${CONFAI_SCRATCH_DIR:-/var/lib/kata-scratch}"
SIZE="${CONFAI_SCRATCH_SIZE:-30G}"
GRACE="${CONFAI_GC_GRACE_SECS:-120}"
SYSBLOCK="${CONFAI_SYS_BLOCK:-/sys/block}"
# Where containerd writes the sandbox's OCI bundle. RKE2/k3s keep their own
# state root, so both are searched unless overridden.
BUNDLE_ROOTS="${CONFAI_BUNDLE_ROOTS:-/run/containerd/io.containerd.runtime.v2.task/k8s.io /run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io}"

# The annotation naming this pod's volumes, and the serial prefix the guest
# matches on. Both must agree with the Go side: pkg/allowlist (the annotation)
# and internal/cmds/volume (SerialPrefix).
VOLUMES_ANNOTATION="confidential.ai/c8s-volumes"
SERIAL_PREFIX="c8s-vol-"

# The scratch file MUST be keyed on a reliably-unique id: two VMs sharing one
# raw disk would corrupt each other. Kata passes the sandbox id in the -name
# argument ("-name sandbox-<64hex>,..."); take the id from THAT arg only (not
# "first 64-hex anywhere in argv", which could match an unrelated value). If we
# can't find it, FAIL — never fall back to a shared name.
name=""
prev=""
for a in "$@"; do
    [ "$prev" = "-name" ] && { name="$a"; break; }
    prev="$a"
done
SBID="$(printf '%s' "$name" | grep -oE '[a-f0-9]{64}' | head -1 || true)"
if [ -z "$SBID" ]; then
    echo "kata-qemu-scratch-wrapper: no sandbox id in -name ('$name'); refusing to launch with a shared scratch disk" >&2
    exit 1
fi

mkdir -p "$SDIR"

# GC scratch files from VMs that are gone: no process holds the file open AND it
# is older than the grace window. The grace window makes this safe against a
# concurrently-launching VM whose file already exists but whose qemu has not
# opened it yet — that file is fresh, so it is skipped.
for f in "$SDIR"/scratch-*.img; do
    [ -e "$f" ] || continue
    if [ -z "$(find "$f" -newermt "-${GRACE} seconds" 2>/dev/null)" ] && ! fuser "$f" >/dev/null 2>&1; then
        rm -f "$f"
    fi
done

IMG="$SDIR/scratch-$SBID.img"
truncate -s "$SIZE" "$IMG"

# volume_names prints this pod's volume names, one per line.
#
# The bundle's config.json holds the pod annotations. Rather than parse JSON,
# the fixed key's value is extracted and every candidate name is validated
# against the same DNS-1123 label rule (and 12-char serial cap) the webhook, the
# sidecar and volumed all apply — so a value crafted to confuse the extraction
# yields names that fail validation and are skipped, never a shell word.
volume_names() {
    local cfg="" root
    for root in $BUNDLE_ROOTS; do
        if [ -f "$root/$SBID/config.json" ]; then
            cfg="$root/$SBID/config.json"
            break
        fi
    done
    [ -n "$cfg" ] || return 0

    local raw
    raw="$(grep -o "\"$VOLUMES_ANNOTATION\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$cfg" |
        head -1 | sed 's/.*:[[:space:]]*"//; s/"$//' || true)"
    [ -n "$raw" ] || return 0

    # Trailing newline matters: without it `read` drops the last entry, and the
    # pod would silently lose its final volume.
    printf '%s\n' "$raw" | tr ',' '\n' | while IFS= read -r entry; do
        local name="${entry%%=*}"
        if printf '%s' "$name" | grep -qE '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' &&
            [ "${#name}" -le 12 ]; then
            printf '%s\n' "$name"
        else
            echo "kata-qemu-scratch-wrapper: ignoring malformed volume entry '$entry'" >&2
        fi
    done
}

# serial_of prints a block device's serial, from whichever sysfs spelling its
# transport provides: virtio-blk publishes <dev>/serial, SCSI publishes VPD
# page 0x80 at <dev>/device/vpd_pg80. `c8s volume attach` drives LIO, so a
# host that cannot set a virtio serial reaches the guest only through the
# latter. Prints nothing when the device has no serial at all.
# Mirrors SerialDevices.serialOf in internal/cmds/volumed.
serial_of() {
    local d="$1"
    if [ -r "$d/serial" ]; then
        tr -d '[:space:]' <"$d/serial"
        return 0
    fi
    [ -r "$d/device/vpd_pg80" ] || return 0
    # Device type, page code 0x80, big-endian uint16 length, then the serial
    # padded to a fixed width. sysfs reports size 0, so the declared length is
    # the only bound; it is trusted only as far as the bytes actually read.
    od -An -tu1 -v "$d/device/vpd_pg80" 2>/dev/null | awk '
        { for (i = 1; i <= NF; i++) b[n++] = $i }
        END {
            if (n < 4) exit
            end = 4 + b[2] * 256 + b[3]
            if (end <= 4 || end > n) end = n
            s = ""
            for (i = 4; i < end; i++) if (b[i] != 0) s = s sprintf("%c", b[i])
            print s
        }' | tr -d '[:space:]'
}

# device_for prints the block device carrying serial $SERIAL_PREFIX$1.
#
# A serial matching more than one device is refused rather than resolved to
# whichever was read first: the host can attach two devices claiming the same
# serial, and picking one would make which volume a pod gets depend on scan
# order. Mirrors SerialDevices.Device in internal/cmds/volumed.
device_for() {
    local want="$SERIAL_PREFIX$1" found=() d serial
    for d in "$SYSBLOCK"/*; do
        serial="$(serial_of "$d")"
        [ -n "$serial" ] || continue
        [ "$serial" = "$want" ] && found+=("$(basename "$d")")
    done
    if [ "${#found[@]}" -ne 1 ]; then
        echo "kata-qemu-scratch-wrapper: ${#found[@]} block devices carry serial $want; not attaching" >&2
        return 1
    fi
    printf '/dev/%s\n' "${found[0]}"
}

# A missing or ambiguous device is logged and skipped rather than failing the
# launch: refusing here surfaces as an opaque shim error on a pod that never
# starts, whereas letting it boot leaves the in-guest daemon to answer "volume
# device is not present", which is where an operator is already looking.
volume_args=()
n=0
while IFS= read -r vol; do
    [ -n "$vol" ] || continue
    if dev="$(device_for "$vol")"; then
        volume_args+=(
            -drive "file=$dev,format=raw,if=none,id=confaivol$n,cache=none"
            -device "virtio-blk-pci,drive=confaivol$n,serial=$SERIAL_PREFIX$vol"
        )
        n=$((n + 1))
    fi
done < <(volume_names)

# file.locking left at the qemu default (on): with unique per-sandbox files a
# lock conflict now means a real bug (two launches, same id) and should fail
# loudly rather than silently share the disk.
exec "$QEMU" "$@" \
    -drive "file=$IMG,format=raw,if=none,id=confaiscratch,cache=none" \
    -device virtio-blk-pci,drive=confaiscratch,serial=confai-scratch \
    "${volume_args[@]+"${volume_args[@]}"}"
