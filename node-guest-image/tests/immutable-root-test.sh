#!/usr/bin/env bash
# Exercise the pinned initrd with real mounts, without booting a CVM. Hardware
# discovery and switch_root are shims; the production init/finalizer stay intact.
set -euo pipefail
test_script=$(realpath "${BASH_SOURCE[0]}")
ngi_dir=$(cd "$(dirname "$test_script")/.." && pwd)
CONFOS_DIR=$(realpath "${CONFOS_DIR:-$ngi_dir/../confos}")
export CONFOS_DIR

if [ "$EUID" -ne 0 ] || [ "$(uname -s)" != Linux ]; then
    echo "immutable-root-test.sh requires root on Linux with mount namespace/overlay support" >&2
    exit 1
fi
if [ "${1:-}" != --private-mount-namespace ]; then
    # Each case gets a fresh namespace, so failed boot mounts never leak into
    # another case. Cleanup runs outside chroot with the real /proc mount table.
    for test_case in test_declared_state_writes_leave_the_image_immutable \
        test_missing_declared_directory_prevents_switch_root; do
        unshare --mount --propagation private /bin/bash "$test_script" \
            --private-mount-namespace "$test_case"
    done
    exit 0
fi

fixture_root=$(mktemp -d)
cleanup() {
    local status=$?
    trap - EXIT
    # Never recursively remove a fixture while it contains host bind mounts.
    if mountpoint -q "$fixture_root"; then
        if ! umount -R "$fixture_root"; then
            echo "Failed to unmount test root: $fixture_root" >&2
            exit 1
        fi
    fi
    rmdir "$fixture_root"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mount -t tmpfs tmpfs "$fixture_root"
mkdir -p "$fixture_root"/{usr,dev,proc,sys,run,tmp,image-template}
mount --bind /usr "$fixture_root/usr"
mount -o remount,bind,ro "$fixture_root/usr"
# /usr stays read-only; this private tmpfs supplies only hardware boundary shims.
mount -t tmpfs tmpfs "$fixture_root/usr/sbin"
for directory in bin sbin lib; do
    ln -s "usr/$directory" "$fixture_root/$directory"
done
if [ -d /usr/lib64 ]; then
    ln -s usr/lib64 "$fixture_root/lib64"
fi
touch "$fixture_root/c8s-immutable-test-root" "$fixture_root/dev/null" "$fixture_root/dev/vda2"
mount --bind /dev/null "$fixture_root/dev/null"
printf 'roothash=%064d\n' 0 > "$fixture_root/proc/cmdline"
# A fail-closed boot can only write this ordinary fixture file, never host sysrq.
touch "$fixture_root/proc/sysrq-trigger"

base="$CONFOS_DIR/mkosi/base"
for extra in "$base/mkosi.extra" \
    "$base/mkosi.profiles/gpu/mkosi.extra" \
    "$base/mkosi.profiles/attest-gpu/mkosi.extra" \
    "$ngi_dir/c8s/mkosi.extra"; do
    cp -a "$extra/." "$fixture_root/image-template/"
done
cp "$ngi_dir/c8s/image-policy.yaml.in" "$fixture_root/nri-floor-template"
cp "$base/mkosi.finalize" "$fixture_root/finalize-under-test"
cp "$CONFOS_DIR/mkosi/initrd/mkosi.extra/init" "$fixture_root/init-under-test"
cp "$ngi_dir/tests/immutable_root_test.py" "$fixture_root/tests.py"

cat > "$fixture_root/usr/sbin/veritysetup" <<'SHIM'
#!/bin/bash
exit 0
SHIM
cat > "$fixture_root/usr/sbin/blkid" <<'SHIM'
#!/bin/bash
# No operator-key or scratch disk: exercise the real tmpfs state fallback.
exit 1
SHIM
cat > "$fixture_root/usr/sbin/mount" <<'SHIM'
#!/bin/bash
set -euo pipefail
case "$*" in
    "-t proc proc /proc"|"-t sysfs sysfs /sys"|"-t devtmpfs devtmpfs /dev")
        exit 0 ;;
    "-o ro /dev/mapper/root /sysroot")
        /usr/bin/mount --bind /image /sysroot
        exec /usr/bin/mount -o remount,bind,ro /sysroot ;;
    *)
        exec /usr/bin/mount "$@" ;;
esac
SHIM
cat > "$fixture_root/usr/sbin/switch_root" <<'SHIM'
#!/bin/bash
printf '%s\n' "$@" > /switch-root-args
SHIM
chmod +x "$fixture_root"/usr/sbin/*
chroot "$fixture_root" /usr/bin/python3 /tests.py "ImmutableNodeRootTests.${2:?missing test case}"
