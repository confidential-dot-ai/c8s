# volumed teardown — run as a privileged pre-delete hook on every volumed node.
#
# Removes the device-mapper stack volumed opened for the pods on this node:
# unmount each c8s volume, then close the dm-verity and dm-crypt mappings
# behind it. volumed is the only component that reaps those, so once the
# release is gone nothing on the node can — the mappings keep the backing disk
# open and the next install fails to reopen it ("already mapped or mounted").
# Idempotent: a node with nothing open exits clean.
#
# Names come from internal/cmds/volumed/open.go (mapperName): the mappings are
# c8s-crypt-<pod-uid>-<volume> and c8s-verity-<pod-uid>-<volume>, and the
# verity device is the mount source.
set -eu

echo "==> volumed teardown starting"

# 1. Unmount what the verity devices back. /proc/mounts names the source
#    device, which holds even after kubelet has renamed the pod directory.
#    Collect the targets before unmounting any: /proc/mounts is generated as
#    it is read, so unmounting mid-scan would shift the rest of the file.
targets=""
while read -r source target _; do
  case "$source" in
  /dev/mapper/c8s-verity-*) targets="$targets $target" ;;
  esac
done </proc/mounts

for target in $targets; do
  if umount "$target"; then
    echo "unmounted $target"
  else
    echo "WARNING: umount $target failed" >&2
  fi
done

# 2. Close the mappings, verity before crypt: verity is stacked on the crypt
#    device and holds it open.
closed=0
for dev in /dev/mapper/c8s-verity-* /dev/mapper/c8s-crypt-*; do
  [ -e "$dev" ] || continue
  name=${dev#/dev/mapper/}
  close=veritysetup
  case "$name" in
  c8s-crypt-*) close=cryptsetup ;;
  esac
  if "$close" close "$name"; then
    closed=$((closed + 1))
    echo "closed $name"
  else
    echo "WARNING: $close close $name failed" >&2
  fi
done

echo "==> volumed teardown finished: $closed mapping(s) closed"
