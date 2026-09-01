#!/bin/bash
# Unit test for scratch-enforce.sh: passes only when a dm device named
# "scratch" exists, i.e. the initrd really backed the rootfs upper with the
# confai-scratch disk. Root-free: fakes the dm sysfs tree under a temp root.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${SCRATCH_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/scratch-enforce.sh"}
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Run the production script verbatim with the sysfs root rebased into $WORK.
run_enforce() {
    sed -e "s|/sys/block|$WORK/sys/block|g" "$SCRIPT" | sh 2>"$WORK/stderr"
}
set_dm() { # set_dm NAME... — one 80Gi dm-N per name; none = tmpfs fallback boot
    rm -rf "$WORK/sys/block"
    mkdir -p "$WORK/sys/block"
    local i=0 name
    for name in "$@"; do
        mkdir -p "$WORK/sys/block/dm-$i/dm"
        printf '%s' "$name" > "$WORK/sys/block/dm-$i/dm/name"
        printf '167772160' > "$WORK/sys/block/dm-$i/size"
        i=$((i + 1))
    done
}

CASE="scratch upper"
set_dm scratch
ok "passes" run_enforce

CASE="scratch among other dm devices"
set_dm containerd scratch
ok "passes" run_enforce

CASE="tmpfs fallback (no dm devices)"
set_dm
ok "fails" not run_enforce
ok "names the cause" stderr_has "tmpfs overlay"

CASE="other dm devices only"
set_dm containerd
ok "fails" not run_enforce

CASE="scratch too small"
set_dm scratch
printf '16777216' > "$WORK/sys/block/dm-0/size" # 8Gi
ok "fails" not run_enforce
ok "names the cause" stderr_has "too small"

summarize "scratch-enforce"
