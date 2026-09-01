#!/bin/bash
# Unit test for gpu-cc-enforce.sh: a GPU-less boot is a no-op, every CC-on
# wording passes, and any GPU with CC off, an unparseable status, or a dead
# driver fails the gate. Root-free: fakes the PCI sysfs tree under a temp root
# and shadows nvidia-smi with a stub on PATH.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${GPU_CC_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/gpu-cc-enforce.sh"}
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

not() { ! "$@"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# Run the production script verbatim with the sysfs root rebased into $WORK
# and the stub nvidia-smi first on PATH.
run_enforce() {
    sed -e "s|/sys/bus/pci/devices|$WORK/sys/bus/pci/devices|g" "$SCRIPT" \
        | PATH="$WORK/bin:$PATH" sh 2>"$WORK/stderr"
}
set_vendor() { # set_vendor HEXID
    rm -rf "$WORK/sys/bus/pci/devices"
    mkdir -p "$WORK/sys/bus/pci/devices/0000:0b:00.0"
    printf '%s' "$1" > "$WORK/sys/bus/pci/devices/0000:0b:00.0/vendor"
}
# stub_smi RC OUTPUT... — nvidia-smi prints each OUTPUT line and exits RC.
stub_smi() {
    local rc=$1; shift
    { echo '#!/bin/sh'; printf 'echo "%s"\n' "$@"; echo "exit $rc"; } > "$WORK/bin/nvidia-smi"
    chmod +x "$WORK/bin/nvidia-smi"
}
stderr_has() { grep -q "$1" "$WORK/stderr"; }

CASE="no nvidia device"
set_vendor 0x8086
stub_smi 1 "No devices were found"
ok "no-op without a GPU even when nvidia-smi fails" run_enforce

CASE="cc on (driver 595 wording)"
set_vendor 0x10de
stub_smi 0 "CC status: ON"
ok "passes" run_enforce

CASE="cc on (older 'CC feature' wording)"
stub_smi 0 "CC feature: ON"
ok "passes" run_enforce

CASE="cc off"
stub_smi 0 "CC status: OFF"
ok "fails" not run_enforce
ok "names the cause" stderr_has "not in CC mode"

CASE="one of two gpus off"
stub_smi 0 "GPU 0: CC status: ON" "GPU 1: CC status: OFF"
ok "fails when any GPU is off" not run_enforce

CASE="unparseable status"
stub_smi 0 "Confidential Compute is not supported on this device"
ok "fails when no CC status line is printed" not run_enforce
ok "names the cause" stderr_has "cannot parse"

CASE="driver not up"
stub_smi 9 "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver"
ok "fails when nvidia-smi errors" not run_enforce
ok "names the cause" stderr_has "conf-compute -f failed"

summarize "gpu-cc-enforce"
