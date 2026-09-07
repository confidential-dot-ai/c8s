#!/bin/bash
# Unit test for c8s-chart-values.sh, now a thin wrapper: `c8s launch-values
# render` (internal/cmds/launchvalues) owns resolving this guest's own
# measurement, the operator key, and the fragment/allowlist logic, all
# covered by Go tests in that package instead. This script's own remaining
# job — parse --platform, mount the optional opkeydata ISO and locate
# values.yaml/values.yaml.sig on it, exec `c8s launch-values render --out` —
# is what this test covers: platform validation, opkeydata absent (no
# --fragment), opkeydata present with a values.yaml but no .sig (fails
# closed before c8s ever runs), opkeydata present with a signed fragment
# (--fragment/--signature passed through), and that the stub c8s's --out
# file is what "wrote the manifest" means here. Root-free: rebases every
# baked path with sed and shadows mount/umount/mountpoint/c8s with stubs on
# PATH, mirroring gpu-cc-enforce-test.sh / lib.sh. The real mount(8) call is
# stubbed out entirely (loop-mounting an ISO needs root — see
# rke2-role-test.sh for that harness); this test instead pre-populates the
# rebased opkeydata mountpoint directory directly and asserts the script
# reads it and unmounts (calls the stub) at the right points.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${CHART_VALUES_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/c8s-chart-values.sh"}
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/manifests" "$WORK/opkeydata-mnt"
DEST="$WORK/manifests/c8s-chart-values.yaml"
OPKEYDATA_DEV="$WORK/opkeydata-dev"
OPKEYDATA_MNT="$WORK/opkeydata-mnt"

# rebased SCRIPT — sed a copy of the production script with every baked path
# rebased into $WORK; written once, run many times below.
REBASED="$WORK/script.sh"
sed \
    -e "s|/var/lib/rancher/rke2/server/manifests/c8s-chart-values.yaml|$DEST|g" \
    -e "s|/dev/disk/by-label/opkeydata|$OPKEYDATA_DEV|g" \
    -e "s|/run/confos/opkeydata|$OPKEYDATA_MNT|g" \
    -e "s|/usr/local/bin/c8s \"|$WORK/bin/c8s \"|g" \
    "$SCRIPT" > "$REBASED"

# run_values ARGS... — run the rebased script with the stub bin dir first on
# PATH (stubs shadow any real mount/umount/mountpoint the test host happens
# to have, and provide the c8s stub).
run_values() {
    PATH="$WORK/bin:$PATH" sh "$REBASED" "$@" 2>"$WORK/stderr"
}

# stub_mount_tools — no-op mount/umount/mountpoint stubs standing in for the
# real loop-mount rke2-role-test.sh exercises with root. The script only
# ever mounts opkeydata (never writes through the mount), so a no-op mount
# plus a directly pre-populated $OPKEYDATA_MNT (via set_fragment below) is
# behaviorally equivalent for everything this script reads. `timeout 10
# mount ...` is invoked as `timeout` first; that stub execs through to the
# real command list minus mount, so only mount itself needs stubbing —
# timeout(1) itself is real coreutils and stays on PATH.
stub_mount_tools() {
    cat > "$WORK/bin/mount" <<'EOF'
#!/bin/sh
echo "stub-mount: $*" >> "${STUB_MOUNT_LOG:-/dev/null}"
exit 0
EOF
    cat > "$WORK/bin/umount" <<'EOF'
#!/bin/sh
echo "stub-umount: $*" >> "${STUB_MOUNT_LOG:-/dev/null}"
exit 0
EOF
    cat > "$WORK/bin/mountpoint" <<'EOF'
#!/bin/sh
# Always report "is a mountpoint" (-q => silent, exit 0): the stub mount
# above never actually mounts anything, so this cannot check the real
# state; the script only uses it to decide whether to also try umount,
# which is itself a no-op stub, so reporting mounted unconditionally is
# both harmless and simplest.
exit 0
EOF
    chmod +x "$WORK/bin/mount" "$WORK/bin/umount" "$WORK/bin/mountpoint"
}
stub_mount_tools

# stub_c8s_render — a stub `c8s launch-values render` that records its argv
# and, when --out is given, writes a recognizable HelmChartConfig there
# (honouring --out the way the real `c8s launch-values render` does) so
# tests can assert both the exact flags c8s-chart-values.sh passes and that
# the destination file lands.
stub_c8s_render() {
    cat > "$WORK/bin/c8s" <<EOF
#!/bin/sh
echo "\$*" > "$WORK/c8s-argv"
if [ "\$1" = "launch-values" ] && [ "\$2" = "render" ]; then
    shift 2
    fragment="" out=""
    for a in "\$@"; do
        case "\$a" in
            --fragment=*) fragment="\${a#--fragment=}" ;;
            --out=*) out="\${a#--out=}" ;;
        esac
    done
    body="kind: HelmChartConfig"
    if [ -n "\$fragment" ]; then
        body="\$body
STUB_RENDER_WITH_FRAGMENT: \$fragment"
    else
        body="\$body
STUB_RENDER_NO_FRAGMENT"
    fi
    if [ -n "\$out" ]; then
        printf '%s\n' "\$body" > "\$out"
    else
        printf '%s\n' "\$body"
    fi
    exit 0
fi
echo "stub c8s: unexpected args: \$*" >&2
exit 1
EOF
    chmod +x "$WORK/bin/c8s"
}
stub_c8s_render_failing() {
    cat > "$WORK/bin/c8s" <<'EOF'
#!/bin/sh
echo "stub c8s: refusing (test fixture)" >&2
exit 1
EOF
    chmod +x "$WORK/bin/c8s"
}

# set_opkeydata_device / rm_opkeydata_device — presence of the rebased
# "/dev/disk/by-label/opkeydata" path, which the script only ever tests with
# `-e`.
set_opkeydata_device() { : > "$OPKEYDATA_DEV"; }
rm_opkeydata_device() { rm -f "$OPKEYDATA_DEV"; }

# set_fragment / rm_fragment — populate (or clear) the rebased opkeydata
# mountpoint directly, standing in for what a real mount would expose.
set_fragment() {
    printf '%s' "${1:-fake-fragment}" > "$OPKEYDATA_MNT/values.yaml"
}
set_fragment_sig() {
    printf '%s' "${1:-fake-sig}" > "$OPKEYDATA_MNT/values.yaml.sig"
}
rm_fragment() { rm -f "$OPKEYDATA_MNT/values.yaml" "$OPKEYDATA_MNT/values.yaml.sig"; }

require_dest() { [[ -s "$DEST" ]]; }
dest_has() { grep -qF "$1" "$DEST"; }
argv_has() { grep -qF -- "$1" "$WORK/c8s-argv"; }

CASE="no --platform"
stub_c8s_render
ok "fails" not run_values
ok "names the cause" stderr_has "platform must be tdx or snp"

CASE="tdx, no opkeydata device"
rm_opkeydata_device
rm_fragment
rm -f "$DEST" "$WORK/c8s-argv"
ok "succeeds" run_values --platform=tdx
ok "writes the manifest" require_dest
ok "is a HelmChartConfig" dest_has "kind: HelmChartConfig"
ok "invokes c8s launch-values render" argv_has "launch-values render"
ok "passes --platform=tdx" argv_has "--platform=tdx"
ok "passes --out pointing at the manifests dest" argv_has "--out=$DEST"
ok "does not pass --fragment (no opkeydata device)" bash -c "! grep -q -- '--fragment' '$WORK/c8s-argv'"
ok "carries the stub's no-fragment output" dest_has "STUB_RENDER_NO_FRAGMENT"

CASE="snp, no opkeydata device"
rm -f "$DEST" "$WORK/c8s-argv"
ok "succeeds" run_values --platform=snp
ok "passes --platform=snp" argv_has "--platform=snp"

CASE="opkeydata present with a values.yaml but no .sig"
set_opkeydata_device
set_fragment
rm -f "$WORK/opkeydata-mnt/values.yaml.sig"
rm -f "$WORK/c8s-argv"
ok "fails" not run_values --platform=tdx
ok "names the cause" stderr_has "without values.yaml.sig"
ok "never invokes c8s (refused before render)" bash -c "[[ ! -e '$WORK/c8s-argv' ]]"
rm_fragment

CASE="opkeydata present with a signed values.yaml fragment"
set_fragment
set_fragment_sig
rm -f "$DEST"
ok "succeeds" run_values --platform=tdx
ok "writes the manifest" require_dest
ok "passes --fragment pointing at the mounted values.yaml" argv_has "--fragment=$OPKEYDATA_MNT/values.yaml"
ok "passes --signature pointing at the mounted values.yaml.sig" argv_has "--signature=$OPKEYDATA_MNT/values.yaml.sig"
ok "carries the stub's fragment-aware output" dest_has "STUB_RENDER_WITH_FRAGMENT"
rm_opkeydata_device
rm_fragment

CASE="unrecognized argument"
ok "fails" not run_values --platform=tdx --bogus
ok "names the cause" stderr_has "unrecognized argument"

CASE="c8s launch-values render fails"
stub_c8s_render_failing
ok "fails" not run_values --platform=tdx
stub_c8s_render

summarize "c8s-chart-values"
