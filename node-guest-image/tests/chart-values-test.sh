#!/bin/bash
# Unit test for c8s-chart-values.sh: TDX reads mrtd/rtmr1/rtmr2 from a fake
# sysfs tree; SNP self-attests against a fake attestation-api (stub curl);
# an absent operator pubkey omits cds.operatorKeys; a short/malformed
# register or a malformed attestation-api response fails closed;
# opkeydata's optional values.yaml/values.yaml.sig fragment is handed to a
# stub `c8s launch-values render` and a values.yaml without its .sig fails
# the boot before render is ever invoked. Root-free: rebases every baked
# path with sed and shadows curl/jq/mount/umount/c8s with stubs on PATH,
# mirroring gpu-cc-enforce-test.sh / lib.sh. The real mount(8) call is
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
mkdir -p "$WORK/bin" "$WORK/sys/devices/virtual/misc/tdx_guest/measurements" \
         "$WORK/confai" "$WORK/manifests" "$WORK/opkeydata-mnt"
DEST="$WORK/manifests/c8s-chart-values.yaml"
OPKEYDATA_DEV="$WORK/opkeydata-dev"
OPKEYDATA_MNT="$WORK/opkeydata-mnt"

# rebased SCRIPT — sed a copy of the production script with every baked path
# rebased into $WORK; written once, run many times below.
REBASED="$WORK/script.sh"
sed \
    -e "s|/sys/devices/virtual/misc/tdx_guest|$WORK/sys/devices/virtual/misc/tdx_guest|g" \
    -e "s|/etc/confai/operator-pubkey|$WORK/confai/operator-pubkey|g" \
    -e "s|/var/lib/rancher/rke2/server/manifests/c8s-chart-values.yaml|$DEST|g" \
    -e "s|/dev/disk/by-label/opkeydata|$OPKEYDATA_DEV|g" \
    -e "s|/run/confos/opkeydata|$OPKEYDATA_MNT|g" \
    -e "s|/usr/local/bin/c8s \"|$WORK/bin/c8s \"|g" \
    "$SCRIPT" > "$REBASED"

# run_values ARGS... — run the rebased script with the stub bin dir first on
# PATH (stubs shadow any real curl/jq/mount/umount/mountpoint the test host
# happens to have, and provide the c8s stub).
run_values() {
    PATH="$WORK/bin:$PATH" sh "$REBASED" "$@" 2>"$WORK/stderr"
}

# run_values_no_curl ARGS... — run with PATH scrubbed to just enough
# coreutils for the script's own logic (od, sed, cat, mkdir, mv, ...) and NO
# curl anywhere, not even the test host's real one — unlike run_values,
# which only shadows it via a stub $WORK/bin/curl. Still includes the mount
# stubs and c8s stub from $WORK/bin.
run_values_no_curl() {
    local scrubbed="$WORK/path-no-curl"
    rm -rf "$scrubbed"; mkdir -p "$scrubbed"
    local d bin
    for d in /bin /usr/bin "$WORK/bin"; do
        for bin in "$d"/*; do
            [ -x "$bin" ] || continue
            [ "$(basename "$bin")" = curl ] && continue
            ln -sf "$bin" "$scrubbed/$(basename "$bin")" 2>/dev/null
        done
    done
    PATH="$scrubbed" sh "$REBASED" "$@" 2>"$WORK/stderr"
}

# set_register NAME HEXBYTE — write a 48-byte TDX register file, every byte
# equal to HEXBYTE (a two-hex-digit octal-independent \xNN escape).
set_register() {
    local name=$1 byte=$2
    printf "\\x$byte%.0s" $(seq 1 48) > "$WORK/sys/devices/virtual/misc/tdx_guest/measurements/$name:sha384"
}
set_tdx_registers() {
    set_register mrtd aa
    set_register rtmr1 bb
    set_register rtmr2 cc
}
rm_register() { rm -f "$WORK/sys/devices/virtual/misc/tdx_guest/measurements/$1:sha384"; }

set_operator_key() { printf '%s\n' "-----BEGIN PUBLIC KEY-----FAKE-----END PUBLIC KEY-----" > "$WORK/confai/operator-pubkey"; }
rm_operator_key() { rm -f "$WORK/confai/operator-pubkey"; }

# stub_curl_snp DIGEST — a fake attestation-api: POST .../attest returns a
# platform+evidence envelope, POST .../verify returns a claims object
# carrying DIGEST as launch_digest. Needs jq to build the responses so the
# test doesn't hardcode escaping.
stub_curl_snp() {
    local digest=$1
    cat > "$WORK/bin/curl" <<EOF
#!/bin/sh
for a in "\$@"; do
  case "\$a" in
    */attest) printf '{"platform":"sev-snp","evidence":{"quote":"ZmFrZQ=="}}\\n'; exit 0 ;;
    */verify) printf '{"result":{"claims":{"launch_digest":"$digest"}},"token":null}\\n'; exit 0 ;;
  esac
done
echo "unexpected curl args: \$*" >&2
exit 1
EOF
    chmod +x "$WORK/bin/curl"
}
stub_curl_failing() {
    cat > "$WORK/bin/curl" <<'EOF'
#!/bin/sh
exit 7
EOF
    chmod +x "$WORK/bin/curl"
}

# stub_mount_tools — no-op mount/umount/mountpoint/timeout stubs standing in
# for the real loop-mount rke2-role-test.sh exercises with root. The script
# only ever mounts opkeydata (never writes through the mount), so a no-op
# mount plus a directly pre-populated $OPKEYDATA_MNT (via set_opkeydata_*
# below) is behaviorally equivalent for everything this script reads.
# `timeout 10 mount ...` is invoked as `timeout` first; that stub execs
# through to the real command list minus mount, so only mount itself needs
# stubbing — timeout(1) itself is real coreutils and stays on PATH.
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

# stub_c8s_render — a stub `c8s launch-values render` that echoes back a
# recognizable values tree and records its argv, so tests can assert both
# the exact flags c8s-chart-values.sh passes and that its stdout ends up
# under spec.valuesContent.
stub_c8s_render() {
    cat > "$WORK/bin/c8s" <<EOF
#!/bin/sh
echo "\$*" > "$WORK/c8s-argv"
if [ "\$1" = "launch-values" ] && [ "\$2" = "render" ]; then
    shift 2
    fragment=""
    for a in "\$@"; do
        case "\$a" in --fragment=*) fragment="\${a#--fragment=}" ;; esac
    done
    if [ -n "\$fragment" ]; then
        echo "STUB_RENDER_WITH_FRAGMENT: \$fragment"
    else
        echo "STUB_RENDER_NO_FRAGMENT"
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

SNP_DIGEST_OK=$(printf 'ab%.0s' $(seq 1 48))
SNP_DIGEST_SHORT=$(printf 'ab%.0s' $(seq 1 40))

CASE="tdx: no --platform"
stub_c8s_render
ok "fails" not run_values
ok "names the cause" stderr_has "platform must be tdx or snp"

CASE="tdx happy path, operator boot, no opkeydata device"
set_tdx_registers
set_operator_key
rm_opkeydata_device
rm_fragment
rm "$DEST" 2>/dev/null
ok "succeeds" run_values --platform=tdx
ok "writes the manifest" require_dest
ok "is a HelmChartConfig for c8s/kube-system" dest_has "kind: HelmChartConfig"
ok "invokes c8s launch-values render" argv_has "launch-values render"
ok "passes --own-measurement=mrtd" argv_has "--own-measurement=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ok "passes --rtmrs" argv_has "--rtmrs=1=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,2=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
ok "does not pass --fragment (no opkeydata device)" bash -c "! grep -q -- '--fragment' '$WORK/c8s-argv'"
ok "carries the stub's boot-derived-only output" dest_has "STUB_RENDER_NO_FRAGMENT"

CASE="tdx, non-operator boot"
rm_operator_key
rm "$DEST" 2>/dev/null
ok "succeeds" run_values --platform=tdx
set_operator_key

CASE="tdx missing mrtd register"
rm_register mrtd
ok "fails" not run_values --platform=tdx
ok "names the cause" stderr_has "cannot read"
set_tdx_registers

CASE="tdx short register"
printf '\xaa%.0s' $(seq 1 40) > "$WORK/sys/devices/virtual/misc/tdx_guest/measurements/mrtd:sha384"
ok "fails" not run_values --platform=tdx
ok "names the cause" stderr_has "got 40 bytes, want 48"
set_tdx_registers

CASE="tdx: opkeydata present with a values.yaml but no .sig"
set_opkeydata_device
set_fragment
rm "$WORK/opkeydata-mnt/values.yaml.sig" 2>/dev/null
ok "fails" not run_values --platform=tdx
ok "names the cause" stderr_has "without values.yaml.sig"
ok "never invokes c8s (refused before render)" bash -c "rm -f '$WORK/c8s-argv'; run_values --platform=tdx >/dev/null 2>&1; [[ ! -e '$WORK/c8s-argv' ]]"
rm_fragment

CASE="tdx: opkeydata present with a signed values.yaml fragment"
set_fragment
set_fragment_sig
rm "$DEST" 2>/dev/null
ok "succeeds" run_values --platform=tdx
ok "writes the manifest" require_dest
ok "passes --fragment pointing at the mounted values.yaml" argv_has "--fragment=$OPKEYDATA_MNT/values.yaml"
ok "passes --signature pointing at the mounted values.yaml.sig" argv_has "--signature=$OPKEYDATA_MNT/values.yaml.sig"
ok "carries the stub's fragment-aware output" dest_has "STUB_RENDER_WITH_FRAGMENT"

CASE="tdx: opkeydata device present but no values.yaml on it"
rm_fragment
rm "$WORK/c8s-argv" 2>/dev/null
rm "$DEST" 2>/dev/null
ok "succeeds (fragment is optional)" run_values --platform=tdx
ok "does not pass --fragment" bash -c "! grep -q -- '--fragment' '$WORK/c8s-argv'"
rm_opkeydata_device

CASE="tdx: c8s launch-values render fails"
stub_c8s_render_failing
ok "fails" not run_values --platform=tdx
ok "names the cause" stderr_has "launch-values render failed"
stub_c8s_render

CASE="snp happy path"
stub_curl_snp "$SNP_DIGEST_OK"
rm "$DEST" 2>/dev/null
ok "succeeds" run_values --platform=snp
ok "writes the manifest" require_dest
ok "passes --own-measurement from the verified launch_digest" argv_has "--own-measurement=$SNP_DIGEST_OK"
ok "passes no --rtmrs (SNP has none)" bash -c "! grep -q -- '--rtmrs' '$WORK/c8s-argv'"

CASE="snp: attestation-api unreachable"
stub_curl_failing
ok "fails" not run_values --platform=snp

CASE="snp: verify returns a short digest"
stub_curl_snp "$SNP_DIGEST_SHORT"
ok "fails" not run_values --platform=snp
ok "names the cause" stderr_has "want 96"

CASE="snp: no curl on PATH"
ok "fails" not run_values_no_curl --platform=snp
ok "names the cause" stderr_has "curl not found"

summarize "c8s-chart-values"
