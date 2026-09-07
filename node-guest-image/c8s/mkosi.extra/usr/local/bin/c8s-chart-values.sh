#!/bin/sh
# Write the launch-time-only inputs the baked HelmChart c8s cannot carry
# (server/manifests/c8s-chart.yaml, rendered from c8s-chart.yaml.in at build
# time): the operator key, this node's own measurement, and (Phase 0b) an
# optional signed opkeydata values.yaml fragment are only known once the
# guest has booted and attested, not at image-build time.
#
# Renders a HelmChartConfig c8s in kube-system to
# server/manifests/c8s-chart-values.yaml; RKE2's supervisor merges a
# HelmChartConfig into the matching HelmChart's spec it already manages (see
# rke2-cilium-config.yaml for the same mechanism), so this never touches the
# measured c8s-chart.yaml itself.
#
# This script resolves the boot-only inputs and hands them to
# `c8s launch-values render` (internal/cmds/launchvalues), which owns
# spec.valuesContent from here: it builds the boot-derived tree (this
# guest's own measurement/RTMR pins, cds.operatorKeys) and, when opkeydata
# carries a values.yaml fragment, verifies its signature under the measured
# operator key, checks it names this guest's own measurement, validates
# every leaf against an explicit allowlist, and deep-merges it UNDER the
# boot-derived keys so a fragment can never override them. This script's own
# job is only:
#
#   - resolve this guest's own launch measurement and TDX RTMR pins (TDX:
#     the tdx_guest sysfs; SNP: self-attest against the local
#     attestation-api and read the verified launch_digest claim).
#   - mount the opkeydata ISO (if present) and locate values.yaml /
#     values.yaml.sig on it, the same way rke2-role.sh mounts joindata.
#   - write the rendered HelmChartConfig atomically.
#
# TDX reads mrtd/rtmr1/rtmr2 straight from the tdx_guest sysfs — a plain
# read, no attestation round trip; the kernel TSM node is this guest's own
# measured state, not a claim a peer could forge. SNP has no such sysfs: its
# launch measurement is only visible in an attestation report, so this
# self-attests against the baked attestation-api and reads the verified
# launch_digest claim — the same self-attest-then-verify shape
# credrelease.verifyKeyLaunchBound uses for the operator-key HOSTDATA check
# (internal/cmds/credrelease/binding.go), reimplemented here in shell (curl +
# jq) rather than by shelling out to the c8s binary, so this script has no
# dependency beyond what mkosi.conf already bakes for on-node debugging.
#
# Fails closed: any read, mount, attestation, render, or write error exits
# non-zero: this unit's [Install] RequiredBy=rke2-server.service means
# rke2-server does not start until it has succeeded. In particular, a
# values.yaml present on opkeydata WITHOUT a values.yaml.sig next to it is a
# hard failure, not a silent skip — an unsigned fragment must never reach
# the render.
set -eu

PLATFORM=""
for arg in "$@"; do
    case "$arg" in
        --platform=*) PLATFORM="${arg#--platform=}" ;;
        *) echo "c8s-chart-values: unrecognized argument: $arg" >&2; exit 1 ;;
    esac
done
case "$PLATFORM" in
    tdx|snp) ;;
    *) echo "c8s-chart-values: --platform must be tdx or snp, got '${PLATFORM}'" >&2; exit 1 ;;
esac

ATTESTATION_API_URL="http://127.0.0.1:8400"
OPERATOR_PUBKEY_PATH="/etc/confai/operator-pubkey"
DEST="/var/lib/rancher/rke2/server/manifests/c8s-chart-values.yaml"
OPKEYDATA_DEV="/dev/disk/by-label/opkeydata"
OPKEYDATA_MNT="/run/confos/opkeydata"

# readRegister PATH — hex-encode a 48-byte (SHA-384) binary register file.
readRegister() {
    path="$1"
    [ -r "$path" ] || { echo "c8s-chart-values: cannot read $path (is this a TDX guest with runtime measurement?)" >&2; exit 1; }
    size=$(wc -c < "$path")
    if [ "$size" -ne 48 ]; then
        echo "c8s-chart-values: $path: got $size bytes, want 48" >&2
        exit 1
    fi
    # -v: do not collapse repeated lines with '*' — a register whose bytes
    # repeat (a plausible all-zero or all-same-byte pin) would otherwise
    # come out truncated instead of failing loudly.
    hex=$(od -An -v -tx1 "$path" | tr -d ' \n')
    if [ "${#hex}" -ne 96 ]; then
        echo "c8s-chart-values: $path: hex-encoded to ${#hex} chars, want 96" >&2
        exit 1
    fi
    printf '%s' "$hex"
}

# --- TDX: direct sysfs read, no network -------------------------------------
tdxMeasurements() {
    mrtd=$(readRegister /sys/devices/virtual/misc/tdx_guest/measurements/mrtd:sha384)
    rtmr1=$(readRegister /sys/devices/virtual/misc/tdx_guest/measurements/rtmr1:sha384)
    rtmr2=$(readRegister /sys/devices/virtual/misc/tdx_guest/measurements/rtmr2:sha384)
    MEASUREMENT="$mrtd"
    RTMR_PINS="1=$rtmr1,2=$rtmr2"
}

# --- SNP: self-attest against the local attestation-api, verify, read the
# --- claimed launch_digest. Mirrors credrelease.verifyKeyLaunchBound's
# --- attest-then-verify shape (binding.go verifiedSelfHostData), but this
# --- reads the LAUNCH_DIGEST claim rather than the HOSTDATA claim, and
# --- (unlike that operator-key check) does not bind a REPORTDATA nonce to
# --- anything: nothing here authenticates a caller, it only reads this
# --- guest's own attested launch measurement.
snpMeasurement() {
    have curl || { echo "c8s-chart-values: curl not found on PATH" >&2; exit 1; }
    have jq || { echo "c8s-chart-values: jq not found on PATH" >&2; exit 1; }

    # 48 zero bytes, base64-encoded: report_data has no binding purpose here
    # (see header), so a fixed all-zero anchor is as good as a random one and
    # keeps the request reproducible for debugging. Precomputed rather than
    # built with dd/tr: base64(bytes([0]*48)) is constant.
    report_data="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    attest_req=$(jq -nc --arg rd "$report_data" '{report_data: $rd, platform: "auto"}')
    attest_resp=$(curl -fsS --max-time 15 -X POST "$ATTESTATION_API_URL/attest" \
        -H 'Content-Type: application/json' -d "$attest_req") \
        || { echo "c8s-chart-values: POST $ATTESTATION_API_URL/attest failed" >&2; exit 1; }

    evidence_platform=$(printf '%s' "$attest_resp" | jq -r '.platform // empty')
    evidence=$(printf '%s' "$attest_resp" | jq -c '.evidence // empty')
    if [ -z "$evidence_platform" ] || [ -z "$evidence" ] || [ "$evidence" = "null" ]; then
        echo "c8s-chart-values: /attest response missing platform or evidence: $attest_resp" >&2
        exit 1
    fi

    verify_req=$(jq -nc --arg p "$evidence_platform" --argjson e "$evidence" '{platform: $p, evidence: $e}')
    verify_resp=$(curl -fsS --max-time 15 -X POST "$ATTESTATION_API_URL/verify" \
        -H 'Content-Type: application/json' -d "$verify_req") \
        || { echo "c8s-chart-values: POST $ATTESTATION_API_URL/verify failed" >&2; exit 1; }

    digest=$(printf '%s' "$verify_resp" | jq -r '.result.claims.launch_digest // empty')
    case "$digest" in
        '') echo "c8s-chart-values: /verify response carries no launch_digest claim: $verify_resp" >&2; exit 1 ;;
        *[!0-9a-fA-F]*) echo "c8s-chart-values: launch_digest is not hex: $digest" >&2; exit 1 ;;
    esac
    if [ "${#digest}" -ne 96 ]; then
        echo "c8s-chart-values: launch_digest is ${#digest} hex chars, want 96 (48 bytes)" >&2
        exit 1
    fi
    MEASUREMENT=$(printf '%s' "$digest" | tr 'A-F' 'a-f')
    RTMR_PINS=""  # RTMRs are TDX-only.
}

have() { command -v "$1" >/dev/null 2>&1; }

MEASUREMENT=""
RTMR_PINS=""
case "$PLATFORM" in
    tdx) tdxMeasurements ;;
    snp) snpMeasurement ;;
esac
[ -n "$MEASUREMENT" ] || { echo "c8s-chart-values: resolved an empty measurement" >&2; exit 1; }

# --- operator key: absent file = non-operator boot. c8s launch-values
# --- render makes the same check on --operator-pubkey and, when absent,
# --- omits cds.operatorKeys from its boot-derived tree entirely rather than
# --- failing (LoadMeasuredOperatorKey has nothing staged to load either).
# --- This is just the boot log message; the gate itself lives in render.
if [ -r "$OPERATOR_PUBKEY_PATH" ]; then
    echo "c8s-chart-values: operator boot — cds.operatorKeys will be set"
else
    echo "c8s-chart-values: no operator pubkey at $OPERATOR_PUBKEY_PATH — non-operator boot, allowlist writes stay disabled"
fi

# --- opkeydata: optional values.yaml + values.yaml.sig, mounted the same
# --- way rke2-role.sh mounts joindata (iso9660, ro, nodev, nosuid, noexec,
# --- bounded). Host-controlled device: pin the fs parser, bound a wedged
# --- mount. A values.yaml present without its .sig is a hard failure below
# --- — an unsigned fragment must never reach the render.
#
# One cleanup trap for the whole rest of the script (mount + TMP), not one
# per resource: a second `trap ... EXIT` later would silently replace this
# one and leak the mount if it fires before the mount is torn down.
TMP="${DEST}.tmp.$$"
cleanup() {
    rm -f "$TMP"
    if [ -n "$FRAGMENT" ] || mountpoint -q "$OPKEYDATA_MNT" 2>/dev/null; then
        umount "$OPKEYDATA_MNT" 2>/dev/null || true
    fi
}
trap cleanup EXIT

FRAGMENT=""
SIGNATURE=""
if [ -e "$OPKEYDATA_DEV" ]; then
    mkdir -p "$OPKEYDATA_MNT"
    timeout 10 mount -t iso9660 -o ro,nodev,nosuid,noexec "$OPKEYDATA_DEV" "$OPKEYDATA_MNT"

    if [ -r "$OPKEYDATA_MNT/values.yaml" ]; then
        if [ ! -r "$OPKEYDATA_MNT/values.yaml.sig" ]; then
            echo "c8s-chart-values: $OPKEYDATA_MNT/values.yaml is present without values.yaml.sig — refusing an unsigned launch-values fragment" >&2
            exit 1
        fi
        FRAGMENT="$OPKEYDATA_MNT/values.yaml"
        SIGNATURE="$OPKEYDATA_MNT/values.yaml.sig"
        echo "c8s-chart-values: opkeydata carries a signed values.yaml fragment"
    fi
fi

# --- render: c8s launch-values render owns spec.valuesContent from here —
# --- boot-derived keys plus (if FRAGMENT is set) the verified, allowlisted,
# --- deep-merged fragment. See internal/cmds/launchvalues.
set -- launch-values render \
    --platform="$PLATFORM" \
    --attestation-api-url="$ATTESTATION_API_URL" \
    --operator-pubkey="$OPERATOR_PUBKEY_PATH" \
    --own-measurement="$MEASUREMENT"
if [ -n "$RTMR_PINS" ]; then
    set -- "$@" --rtmrs="$RTMR_PINS"
fi
if [ -n "$FRAGMENT" ]; then
    set -- "$@" --fragment="$FRAGMENT" --signature="$SIGNATURE"
fi

VALUES_CONTENT=$(/usr/local/bin/c8s "$@") \
    || { echo "c8s-chart-values: c8s launch-values render failed" >&2; exit 1; }
[ -n "$VALUES_CONTENT" ] || { echo "c8s-chart-values: c8s launch-values render produced no output" >&2; exit 1; }

# Unmount as soon as the fragment (if any) has been read and rendered — the
# write below no longer needs opkeydata.
if [ -n "$FRAGMENT" ] || mountpoint -q "$OPKEYDATA_MNT" 2>/dev/null; then
    umount "$OPKEYDATA_MNT" 2>/dev/null || true
fi

# --- write ---------------------------------------------------------------
mkdir -p "$(dirname "$DEST")"

{
    echo "# Rendered at boot by c8s-chart-values.service — DO NOT EDIT."
    echo "# Launch-time inputs the baked HelmChart c8s (c8s-chart.yaml) cannot carry"
    echo "# itself. RKE2 merges this into that HelmChart's spec; see"
    echo "# node-guest-image/c8s/mkosi.extra/usr/local/bin/c8s-chart-values.sh and"
    echo "# internal/cmds/launchvalues."
    echo "apiVersion: helm.cattle.io/v1"
    echo "kind: HelmChartConfig"
    echo "metadata:"
    echo "  name: c8s"
    echo "  namespace: kube-system"
    echo "spec:"
    echo "  valuesContent: |-"
    printf '%s\n' "$VALUES_CONTENT" | sed 's/^/    /'
} > "$TMP"

mv "$TMP" "$DEST"
trap - EXIT
prefix=$(printf '%.8s' "$MEASUREMENT")
echo "c8s-chart-values: wrote $DEST (measurement ${prefix}...)"
