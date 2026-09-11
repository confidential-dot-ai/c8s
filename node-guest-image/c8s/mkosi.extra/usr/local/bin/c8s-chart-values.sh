#!/bin/sh
# Thin wrapper around `c8s launch-values render --out` (internal/cmds/
# launchvalues), which resolves this guest's own launch measurement (one
# verified self-attestation), loads and verifies the operator key,
# verifies and merges an optional opkeydata values.yaml fragment, and writes
# the HelmChartConfig atomically. See internal/cmds/launchvalues's package
# doc for the trust chain and docs/operator.md, "Launch-time values", for the
# fragment shape and allowlist.
#
# This script's own job is only what a shell running in the guest's mount
# namespace can do:
#
#   - parse --platform.
#   - mount the opkeydata ISO (if present) and locate values.yaml /
#     values.yaml.sig on it, the same way rke2-role.sh mounts joindata.
#   - exec into `c8s launch-values render`.
#
# Fails closed: any mount or render error exits non-zero: this unit's
# [Install] RequiredBy=rke2-server.service means rke2-server does not start
# until it has succeeded. In particular, a values.yaml present on opkeydata
# WITHOUT a values.yaml.sig next to it is a hard failure, not a silent skip —
# an unsigned fragment must never reach the render.
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

DEST="/var/lib/rancher/rke2/server/manifests/c8s-chart-values.yaml"
OPKEYDATA_DEV="/dev/disk/by-label/opkeydata"
OPKEYDATA_MNT="/run/confos/opkeydata"

# --- opkeydata: optional values.yaml + values.yaml.sig, mounted the same
# --- way rke2-role.sh mounts joindata (iso9660, ro, nodev, nosuid, noexec,
# --- bounded). Host-controlled device: pin the fs parser, bound a wedged
# --- mount. A values.yaml present without its .sig is a hard failure below
# --- — an unsigned fragment must never reach the render.
cleanup() {
    if mountpoint -q "$OPKEYDATA_MNT" 2>/dev/null; then
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

# --- render: c8s launch-values render resolves this guest's own measurement,
# --- the operator key, and (if FRAGMENT is set) the verified, allowlisted,
# --- merged fragment, then writes DEST itself (atomically — a temp file
# --- plus rename in the same directory).
set -- launch-values render --platform="$PLATFORM" --out="$DEST"
if [ -n "$FRAGMENT" ]; then
    set -- "$@" --fragment="$FRAGMENT" --signature="$SIGNATURE"
fi

/usr/local/bin/c8s "$@"
