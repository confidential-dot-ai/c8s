#!/usr/bin/env bash
# Shared helpers for the live-cluster e2e checks under test/e2e/. Source it
# after `set -euo pipefail`:
#
#   . "$(dirname "$0")/lib.sh"

# fail prints a FAIL: line to stderr and exits non-zero. The "FAIL:" prefix is
# the convention CI greps for, so keep both scripts on this one definition.
fail() { echo "FAIL: $*" >&2; exit 1; }

# cw_namespace creates <ns> if missing and opens only PSA enforcement for the
# webhook-injected inventory hostPath. The chart's tenant-pod VAP restores the
# Restricted controls and admits that one read-only sidecar mount; Restricted
# warning and audit stay enabled so drift remains visible. Only the operator's
# PodSecurity-exemption credential may apply the enforce label.
cw_namespace() {
  kubectl create namespace "$1" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label namespace "$1" --overwrite \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/audit=restricted >/dev/null
}
