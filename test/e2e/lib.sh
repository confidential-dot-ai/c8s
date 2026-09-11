#!/usr/bin/env bash
# Shared helpers for the live-cluster e2e checks under test/e2e/. Source it
# after `set -euo pipefail`:
#
#   . "$(dirname "$0")/lib.sh"

# fail prints a FAIL: line to stderr and exits non-zero. The "FAIL:" prefix is
# the convention CI greps for, so keep both scripts on this one definition.
fail() { echo "FAIL: $*" >&2; exit 1; }

# cw_namespace creates <ns> if missing and enforces the current Restricted
# profile. Credential sidecars receive their claims socket through NRI, so
# confidential workloads need no PodSecurity exemption.
cw_namespace() {
  kubectl create namespace "$1" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label namespace "$1" --overwrite \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/audit=restricted >/dev/null
}
