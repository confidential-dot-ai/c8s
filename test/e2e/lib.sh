#!/usr/bin/env bash
# Shared helpers for the live-cluster e2e checks under test/e2e/. Source it
# after `set -euo pipefail`:
#
#   . "$(dirname "$0")/lib.sh"

# fail prints a FAIL: line to stderr and exits non-zero. The "FAIL:" prefix is
# the convention CI greps for, so keep both scripts on this one definition.
fail() { echo "FAIL: $*" >&2; exit 1; }

# cw_namespace creates <ns> if missing and labels it privileged. The node
# image enforces the restricted PodSecurity standard outside its platform
# namespaces, and in node mode the webhook mounts the inventory socket into
# every confidential-workload pod as a hostPath, which restricted forbids. A
# namespace hosting CW pods is therefore opened by the operator, whose
# credential may grant PodSecurity exemptions (node-guest-image/README.md,
# "Workload isolation"); the e2e scripts run under that credential.
cw_namespace() {
  kubectl create namespace "$1" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label namespace "$1" --overwrite \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/warn=privileged \
    pod-security.kubernetes.io/audit=privileged >/dev/null
}
