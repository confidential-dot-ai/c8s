#!/usr/bin/env bash
# Shared helpers for the live-cluster e2e checks under test/e2e/. Source it
# after `set -euo pipefail`:
#
#   . "$(dirname "$0")/lib.sh"

# fail prints a FAIL: line to stderr and exits non-zero. The "FAIL:" prefix is
# the convention CI greps for, so keep both scripts on this one definition.
fail() { echo "FAIL: $*" >&2; exit 1; }

# cw_namespace creates a new <ns> and labels it privileged. Refuse to adopt
# an existing namespace: callers may clean up only one they created. The node
# image enforces the restricted PodSecurity standard outside its platform
# namespaces, and in node mode the webhook mounts the inventory socket into
# every confidential-workload pod as a hostPath, which restricted forbids. A
# namespace hosting CW pods is therefore opened by the operator, whose
# credential may grant PodSecurity exemptions (node-guest-image/README.md,
# "Workload isolation"); the e2e scripts run under that credential.
cw_namespace() {
  CW_NAMESPACE_CREATED=
  kubectl create namespace "$1" >/dev/null || return
  CW_NAMESPACE_CREATED=$1
  kubectl label namespace "$1" \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/warn=privileged \
    pod-security.kubernetes.io/audit=privileged >/dev/null
}

# cw_namespace_owned lets cleanup check ownership without adopting old state.
cw_namespace_owned() { [ "${CW_NAMESPACE_CREATED:-}" = "$1" ]; }
