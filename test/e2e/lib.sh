#!/usr/bin/env bash
# Shared helpers for the live-cluster e2e checks under test/e2e/. Source it
# after `set -euo pipefail`:
#
#   . "$(dirname "$0")/lib.sh"

# fail prints a FAIL: line to stderr and exits non-zero. The "FAIL:" prefix is
# the convention CI greps for, so keep both scripts on this one definition.
fail() { echo "FAIL: $*" >&2; exit 1; }

# cw_namespace creates a new namespace with the current Restricted profile.
# Refuse to adopt an existing namespace: callers may clean up only one they
# created. Credential sidecars receive their claims socket through NRI, so
# confidential workloads need no PodSecurity exemption.
cw_namespace() {
  CW_NAMESPACE_CREATED=
  kubectl create namespace "$1" >/dev/null || return
  CW_NAMESPACE_CREATED=$1
  kubectl label namespace "$1" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/audit=restricted >/dev/null
}

# cw_namespace_owned lets cleanup check ownership without adopting old state.
cw_namespace_owned() { [ "${CW_NAMESPACE_CREATED:-}" = "$1" ]; }
