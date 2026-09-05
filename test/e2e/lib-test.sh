#!/usr/bin/env bash
# Exercise the shared helper itself, with kubectl replaced at its boundary.
set -euo pipefail
test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$test_dir/lib.sh"

calls=()
create_status=0
label_status=0
kubectl() {
  calls+=("$*")
  case "$1" in
    create) return "$create_status" ;;
    label) return "$label_status" ;;
    *) fail "unexpected kubectl command: $*" ;;
  esac
}

cw_namespace c8s-test
[[ ${#calls[@]} == 2 && $CW_NAMESPACE_CREATED == c8s-test ]] || fail "creation ownership not recorded"
[[ ${calls[0]} == 'create namespace c8s-test' ]] || fail "namespace must be created, not adopted"
cw_namespace_owned c8s-test || fail "created namespace not owned"
if cw_namespace_owned another; then fail "unrelated namespace claimed"; fi
[[ ${calls[1]} == 'label namespace c8s-test pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/warn=privileged pod-security.kubernetes.io/audit=privileged' ]] || fail "wrong exemption labels"

calls=()
create_status=1
if cw_namespace existing; then fail "existing namespace accepted"; fi
[[ ${#calls[@]} == 1 && -z $CW_NAMESPACE_CREATED ]] || fail "existing namespace labelled or claimed"

calls=()
create_status=42
status=0
cw_namespace unavailable || status=$?
[[ $status == 42 && ${#calls[@]} == 1 && -z $CW_NAMESPACE_CREATED ]] || fail "create failure not preserved"

calls=()
create_status=0
label_status=1
if cw_namespace denied; then fail "label rejection ignored"; fi
[[ ${#calls[@]} == 2 && $CW_NAMESPACE_CREATED == denied ]] || fail "new namespace lost its cleanup ownership"

echo 'PASS: CW namespace creation, exact labels, collision refusal, create error and label error ownership'
