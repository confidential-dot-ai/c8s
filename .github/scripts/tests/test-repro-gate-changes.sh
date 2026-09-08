#!/usr/bin/env bash

set -euo pipefail

TEST_SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly TEST_SCRIPT_DIR
ROOT=$(cd -- "$TEST_SCRIPT_DIR/../../.." && pwd)
readonly ROOT
readonly CLASSIFIER="$TEST_SCRIPT_DIR/../repro-gate-changes"

fail() {
  echo "test-repro-gate-changes: $*" >&2
  exit 1
}

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/test-repro-gate-changes.XXXXXXXX")
trap 'rm -rf "$test_dir"' EXIT
base_manifest="$test_dir/base.json"
current_manifest="$test_dir/current.json"
changed_paths="$test_dir/changed-paths"

reset_case() {
  cp "$ROOT/.github/build-pins.json" "$base_manifest"
  cp "$base_manifest" "$current_manifest"
  : >"$changed_paths"
}

set_paths() {
  : >"$changed_paths"
  local path
  for path in "$@"; do
    printf '%s\0' "$path" >>"$changed_paths"
  done
}

expect_result() {
  local want_image=$1 want_kernel=$2 actual expected
  actual=$(bash "$CLASSIFIER" "$current_manifest" "$base_manifest" "$changed_paths")
  expected=$(printf 'image=%s\nkernel_snapshot=%s' "$want_image" "$want_kernel")
  [ "$actual" = "$expected" ] || {
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    fail "classification differs"
  }
}

reset_case
set_paths docs/development.md
expect_result false false

reset_case
set_paths node-guest-image/mkosi.conf
expect_result true false

reset_case
set_paths kata-guest-base/kernel/container.config
expect_result false true

reset_case
set_paths .github/actions/setup-mkosi/action.yml
expect_result true true

reset_case
jq '.builds["node-image"].confos_ref = "1111111111111111111111111111111111111111"' \
  "$base_manifest" >"$current_manifest"
set_paths .github/build-pins.json
expect_result true false

reset_case
jq '.builds["kernel-snapshot"].confos_ref = "2222222222222222222222222222222222222222"' \
  "$base_manifest" >"$current_manifest"
set_paths .github/build-pins.json
expect_result false true

reset_case
jq '.builds["kata-guest"].attestation_rs_ref = "3333333333333333333333333333333333333333"' \
  "$base_manifest" >"$current_manifest"
set_paths .github/build-pins.json
expect_result false false

reset_case
jq '.builds["kata-guest"].confos_ref = "4444444444444444444444444444444444444444"' \
  "$base_manifest" >"$current_manifest"
set_paths .github/build-pins.json
if bash "$CLASSIFIER" "$current_manifest" "$base_manifest" "$changed_paths" \
  >"$test_dir/unexpected.stdout" 2>"$test_dir/unexpected.stderr"; then
  fail "kata-guest confos change without a snapshot-lineage change unexpectedly passed"
fi
grep -q 'must advance kernel-snapshot.confos_ref' "$test_dir/unexpected.stderr" ||
  fail "kata-guest confos mismatch did not explain the required snapshot-lineage change"

reset_case
printf 'not-json\n' >"$current_manifest"
if bash "$CLASSIFIER" "$current_manifest" "$base_manifest" "$changed_paths" \
  >"$test_dir/unexpected.stdout" 2>"$test_dir/unexpected.stderr"; then
  fail "malformed current manifest unexpectedly passed"
fi

echo "repro gate change-classification tests passed"
