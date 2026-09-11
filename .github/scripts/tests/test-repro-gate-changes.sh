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
  local expected="image=$1" actual
  actual=$(bash "$CLASSIFIER" "$current_manifest" "$base_manifest" "$changed_paths")
  [[ "$actual" == "$expected" ]] || fail "expected $expected, got $actual"
}
reset_case
set_paths README.md
expect_result false
reset_case
set_paths node-guest-image/kernel/c8s.config
expect_result true
reset_case
set_paths .github/scripts/pin-manifest.sh
expect_result true
reset_case
jq '.builds["node-image"].confos_ref = "2222222222222222222222222222222222222222"' "$current_manifest" >"$current_manifest.next"
mv "$current_manifest.next" "$current_manifest"
expect_result true
echo "repro-gate-changes tests passed"
