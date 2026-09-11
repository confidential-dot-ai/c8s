#!/usr/bin/env bash
# Exercise the full production gate against copied inputs; fixture writes are
# scanned as text and never executed. The pinned confos checkout stays read-only.
set -euo pipefail
: "${CONFOS_REF:?CONFOS_REF must be set}"
test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
confos_dir=$(cd "$repo_dir/confos" && pwd -P)
fixture_dir=$(mktemp -d)
trap 'rm -rf -- "$fixture_dir"' EXIT
cp -a "$repo_dir/node-guest-image" "$repo_dir/.github" "$fixture_dir/"
ln -s "$confos_dir" "$fixture_dir/confos"
probe="$fixture_dir/node-guest-image/c8s/mkosi.extra/usr/local/bin/invariant-write-test.sh"
tests=0

fail() { echo "FAIL: $*" >&2; exit 1; }
run_gate() {
  (
    cd "$fixture_dir"
    bash .github/scripts/node-guest-image-invariants.sh
  ) >"$fixture_dir/output" 2>&1
}
accepts() {
  printf '%s\n' "$2" >"$probe"
  if ! run_gate; then
    cat "$fixture_dir/output"
    fail "$1 was rejected"
  fi
  tests=$((tests + 1))
}
rejects() {
  printf '%s\n' "$2" >"$probe"
  if run_gate; then fail "$1 was accepted"; fi
  grep -Fq '/usr/bin/c8s-invariant-probe is written at runtime' "$fixture_dir/output" || {
    cat "$fixture_dir/output"
    fail "$1 failed for an unrelated reason"
  }
  tests=$((tests + 1))
}

# The unchanged AppArmor boot probe itself contains an absolute executable
# followed by 2>&1. Its presence in the baseline must not require writable /usr.
accepts "production baseline" '# no additional runtime writes'
accepts "numeric descriptor duplication" '/usr/bin/aa-exec -- /bin/true 2>&1'
# shellcheck disable=SC2016 # Keep command substitution as scanned fixture text.
accepts "descriptor duplication before command-substitution close" \
  'label=$(/usr/bin/aa-exec -- /bin/true 2>&1)'
accepts "numeric input descriptor duplication" '/usr/bin/aa-exec -- /bin/true 3<&0'
rejects "file redirection" 'printf x > /usr/bin/c8s-invariant-probe'
rejects "file redirection before descriptor duplication" \
  'printf x > /usr/bin/c8s-invariant-probe 2>&1'
rejects "file redirection after descriptor duplication" \
  'printf x 2>&1 > /usr/bin/c8s-invariant-probe'
rejects "file append with descriptor duplication" \
  'printf x >> /usr/bin/c8s-invariant-probe 2>&1'
rejects "copy with descriptor duplication" \
  'cp /tmp/source /usr/bin/c8s-invariant-probe 2>&1'
rejects "mkdir with descriptor duplication" \
  'mkdir /usr/bin/c8s-invariant-probe 2>&1'
echo "$tests node-image invariant assertions passed"
