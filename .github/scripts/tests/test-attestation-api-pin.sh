#!/usr/bin/env bash

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
script="$repo_dir/.github/scripts/attestation-api-pin.sh"
fixture_dir=$(mktemp -d)
trap 'rm -rf -- "$fixture_dir"' EXIT

tests=0
pass() {
  tests=$((tests + 1))
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

expect_failure() {
  if "$@" >"$fixture_dir/unexpected.stdout" 2>"$fixture_dir/unexpected.stderr"; then
    fail "command unexpectedly succeeded: $*"
  fi
}

# Offline registry: a tag -> digest table plus a log of every lookup, so a
# test can assert which image reference the script asked for.
registry="$fixture_dir/registry.tsv"
lookups="$fixture_dir/lookups.log"
resolver="$fixture_dir/resolver.sh"
cat >"$resolver" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$1" >>"$lookups"
awk -v ref="\$1" '\$1 == ref {print \$2; found = 1} END {exit !found}' "$registry"
EOF
chmod +x "$resolver"
export C8S_ATTESTATION_API_RESOLVER=$resolver

attest_a=aaaaaaa0000000000000000000000000000000aa
attest_b=bbbbbbb0000000000000000000000000000000bb
attest_unpublished=0000000000000000000000000000000000000000
digest_a=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
digest_b=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
digest_stale=sha256:1111111111111111111111111111111111111111111111111111111111111111
image=ghcr.io/confidential-dot-ai/attestation-api
attest_garbage=ccccccc0000000000000000000000000000000cc
printf '%s\t%s\n' "$image:sha-aaaaaaa" "$digest_a" "$image:sha-bbbbbbb" "$digest_b" \
  "$image:sha-ccccccc" latest >"$registry"

manifest="$fixture_dir/build-pins.json"
cat >"$manifest" <<EOF
{
  "schema_version": 1,
  "builds": {
    "node-image": {
      "confos_ref": "1111111111111111111111111111111111111111",
      "attestation_rs_ref": "$attest_a",
      "mkosi_ref": "3333333333333333333333333333333333333333",
      "mkosi_version": "v27"
    },
    "kata-guest": {
      "confos_ref": "1111111111111111111111111111111111111111",
      "attestation_rs_ref": "$attest_b",
      "mkosi_ref": "3333333333333333333333333333333333333333",
      "mkosi_version": "v27"
    }
  }
}
EOF

# Same shape as the chart's c8sComponents: the cds entry is a decoy so a
# pinnedDigest outside the attestationApi component is never touched.
new_values() {
  local name=$1 digest=$2
  local path="$fixture_dir/$name.yaml"
  cat >"$path" <<EOF
c8sComponents:
  - valuePath: image
    enabledPath: ""
    cdsExempt: false
  - valuePath: cds.image
    enabledPath: ""
    cdsExempt: true
    pinnedDigest: $digest_stale
  - valuePath: attestationApi.image
    enabledPath: attestationApi.enabled
    cdsExempt: false
    ## kept verbatim by stamp
    pinnedDigest: $digest
  - valuePath: ratlsMesh.image
    enabledPath: ratlsMesh.enabled
    cdsExempt: false
EOF
  printf '%s\n' "$path"
}

values=$(new_values aligned "$digest_a")
bash "$script" check --manifest "$manifest" --values "$values" >/dev/null
grep -qx "$image:sha-aaaaaaa" "$lookups" || fail "check did not resolve the sha-<7> tag of the node-image attestation_rs_ref"
pass

values=$(new_values aligned-kata "$digest_b")
bash "$script" check --manifest "$manifest" --values "$values" --domain kata-guest >/dev/null
pass

values=$(new_values stale "$digest_stale")
expect_failure bash "$script" check --manifest "$manifest" --values "$values"
grep -q "$digest_stale" "$fixture_dir/unexpected.stderr" || fail "check did not report the stale digest"
grep -q "stamp --attest $attest_a" "$fixture_dir/unexpected.stderr" || fail "check did not name the stamp remedy"
pass

values=$(new_values stamp "$digest_stale")
expected=$(new_values stamp-expected "$digest_a")
out=$(bash "$script" stamp --values "$values" --attest "$attest_a")
cmp -s "$values" "$expected" || fail "stamp changed more than the attestationApi pinnedDigest line"
grep -q "^stamped " <<<"$out" || fail "stamp did not report the rewrite: $out"
bash "$script" check --manifest "$manifest" --values "$values" >/dev/null
pass

out=$(bash "$script" stamp --values "$values" --attest "$attest_a")
[ "$out" = no-drift ] || fail "idempotent stamp printed '$out'"
cmp -s "$values" "$expected" || fail "idempotent stamp rewrote the file"
pass

values=$(new_values unpublished "$digest_a")
cp -- "$values" "$fixture_dir/unpublished.before"
expect_failure bash "$script" stamp --values "$values" --attest "$attest_unpublished"
cmp -s "$values" "$fixture_dir/unpublished.before" || fail "stamp wrote a pin for an unpublished image"
[ -z "$(find "$fixture_dir" -name 'unpublished.yaml.*')" ] || fail "stamp left a temp file behind"
pass

values=$(new_values garbage "$digest_a")
cp -- "$values" "$fixture_dir/garbage.before"
expect_failure bash "$script" stamp --values "$values" --attest "$attest_garbage"
cmp -s "$values" "$fixture_dir/garbage.before" || fail "stamp wrote a non-digest the resolver returned"
pass

values=$(new_values no-pin "$digest_a")
sed -i.bak '/^    pinnedDigest: '"$digest_a"'$/d' "$values" && rm -f -- "$values.bak"
expect_failure bash "$script" check --manifest "$manifest" --values "$values"
expect_failure bash "$script" stamp --values "$values" --attest "$attest_a"
pass

values=$(new_values bad-pin "$digest_a")
sed -i.bak 's/^    pinnedDigest: '"$digest_a"'$/    pinnedDigest: main/' "$values" && rm -f -- "$values.bak"
expect_failure bash "$script" check --manifest "$manifest" --values "$values"
pass

values=$(new_values args "$digest_a")
expect_failure bash "$script" stamp --values "$values" --attest abc123
expect_failure bash "$script" stamp --values "$values"
expect_failure bash "$script" check --values "$values"
expect_failure bash "$script" check --manifest "$manifest" --values "$values" --domain kernel-snapshot
expect_failure bash "$script" frobnicate --manifest "$manifest" --values "$values"
pass

echo "test-attestation-api-pin: $tests checks passed"
