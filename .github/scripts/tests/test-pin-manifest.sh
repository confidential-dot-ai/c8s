#!/usr/bin/env bash

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
script="$repo_dir/.github/scripts/pin-manifest.sh"
source_manifest="$repo_dir/.github/build-pins.json"
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

new_fixture() {
  local name=$1
  local path="$fixture_dir/$name.json"
  cp -- "$source_manifest" "$path"
  printf '%s\n' "$path"
}

new_confos=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
new_attest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
new_mkosi=cccccccccccccccccccccccccccccccccccccccc

bash "$script" validate --manifest "$source_manifest" >/dev/null
[[ $(jq -r '.builds["node-image"].confos_ref' "$source_manifest") == \
  cffb512383ca0cfdc966e4a981319411e7840ba9 ]] || fail "node default moved"
[[ $(jq -r '.builds["kata-guest"].confos_ref' "$source_manifest") == \
  14e770f26f912d360f1a60a464145c3ee5615124 ]] || fail "kata default moved"
[[ $(jq -r '.builds["kernel-snapshot"].confos_ref' "$source_manifest") == \
  3e6f858f93e1b85c6d1473aa4a031fdefb387710 ]] || fail "kernel default moved"
pass

exported=$(bash "$script" export --manifest "$source_manifest" \
  --domain node-image --format github-env)
grep -Fxq 'MKOSI_VERSION=v27' <<<"$exported" ||
  fail "node environment export is incomplete"
grep -Eq '^CONFOS_REF=[0-9a-f]{40}$' <<<"$exported" ||
  fail "node confos export is invalid"
pass

exported=$(bash "$script" export --manifest "$source_manifest" \
  --domain kernel-snapshot --format github-output \
  --confos-override refs/heads/measurement-check)
grep -Fxq 'confos=refs/heads/measurement-check' <<<"$exported" ||
  fail "safe confos override was not exported"
if grep -q '^attest=' <<<"$exported"; then
  fail "kernel export unexpectedly contains an attestation pin"
fi
expect_failure bash "$script" export --manifest "$source_manifest" \
  --domain node-image --format github-env \
  --confos-override $'main\nINJECTED=value'
pass

node_fixture=$(new_fixture node)
kata_before=$(jq -c '.builds["kata-guest"]' "$node_fixture")
kernel_before=$(jq -c '.builds["kernel-snapshot"]' "$node_fixture")
bash "$script" update --manifest "$node_fixture" --domain node-image \
  --confos "$new_confos" --attest "$new_attest" \
  --mkosi-sha "$new_mkosi" --mkosi-ver v28 >/dev/null
[[ $(jq -r '.builds["node-image"].attestation_rs_ref' "$node_fixture") == \
  "$new_attest" ]] || fail "node attestation pin did not update"
[[ $(jq -c '.builds["kata-guest"]' "$node_fixture") == "$kata_before" ]] ||
  fail "node update changed kata pins"
[[ $(jq -c '.builds["kernel-snapshot"]' "$node_fixture") == "$kernel_before" ]] ||
  fail "node update changed kernel pins"
pass

kata_fixture=$(new_fixture kata)
node_before=$(jq -c '.builds["node-image"]' "$kata_fixture")
bash "$script" update --manifest "$kata_fixture" --domain kata-guest \
  --confos "$new_confos" --attest "$new_attest" \
  --mkosi-sha "$new_mkosi" --mkosi-ver v28 >/dev/null
[[ $(jq -r '.builds["kata-guest"].confos_ref' "$kata_fixture") == \
  "$new_confos" ]] || fail "kata confos pin did not update"
[[ $(jq -r '.builds["kernel-snapshot"].confos_ref' "$kata_fixture") == \
  "$new_confos" ]] || fail "kernel confos pin did not follow kata"
[[ $(jq -r '.builds["kernel-snapshot"].mkosi_ref' "$kata_fixture") == \
  "$new_mkosi" ]] || fail "kernel mkosi pin did not follow kata"
[[ $(jq -c '.builds["node-image"]' "$kata_fixture") == "$node_before" ]] ||
  fail "kata update changed node pins"
pass

no_drift_fixture=$(new_fixture no-drift)
jq -c . "$no_drift_fixture" >"$no_drift_fixture.compact"
mv "$no_drift_fixture.compact" "$no_drift_fixture"
cp "$no_drift_fixture" "$no_drift_fixture.before"
node_confos=$(jq -r '.builds["node-image"].confos_ref' "$no_drift_fixture")
node_attest=$(jq -r '.builds["node-image"].attestation_rs_ref' "$no_drift_fixture")
node_mkosi=$(jq -r '.builds["node-image"].mkosi_ref' "$no_drift_fixture")
node_version=$(jq -r '.builds["node-image"].mkosi_version' "$no_drift_fixture")
result=$(bash "$script" update --manifest "$no_drift_fixture" \
  --domain node-image --confos "$node_confos" --attest "$node_attest" \
  --mkosi-sha "$node_mkosi" --mkosi-ver "$node_version")
[[ "$result" == no-drift ]] || fail "no-drift result was not reported"
cmp -s "$no_drift_fixture" "$no_drift_fixture.before" ||
  fail "no-drift update rewrote the manifest"
pass

invalid_target=$(new_fixture invalid-target)
cp "$invalid_target" "$invalid_target.before"
expect_failure bash "$script" update --manifest "$invalid_target" \
  --domain node-image --confos "$new_confos" --attest "$new_attest" \
  --mkosi-sha not-a-sha --mkosi-ver v28
cmp -s "$invalid_target" "$invalid_target.before" ||
  fail "invalid target changed the manifest"
pass

unknown_key=$(new_fixture unknown-key)
jq '.builds["node-image"].unexpected = true' "$unknown_key" >"$unknown_key.next"
mv "$unknown_key.next" "$unknown_key"
expect_failure bash "$script" validate --manifest "$unknown_key"
pass

duplicate_key=$(new_fixture duplicate-key)
sed '1,/"schema_version": 1/s/"schema_version": 1/"schema_version": 1, "schema_version": 1/' \
  "$duplicate_key" >"$duplicate_key.next"
mv "$duplicate_key.next" "$duplicate_key"
expect_failure bash "$script" validate --manifest "$duplicate_key"
pass

nested_duplicate=$(new_fixture nested-duplicate)
existing_node_confos=$(jq -r '.builds["node-image"].confos_ref' \
  "$nested_duplicate")
sed "1,/\"confos_ref\": \"$existing_node_confos\"/s/\"confos_ref\": \"$existing_node_confos\"/\"confos_ref\": \"$existing_node_confos\", \"confos_ref\": \"$existing_node_confos\"/" \
  "$nested_duplicate" >"$nested_duplicate.next"
mv "$nested_duplicate.next" "$nested_duplicate"
expect_failure bash "$script" validate --manifest "$nested_duplicate"
pass

divergent=$(new_fixture divergent)
jq '.builds["kernel-snapshot"].mkosi_ref = "7777777777777777777777777777777777777777"' \
  "$divergent" >"$divergent.next"
mv "$divergent.next" "$divergent"
expect_failure bash "$script" validate --manifest "$divergent"
pass

mode_fixture=$(new_fixture mode)
chmod 640 "$mode_fixture"
bash "$script" update --manifest "$mode_fixture" --domain node-image \
  --confos "$new_confos" --attest "$new_attest" \
  --mkosi-sha "$new_mkosi" --mkosi-ver v28 >/dev/null
mode=$(stat -c %a "$mode_fixture" 2>/dev/null || stat -f %Lp "$mode_fixture")
[[ "$mode" == 640 ]] || fail "manifest mode changed to $mode"
pass

echo "pin-manifest: $tests tests passed"
