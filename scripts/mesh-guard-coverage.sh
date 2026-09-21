#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo "Guard enforcement tests require Linux" >&2
  exit 1
fi
sudo -n unshare --net true

profile="${1:?usage: mesh-guard-coverage.sh <coverage-profile>}"
if [[ $(head -n 1 "$profile") != "mode: atomic" ]]; then
  echo "Expected an atomic coverage profile" >&2
  exit 1
fi
for binary in ip iptables iptables-restore ip6tables ip6tables-restore; do
  if ! command -v "$binary" >/dev/null; then
    if ! command -v apt-get >/dev/null; then
      echo "Install iproute2 and iptables before running guard coverage" >&2
      exit 1
    fi
    sudo -n apt-get update
    sudo -n apt-get install -y iproute2 iptables
    break
  fi
done

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

go test -c -race -coverpkg=./... -o "$build_dir/meshnetns.test" ./internal/meshnetns
sudo -n "$build_dir/meshnetns.test" -test.v -test.timeout=3m \
  -test.run '^TestGuardCountsPodTCPAndNonTCPDrops$' \
  -test.coverprofile="$build_dir/guard.out" | tee "$build_dir/guard.log"
if grep -Eq -- '^[[:space:]]*--- SKIP:' "$build_dir/guard.log"; then
  echo "Required guard enforcement test skipped" >&2
  exit 1
fi
if ! grep -Eq -- '^--- PASS: TestGuardCountsPodTCPAndNonTCPDrops ' "$build_dir/guard.log"; then
  echo "Required guard enforcement test did not pass" >&2
  exit 1
fi
tail -n +2 "$build_dir/guard.out" >> "$profile"
