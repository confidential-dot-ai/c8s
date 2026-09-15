#!/usr/bin/env bash
# Installs the node-image host toolchain with confos's snapshot-pinned
# host-deps (confos#36), retrying the whole transaction: host-deps bounds
# each file fetch but has no transaction retry, so a snapshot.ubuntu.com
# 5xx mid-fetch fails it outright. Extra arguments (--cache-dir ...) go to
# host-deps. Run from the directory holding confidential-os-builder/.
#
# No ovmf-inteltdx: #82 TDX firmware is vendored (firmware/OVMF.inteltdx.fd);
# base ovmf is for the SNP path. libclang-dev/clang: bindgen from nvat.h.
# libtss2-dev: tss-esapi-sys. iasl (acpica-tools, DSDT) and clang shape
# measured bytes, which is why the set is snapshot-pinned at all.
#
# Retries are budgeted by time, not count: a flapping mirror fails a
# transaction in seconds (index fetches 5xx, nothing to install) or after
# minutes (one deb 5xx at the end), and three tries of the former are
# over before it recovers. HOST_DEPS_BUDGET seconds, default 25 minutes,
# sits under the calling step's 30 minute bound.
set -euo pipefail
budget=${HOST_DEPS_BUDGET:-1500}
start=$(date +%s)
attempt=0
while :; do
  attempt=$((attempt + 1))
  if confidential-os-builder/bin/host-deps "$@" \
       systemd-container ovmf cpio acpica-tools \
       libclang-dev clang libtss2-dev; then
    exit 0
  fi
  elapsed=$(( $(date +%s) - start ))
  if [ "$elapsed" -ge "$budget" ]; then
    echo "host-deps attempt $attempt failed after ${elapsed}s; budget of ${budget}s spent" >&2
    exit 1
  fi
  echo "host-deps attempt $attempt failed after ${elapsed}s; retrying in 60s" >&2
  sleep 60
done
