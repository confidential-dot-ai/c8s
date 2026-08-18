#!/usr/bin/env bash
#
# Applies kata-guest-base/patches/*.patch, in order, to a kata source tree.
# build.sh calls this before osbuilder compiles kata-agent; the patch gate in
# .github/workflows/kata-patches.yml calls it against a pristine tarball so a
# rejected hunk fails a PR rather than the post-merge image build.
#
# Usage: apply-patches.sh <kata-src-dir> [extra patch args...]
#   e.g. apply-patches.sh /path/to/kata -F0 --dry-run

set -euo pipefail

KATA_SRC="${1:?usage: apply-patches.sh <kata-src-dir> [patch args...]}"
shift

PATCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../patches" && pwd)"

shopt -s nullglob
for p in "${PATCH_DIR}"/*.patch; do
    echo "Applying $(basename "${p}")"
    patch -p1 --forward --batch "$@" -d "${KATA_SRC}" <"${p}" || {
        echo "FATAL: patch $(basename "${p}") does not apply — re-base it against the pinned kata commit." >&2
        exit 1
    }
done
shopt -u nullglob
