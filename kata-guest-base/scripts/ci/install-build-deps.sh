#!/usr/bin/env bash
# CI-only: install the host tools build.sh needs to run kata's osbuilder and bake
# the pause bundle. osbuilder's image-builder runs on the host (loop-device
# partitioning fails inside a container), so it needs umoci, skopeo, the
# verity/image tools, and zstd (to unpack kata-static). docker, sudo, jq, yq, gh,
# rsync and systemctl ship by default on GitHub-hosted ubuntu; on the self-hosted
# `the-machine` runner they must be preprovisioned.
#
# Invoked from .github/workflows/kata-guest-base.yml. No inputs.

set -euo pipefail

# umoci isn't in apt; install the static release binary, pinned by version AND
# sha256. umoci runs under sudo to unpack the pause bundle that lands in the
# dm-verity guest root, so a swapped binary would sit in the measured TCB —
# verify the checksum before chmod, same treatment as the sha256-pinned
# kata-static tarball in stage-kata-conf.sh. Hash is the linux/amd64 release
# asset for UMOCI_VERSION; update both together.
UMOCI_VERSION="v0.6.0"
UMOCI_SHA256="b51c267ec394499e42c6fde47f240b7b7dba57ea49df0b5acd304378b82a3b71"

sudo apt-get update
sudo apt-get install -y skopeo erofs-utils cryptsetup-bin parted gdisk e2fsprogs qemu-utils zstd

sudo curl -fsSL -o /usr/local/bin/umoci \
  "https://github.com/opencontainers/umoci/releases/download/${UMOCI_VERSION}/umoci.linux.amd64"
echo "${UMOCI_SHA256}  /usr/local/bin/umoci" | sha256sum -c -
sudo chmod +x /usr/local/bin/umoci
