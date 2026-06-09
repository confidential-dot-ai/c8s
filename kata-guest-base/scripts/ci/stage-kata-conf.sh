#!/usr/bin/env bash
# CI-only: stage kata's confidential rootfs image (the source of the CoCo
# guest-components — confidential-data-hub, attestation-agent, api-server-rest
# — that osbuilder bakes into the measured rootfs). kata-deploy provides this
# image at /opt/kata on a node; in CI we pull it from the kata-static release
# and extract just the one image we need.
#
# Inputs (env):
#   KATA_VERSION                kata-static release to download.
#   RUNNER_TEMP                 GitHub-runner-provided temp dir.
#   KATA_STATIC_SHA256          (optional) override the pinned sha256 of the
#                               kata-static-${KATA_VERSION}-amd64.tar.zst.
#   GITHUB_ENV                  GitHub-runner env file; we append
#                               KATA_CONFIDENTIAL_IMG=<path> for build.sh.
#
# On a cache hit (the image already lives under ${RUNNER_TEMP}/kata-conf/), the
# download is skipped entirely.

set -euo pipefail

: "${KATA_VERSION:?KATA_VERSION must be set}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"
: "${GITHUB_ENV:?GITHUB_ENV must be set}"

# Pinned sha256 of the kata-static tarball. The guest-components inside are
# baked into the dm-verity root and the SNP launch measurement, so an
# unverified download would undermine the measurement. Update alongside
# KATA_VERSION (compute via `sha256sum kata-static-<ver>-amd64.tar.zst`).
DEFAULT_KATA_STATIC_SHA256_3_30_0="e65aa5e5bd9f4d59bcd12a8c44a00966406e7329511dd3f756026b6eedc8ad26"
KATA_STATIC_SHA256="${KATA_STATIC_SHA256:-${DEFAULT_KATA_STATIC_SHA256_3_30_0}}"

dir="${RUNNER_TEMP}/kata-conf"
img="${dir}/kata-ubuntu-noble-confidential.image"

if [ ! -f "${img}" ]; then
    echo "cache miss — fetching kata-static-${KATA_VERSION}"
    mkdir -p "${dir}"
    tarball="${RUNNER_TEMP}/kata-static.tar.zst"
    curl -fsSL -o "${tarball}" \
        "https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/kata-static-${KATA_VERSION}-amd64.tar.zst"
    echo "${KATA_STATIC_SHA256}  ${tarball}" | sha256sum -c -

    tmp="$(mktemp -d)"
    # Extract as the runner user (no sudo): the image is a regular file, and
    # root-owned temp files would break both the cleanup below and the
    # actions/cache save, which reads the cached file as the runner.
    tar -I unzstd -xf "${tarball}" \
        -C "${tmp}" --wildcards --no-anchored 'kata-ubuntu-noble-confidential.image'
    found="$(find "${tmp}" -name kata-ubuntu-noble-confidential.image | head -1)"
    if [ -z "${found}" ]; then
        echo "::error::kata-ubuntu-noble-confidential.image not found in kata-static-${KATA_VERSION}"
        exit 1
    fi
    mv "${found}" "${img}"
    rm -rf "${tarball}" "${tmp}"
else
    echo "cache hit — reusing ${img}"
fi

echo "KATA_CONFIDENTIAL_IMG=${img}" >> "${GITHUB_ENV}"
echo "CoCo guest-components source: ${img}"
