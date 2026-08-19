#!/usr/bin/env bash
# CI-only: compute the GHCR image ref + tag list for the kata-guest-base oras
# push in .github/workflows/kata-guest-base.yml. Writes `image`, `tags`,
# `debug_tags` (comma-joined), and the optional `release_tag` to GITHUB_OUTPUT.
# `debug_tags` is every mutable/commit tag
# with a `-debug` suffix — the debug-policy variant (build.sh Step 5/5,
# output-debug/) publishes under it in lockstep with the locked image, so
# `kata.guestImage.debug=true` (`c8s install --cvm-mode=pod --debug`) can derive the
# debug ref from any locked tag.
#
# Always publish the commit-scoped short-SHA tag. Then add the
# human-friendly pointer scoped to the ref class:
#   - main                  -> main
#   - any other ref         -> branch-<sanitized ref name>
#
# RELEASE_TAG is kept separate. The workflow promotes the four completed guest
# manifests only after it verifies that an existing stable alias has the same
# digest, so a retry or manual rebuild cannot silently overwrite a release.
#
# :main matches every other c8s artifact (docker.yml: cds, operator,
# ratls-mesh, …) and cmd/c8s/install.go's fallbackImageTag, so the chart's
# kata.guestImage.tag default resolves here.
#
# A side branch NEVER gets main/vX — nothing a human could mistake for a
# released, production image. The branch- prefix plus ref sanitization (any char
# outside [A-Za-z0-9_.-] -> '-') keeps it an obvious dev artifact and a valid OCI
# tag. The sanitized ref is truncated so the longest derived
# `branch-<ref>-nvidia-debug` tag stays within OCI's 128-character limit.
#
# Inputs (env):
#   HEAD_BRANCH     source branch of the triggering Docker event: "main" for a
#                   main push, or the selected ref for a manual run;
#                   github.ref_name on workflow_dispatch.
#   HEAD_SHA        commit Docker succeeded on (workflow_run head_sha), or
#                   github.sha on workflow_dispatch.
#   RELEASE_TAG     optional stable tag created by the successful parent Docker
#                   run for HEAD_SHA. It is emitted only on the main path.
#   REGISTRY        container registry host (ghcr.io).
#   GITHUB_OUTPUT   step output file.

set -euo pipefail

: "${HEAD_BRANCH:?HEAD_BRANCH must be set}"
: "${HEAD_SHA:?HEAD_SHA must be set}"
: "${REGISTRY:?REGISTRY must be set}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"

if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid full commit SHA: $HEAD_SHA" >&2
  exit 1
fi

RELEASE_TAG="${RELEASE_TAG:-}"
if [ -n "$RELEASE_TAG" ] && \
   [[ ! "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$ ]]; then
  echo "invalid stable release tag: $RELEASE_TAG" >&2
  exit 1
fi

SHORT_SHA="${HEAD_SHA::7}"
IMAGE="${REGISTRY}/confidential-dot-ai/kata-guest-base"

tags=("${SHORT_SHA}")
if [[ "${HEAD_BRANCH}" == "main" ]]; then
  tags+=("main")
else
  RELEASE_TAG=""
  SAFE_BRANCH="$(printf '%s' "${HEAD_BRANCH}" | tr -c 'A-Za-z0-9_.-' '-')"
  SAFE_BRANCH="${SAFE_BRANCH:0:108}"
  tags+=("branch-${SAFE_BRANCH}")
fi

joined=$(IFS=,; echo "${tags[*]}")
debug_joined=$(IFS=,; echo "${tags[*]/%/-debug}")
{
  echo "image=${IMAGE}"
  echo "tags=${joined}"
  echo "debug_tags=${debug_joined}"
  echo "release_tag=${RELEASE_TAG}"
} >> "$GITHUB_OUTPUT"
