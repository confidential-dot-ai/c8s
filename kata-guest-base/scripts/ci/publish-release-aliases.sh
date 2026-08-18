#!/usr/bin/env bash
# Publish the four stable kata-guest-base aliases after verifying that every
# existing destination names the commit-scoped source digest. The complete
# preflight happens before the first write, so a conflict cannot leave a newly
# partial release.
#
# Inputs (env):
#   HEAD_SHA      full commit SHA whose Docker and Kata workflows succeeded.
#   IMAGE         kata-guest-base OCI repository.
#   RELEASE_TAG   stable vX.Y.Z release tag.
#   RUNNER_TEMP   GitHub-runner-provided temp directory.

set -euo pipefail

: "${HEAD_SHA:?HEAD_SHA must be set}"
: "${IMAGE:?IMAGE must be set}"
: "${RELEASE_TAG:?RELEASE_TAG must be set}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"

if [[ ! "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$ ]]; then
  echo "invalid stable release tag: $RELEASE_TAG" >&2
  exit 1
fi
if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid full commit SHA: $HEAD_SHA" >&2
  exit 1
fi

short="${HEAD_SHA:0:7}"
repo_tags="$(oras repo tags "$IMAGE")"
aliases="$RUNNER_TEMP/kata-release-aliases"
: > "$aliases"

for suffix in '' -debug -nvidia -nvidia-debug; do
  source_tag="$short$suffix"
  release_alias="$RELEASE_TAG$suffix"
  source_digest="$(oras resolve "$IMAGE:$source_tag")"
  [[ "$source_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
  exists=false
  if grep -Fxq -- "$release_alias" <<< "$repo_tags"; then
    exists=true
    destination_digest="$(oras resolve "$IMAGE:$release_alias")"
    if [ "$destination_digest" != "$source_digest" ]; then
      echo "::error::$IMAGE:$release_alias already names $destination_digest, expected $source_digest"
      exit 1
    fi
  fi
  printf '%s\t%s\t%s\n' "$release_alias" "$source_digest" "$exists" >> "$aliases"
done

while IFS=$'\t' read -r release_alias source_digest exists; do
  if [ "$exists" = false ]; then
    oras tag "$IMAGE@$source_digest" "$release_alias"
  fi
  test "$(oras resolve "$IMAGE:$release_alias")" = "$source_digest"
done < "$aliases"
