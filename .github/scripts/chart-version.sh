#!/usr/bin/env bash
# Derive the Helm chart version published by .github/workflows/chart.yml and
# write it to GITHUB_OUTPUT as `version`.
#
#   - tag push (refs/tags/vX) -> the release version (X), the official artifact
#   - anything else           -> <Chart.yaml version>-g<short-sha> (a dev build)
#
# Inputs (env):
#   GITHUB_REF      the triggering ref.
#   CHART_DIR       chart directory containing Chart.yaml.
#   GITHUB_OUTPUT   step output file.

set -euo pipefail

: "${CHART_DIR:?CHART_DIR must be set}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"

if [[ "$GITHUB_REF" == refs/tags/v* ]]; then
  v="${GITHUB_REF#refs/tags/v}"
else
  base=$(grep -E '^version:' "$CHART_DIR/Chart.yaml" | awk '{print $2}' | tr -d '"')
  # Prefix the sha with "g" (git-describe convention) so the SemVer pre-release
  # segment is never a pure-numeric identifier, which forbids leading zeros: an
  # all-digit sha like 0091982 would make helm reject "0.1.0-0091982" with
  # "Version segment starts with 0".
  v="${base}-g$(git rev-parse --short HEAD)"
fi
echo "version=$v" >> "$GITHUB_OUTPUT"
