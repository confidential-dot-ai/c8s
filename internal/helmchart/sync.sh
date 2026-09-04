#!/usr/bin/env bash
# Materializes the shared library chart, CRDs, and scripts into each shape
# chart so the in-repo chart dirs are directly usable (helm template, helm
# lint, go test). `c8s install` does the same at extract time (embed.go); the
# vendored copies are gitignored. Run after editing lib/, crds/, or scripts/.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)

# Concurrent go test runs call this from TestMain; serialize the rm/cp cycle.
exec 9>"$here/.sync.lock"
flock 9

for shape in pod node-cloud node-metal node-image; do
  rm -rf "$here/$shape/charts" "$here/$shape/crds" "$here/$shape/files"
  mkdir -p "$here/$shape/charts" "$here/$shape/crds" "$here/$shape/files/scripts"
  cp -r "$here/lib" "$here/$shape/charts/c8s-lib"
  cp "$here/crds/"*.yaml "$here/$shape/crds/"
  scripts=$(grep -E "^$shape:" "$here/scripts/MANIFEST" | cut -d: -f2-)
  for s in $scripts; do cp "$here/scripts/$s" "$here/$shape/files/scripts/"; done
done
