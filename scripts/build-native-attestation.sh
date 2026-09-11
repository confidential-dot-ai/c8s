#!/usr/bin/env bash
# Build c8s's attestation-api from an attestation-rs checkout using native TEEs.
# Usage: build-native-attestation.sh /path/to/attestation-rs [cargo build flags]
set -euo pipefail
attestation_checkout=${1:?usage: build-native-attestation.sh ATTESTATION_CHECKOUT [cargo build flags]}
shift
cd "$attestation_checkout"
# --no-default-features on attestation-api does not disable defaults on its
# attestation dependency. Narrow that dependency's defaults in the build
# checkout before Cargo resolves features. Fail if the upstream layout changes.
python3 - <<'PY'
from pathlib import Path
import re
import tomllib

manifest = Path('crates/attestation/Cargo.toml')
source = manifest.read_text()
features = tomllib.loads(source)['features']
assert 'snp' in features and 'tdx' in features, 'native attestation features missing'
updated, count = re.subn(r'(?m)^default\s*=\s*\[[^\]\n]*\]', 'default = ["snp", "tdx"]', source)
assert count == 1, 'expected one attestation default feature list'
manifest.write_text(updated)
PY
cargo build --release -p attestation-api --bin attestation-api "$@"
