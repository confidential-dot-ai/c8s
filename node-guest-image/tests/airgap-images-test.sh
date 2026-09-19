#!/usr/bin/env bash
# Real ORAS + OCI fixture: verify complete index preservation, imported names,
# deterministic archives and rejection of unpinned/empty image lists offline.
set -euo pipefail
TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for tool in oras jq python3 tar; do command -v "$tool" >/dev/null; done
REAL_ORAS=$(command -v oras)
export REAL_ORAS
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
OCI_SOURCE="$work/source"
export OCI_SOURCE
mkdir -p "$work/bin" "$OCI_SOURCE/blobs/sha256"
python3 - "$OCI_SOURCE" > "$work/images.txt" <<'PYFIXTURE'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
def blob(value, media_type):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(data).hexdigest()
    (root / "blobs/sha256" / digest).write_bytes(data)
    return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(data)}
children = []
for architecture in ("amd64", "arm64"):
    config = blob({"architecture": architecture, "os": "linux", "config": {},
                   "rootfs": {"type": "layers", "diff_ids": []}},
                  "application/vnd.oci.image.config.v1+json")
    manifest = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                     "config": config, "layers": []}, "application/vnd.oci.image.manifest.v1+json")
    manifest["platform"] = {"architecture": architecture, "os": "linux"}
    children.append(manifest)
index = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
              "manifests": children}, "application/vnd.oci.image.index.v1+json")
index["annotations"] = {"org.opencontainers.image.ref.name": "fixture"}
(root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
(root / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [index]}))
print("registry.example.com/core@" + index["digest"])
PYFIXTURE
# Replace only the registry transport. The production archiver and actual
# ORAS copying/digest verification run unchanged against a local OCI layout.
cat > "$work/bin/oras" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 4 && $1 == cp && $2 == --to-oci-layout ]]
exec "$REAL_ORAS" cp --from-oci-layout --to-oci-layout "$OCI_SOURCE@${3##*@}" "$4"
SHIM
chmod +x "$work/bin/oras"
export PATH="$work/bin:$PATH"
script="$TESTS_DIR/../c8s/airgap-images.sh"
bash "$script" "$work/images.txt" "$work/cache" "$work/first"
bash "$script" "$work/images.txt" "$work/cache" "$work/second"
cmp "$work/first/c8s-0.tar" "$work/second/c8s-0.tar"
python3 - "$work/first/c8s-0.tar" "$work/images.txt" <<'PYCHECK'
import hashlib, json, pathlib, sys, tarfile
ref = pathlib.Path(sys.argv[2]).read_text().strip()
with tarfile.open(sys.argv[1]) as archive:
    index = json.load(archive.extractfile("index.json"))
    assert len(index["manifests"]) == 1
    descriptor = index["manifests"][0]
    assert descriptor["digest"] == ref.split("@")[1]
    assert descriptor["annotations"]["io.containerd.image.name"] == ref
    for item in archive:
        assert item.uid == item.gid == item.mtime == 0
        if item.isfile() and item.name.startswith("blobs/sha256/"):
            assert hashlib.sha256(archive.extractfile(item).read()).hexdigest() == item.name.split("/")[-1]
    source_index = json.load(archive.extractfile("blobs/sha256/" + descriptor["digest"].split(":")[1]))
    assert {item["platform"]["architecture"] for item in source_index["manifests"]} == {"amd64", "arm64"}
PYCHECK
printf '%s\n' registry.example.com/core:latest > "$work/invalid.txt"
if bash "$script" "$work/invalid.txt" "$work/cache" "$work/invalid"; then
    echo "accepted an unpinned image" >&2; exit 1
fi
: > "$work/empty.txt"
if bash "$script" "$work/empty.txt" "$work/cache" "$work/empty"; then
    echo "accepted an empty core image set" >&2; exit 1
fi
echo "airgap images preserve measured pins and reproducible complete OCI content"
