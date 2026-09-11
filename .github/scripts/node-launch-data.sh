#!/usr/bin/env bash
# Generate one fresh leader keyset and signed launch.yaml for a hardware lane.
# Arguments: output-directory platform cluster-id measurement [rtmr1 rtmr2].
# Private key/tokens stay in mode-0600 files; only pubkey, launch.yaml and its
# signature are attached to opkeydata. The matching leader.json pins clients.
set -euo pipefail
umask 077
[[ $# == 4 || $# == 6 ]] || { echo "usage: $0 DIR tdx|snp CLUSTER MEASUREMENT [RTMR1 RTMR2]" >&2; exit 2; }
out=$1
c8s keys sign-launch --help >/dev/null
mkdir -m700 "$out"
openssl ecparam -name prime256v1 -genkey -noout -out "$out/operator.key"
openssl ec -in "$out/operator.key" -pubout -out "$out/pubkey" 2>/dev/null
python3 - "$@" <<'PYTHON'
import json
import pathlib
import re
import secrets
import sys

out, platform, cluster, digest, *rtmrs = sys.argv[1:]
def require(ok, message):
    if not ok:
        raise SystemExit(message)
require(platform in ("tdx", "snp"), "platform must be tdx or snp")
require(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", cluster), "invalid cluster ID")
require(len(rtmrs) == (2 if platform == "tdx" else 0), "TDX requires exactly RTMR1 and RTMR2")
require(all(re.fullmatch(r"[0-9a-f]{96}", d) for d in [digest, *rtmrs]), "invalid SHA-384 image pin")
out = pathlib.Path(out)
pub = (out / "pubkey").read_text()
server, agent = secrets.token_hex(32), secrets.token_hex(32)
require(server != agent, "independent token generation collided")
# Numeric YAML map keys are intentional: the strict launch parser decodes
# RTMR indices as integers, whereas JSON object keys would be strings.
lines = ["schemaVersion: c8s-launch/v1", "clusterID: " + json.dumps(cluster),
         "role: leader", "image:", "  platform: " + platform,
         "  measurement: " + json.dumps(digest)]
if rtmrs:
    lines += ["  rtmrs:", *[f"    {i}: {json.dumps(d)}" for i, d in enumerate(rtmrs, 1)]]
lines += ["node: " + json.dumps({"name": "c8s-node"}),
          "rke2: " + json.dumps({"serverToken": server, "agentToken": agent}),
          "leader: " + json.dumps({"operatorPublicKey": pub}),
          "followerOperatorPublicKeys: []", "tlsSAN: c8s.local"]
(out / "launch.yaml").write_text("\n".join(lines) + "\n")
entry = {"name": "leader", "operator_key": pub}
if platform == "tdx":
    entry.update(mrtd=digest, rtmr=[None, *rtmrs, None])
else:
    entry["measurement"] = digest
policy = {"schema_version": "1", "tee": "tdx" if platform == "tdx" else "sev-snp", "measurements": [entry]}
(out / "leader.json").write_text(json.dumps(policy) + "\n")
PYTHON
c8s keys sign-launch --key "$out/operator.key" "$out/launch.yaml" >/dev/null
