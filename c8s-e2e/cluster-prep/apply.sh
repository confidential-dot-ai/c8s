#!/usr/bin/env bash
# One-shot prep of the runner cluster (github-runner-dev) for the c8s SNP e2e
# lane. Idempotent — re-run after an rke2 image digest bump (update the DV/Job
# manifests + rke2_cvm_image pin first). Everything here is exactly what
# confidential-metal's ansible would do with rke2_cvm_enabled=true, applied
# via kubectl because the host is SSH-unreachable from the laptop (Tailscale).
#
#   KUBECONFIG=~/dev/conf/github-runner.yaml ./apply.sh
set -euo pipefail
cd "$(dirname "$0")"

echo '== 1/6 node label (current metal main selects confidential.ai/sev-snp) =='
kubectl label node sev-snp-gh-runner confidential.ai/sev-snp=true --overwrite

echo '== 2/6 rke2 rootdisk import (CDI, ~2GiB — first run takes minutes) =='
kubectl apply -f rke2-rootdisk-dv.yaml
kubectl -n confai-images wait dv/rke2-rootdisk-79d45313276e --for=condition=Ready --timeout=20m

echo '== 3/6 stage /var/lib/igvm/rke2.igvm + capture golden measurement =='
kubectl -n confai-images delete job igvm-stage-rke2-79d45313276e --ignore-not-found
kubectl apply -f igvm-stage-job.yaml
kubectl -n confai-images wait job/igvm-stage-rke2-79d45313276e --for=condition=complete --timeout=20m
LOGS=$(kubectl -n confai-images logs job/igvm-stage-rke2-79d45313276e)
echo "$LOGS" | tail -5

echo '== 4/6 publish rke2-image-refs ConfigMap (incl. golden smp4 launch digest) =='
# manifest.json carries per-variant measurements; pull the smp=4 one out
# defensively (schema owned by steep — walk for an object with smp 4 + a
# 96-hex measurement, falling back to any 96-hex string on an smp4 line).
GOLDEN=$(echo "$LOGS" | python3 -c '
import json, re, sys
raw = sys.stdin.read()
start, end = raw.find("{"), raw.rfind("}")
def walk(o):
    if isinstance(o, dict):
        vals = {str(k).lower(): v for k, v in o.items()}
        if str(vals.get("smp")) == "4" or vals.get("cores") == 4:
            for v in o.values():
                if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{96}", v.lower()):
                    yield v.lower()
        for v in o.values(): yield from walk(v)
    elif isinstance(o, list):
        for v in o: yield from walk(v)
cands = []
if start >= 0 and end > start:
    try: cands = list(walk(json.loads(raw[start:end+1])))
    except Exception: pass
if not cands:  # fallback: 96-hex on a line mentioning smp4/smp-4/"smp": 4
    for line in raw.splitlines():
        if re.search(r"smp[-_\" :]*4", line, re.I):
            cands += [m.lower() for m in re.findall(r"[0-9a-fA-F]{96}", line)]
if not cands: sys.exit("no smp4 SHA-384 measurement found in manifest.json")
print(cands[0])
')
echo "golden smp4 launch digest: $GOLDEN"
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: rke2-image-refs
  namespace: confai-images
data:
  image: "ghcr.io/confidential-dot-ai/rke2@sha256:79d45313276e3251db30910aba47c85b9d37f5bc4b746ee0c2d78a032dc41486"
  rootPvc: "rke2-rootdisk-79d45313276e"
  igvmFile: "rke2.igvm"
  smp: "4"
  launchDigestSmp4: "$GOLDEN"
EOF

echo '== 5/6 base-image-refs ConfigMap (base-cpu; playbook publishes this on next provision) =='
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: base-image-refs
  namespace: confai-images
data:
  rootPvc: "cpu-image-rootdisk-0df2ca7d5549"
  sourceDigest: "0df2ca7d5549"
  baseCpuImage: "ghcr.io/confidential-dot-ai/base-cpu-image-cdi@sha256:0df2ca7d5549d0ccedb4373a0c02a742727f6639d7eaa6676fd4b64bebfabd27"
  sidecarImage: "ghcr.io/confidential-dot-ai/igvm-hook-sidecar@sha256:7450bb136bfc4d9434a7c1eb9e478ab3237e7d9acf5c211e7d080f2008b01ba0"
  igvmFilePattern: "guest-smp{cores}.igvm"
EOF

echo '== 6/6 RBAC (adds configmaps read) + egress (adds in-CVM :6443) =='
kubectl apply -f ../../baremetal/kubevirt-rbac.yaml
kubectl apply -f ../../baremetal/runner-egress.cnp.yaml

echo 'done — lane prerequisites in place:'
kubectl -n confai-images get dv,cm
kubectl get node sev-snp-gh-runner -o jsonpath='{.metadata.labels.confidential\.ai/sev-snp}{"\n"}'
