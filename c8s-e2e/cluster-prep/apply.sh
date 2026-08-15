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

echo '== 1/7 node label (current metal main selects confidential.ai/sev-snp) =='
kubectl label node sev-snp-gh-runner confidential.ai/sev-snp=true --overwrite

echo '== 2/7 rke2 rootdisk import (CDI, ~2GiB — first run takes minutes) =='
kubectl apply -f rke2-rootdisk-dv.yaml
kubectl -n confai-images wait dv/rke2-rootdisk-79d45313276e --for=condition=Ready --timeout=20m

echo '== 3/7 stage /var/lib/igvm/rke2.igvm + capture golden measurement =='
kubectl -n confai-images delete job igvm-stage-rke2-79d45313276e --ignore-not-found
kubectl apply -f igvm-stage-job.yaml
kubectl -n confai-images wait job/igvm-stage-rke2-79d45313276e --for=condition=complete --timeout=20m
LOGS=$(kubectl -n confai-images logs job/igvm-stage-rke2-79d45313276e)
echo "$LOGS" | tail -5

echo '== 4/7 publish rke2-image-refs ConfigMap (incl. golden smp4 launch digest) =='
# manifest.json carries per-variant measurements; pull the smp=4 variant's
# snp_launch_digest (nested under measurement.*) — find the smp==4 object,
# then regex its whole subtree for the sha384.
GOLDEN=$(echo "$LOGS" | python3 -c '
import json, re, sys
raw = sys.stdin.read()
start, end = raw.find("{"), raw.rfind("}")
def smp4_objects(o):
    if isinstance(o, dict):
        if str(o.get("smp")) == "4" or o.get("cores") == 4:
            yield o
        for v in o.values(): yield from smp4_objects(v)
    elif isinstance(o, list):
        for v in o: yield from smp4_objects(v)
cands = []
if start >= 0 and end > start:
    try:
        for obj in smp4_objects(json.loads(raw[start:end+1])):
            blob = json.dumps(obj)
            m = re.search(r"\"[a-z_]*launch_digest\"\s*:\s*\"([0-9a-fA-F]{96})\"", blob)
            cands += [m.group(1).lower()] if m else re.findall(r"[0-9a-f]{96}", blob.lower())
    except Exception: pass
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

echo '== 5/7 base-image-refs ConfigMap (base-cpu; playbook publishes this on next provision) =='
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

echo '== 6/7 tdx-rke2-image-refs ConfigMap (TDX lane; pinned image + its measurement tuple) =='
# mrtd/rtmr1/rtmr2 are the confos build manifest for this exact image, not values
# read back from a running guest: get-kubeconfig --image-manifest pins on them.
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: tdx-rke2-image-refs
  namespace: confai-images
data:
  image: "ghcr.io/confidential-dot-ai/c8s-base@sha256:20582959f163acd7b3c0927c3ce2c395da162bb5993890d4f387b46147f4258a"
  rootPvc: "c8s-root-20582959f163"
  cdiTag: "rke2-cdi-64b6d7a"
  c8sRef: "64b6d7a"
  mrtd: "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1"
  rtmr1: "0e65a54c565bdd5045886a4665419eed653bfd0c694ed6590f1b518d512d00b42795838b90f8426804640e327a6c7866"
  rtmr2: "29dba45b23f3773bed4ea6420ec444063c4651c42a37649eb54085b3de99d20a35b557b5b882c0efc894e9213595b311"
EOF

echo '== 7/7 RBAC (adds configmaps read) + egress (adds in-CVM :6443) =='
kubectl apply -f ../../baremetal/kubevirt-rbac.yaml
kubectl apply -f ../../baremetal/runner-egress.cnp.yaml

echo 'done — lane prerequisites in place:'
kubectl -n confai-images get dv,cm
kubectl get node sev-snp-gh-runner -o jsonpath='{.metadata.labels.confidential\.ai/sev-snp}{"\n"}'
