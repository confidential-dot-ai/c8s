#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# c8s-on-Azure-TDX e2e driver — runs IN-GUEST on an ephemeral DC4es_v6
# ConfidentialVM (RKE2), delivered + launched by azure-tdx-e2e.yml via
# `az vm run-command`. There is no AKS and the rke2 apiserver is NOT exposed, so
# every kubectl/c8s/crane call runs here on the node rather than from the CI
# runner. The workflow polls /tmp/azure-tdx-e2e.log for the @@markers@@ this
# emits and gates on @@E2E_PASS@@ / @@E2E_FAIL@@ — the same marker-polling
# contract the metal serial-console lane (cvm-e2e.yml) uses, over run-command
# instead of a console.
#
# Proven on hardware 2026-07-22 (manual trial): the install path
# `c8s install --single-node --cvm-mode aks --hardware-platform tdx` brings the
# node up self-attesting az-tdx over the vTPM (CDS serves /ca over az-tdx
# RA-TLS). This driver automates that plus the consumption + negative
# enforcement proofs.
#
# Arg: $1 = c8s git ref to test (default main).
set -uo pipefail
exec > /tmp/azure-tdx-e2e.log 2>&1
set -x

C8S_REF="${1:-main}"
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod
# RKE2, not k3s: c8s auto-detects distro=rke2 from the kubelet's +rke2 suffix,
# so every rke2-ism (containerd socket, CoreDNS service name, config dir) is
# native — no -f override. k3s looks like rke2 for the containerd socket but
# NOT for CoreDNS (tls-lb's nginx resolves rke2-coredns-*, absent on k3s →
# crashloop) — the reason this lane runs on rke2 like the metal lane does.
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
export PATH="$PATH:/usr/local/go/bin:/root/go/bin:/var/lib/rancher/rke2/bin:/usr/local/bin"

fail() { echo "@@E2E_FAIL $*@@"; kubectl -n c8s-system get pods -o wide 2>/dev/null; exit 0; }
mark() { echo "@@$*@@"; }

# ── toolchain (fresh CVM: no make; nohup strips HOME/GOPATH — both learned in
#    the trial) ────────────────────────────────────────────────────────────────
mark STAGE_TOOLCHAIN
GOVER="$(curl -fsSL https://go.dev/VERSION?m=text 2>/dev/null | head -1 | sed 's/^go//')"
[ -n "$GOVER" ] || GOVER=1.26.3
curl -fsSL "https://go.dev/dl/go${GOVER}.linux-amd64.tar.gz" | tar -C /usr/local -xz || fail "go download"
curl -fsSL https://get.helm.sh/helm-v3.16.2-linux-amd64.tar.gz | tar -xz -C /tmp && install /tmp/linux-amd64/helm /usr/local/bin/helm || fail "helm"
curl -fsSL https://github.com/google/go-containerregistry/releases/download/v0.20.2/go-containerregistry_Linux_x86_64.tar.gz | tar -xz -C /usr/local/bin crane || fail "crane"
mark TOOLCHAIN_OK

# ── build c8s at the ref under test (go install, not make — bare CVM) ─────────
mark STAGE_BUILD
rm -rf /root/c8s
git clone https://github.com/confidential-dot-ai/c8s.git /root/c8s || fail "clone"
git -C /root/c8s checkout "$C8S_REF" || fail "checkout $C8S_REF (bad ref? — refusing to silently test main)"
echo "@@REF_SHA $(git -C /root/c8s rev-parse HEAD)@@"
( cd /root/c8s && go install ./cmd/c8s ) || fail "c8s build"
command -v c8s >/dev/null || fail "c8s not on PATH after build"
mark BUILD_OK

# ── install: the az-tdx vTPM path. No -f override — c8s auto-detects the rke2
#    distro from the kubelet version and wires the containerd socket, config
#    dir and CoreDNS naming natively (the metal lane installs the same way). ────
mark STAGE_INSTALL
openssl ecparam -name prime256v1 -genkey -noout -out /root/operator.key
openssl ec -in /root/operator.key -pubout -out /root/operator.pub
FLAGS="--single-node --cvm-mode aks --hardware-platform tdx --operator-keys /root/operator.pub"
# helm --wait's baked 5-min ceiling loses to a 4-vCPU single node bringing up
# six components; install is idempotent, so two attempts then an explicit gate.
c8s install $FLAGS \
  || { mark INSTALL_RETRY; c8s install $FLAGS; } \
  || mark INSTALL_WAIT_TIMEOUT
mark INSTALL_APPLIED

# ── converge: all six components Ready (real count, never zero-pod false-pass).
#    WIDE budget (~17min): the nri-image-policy install restarts rke2-server to
#    reload containerd with the NRI drop-in, which briefly bounces the apiserver
#    and pods mid-install — kubectl calls transiently fail (swallowed by
#    2>/dev/null; the loop retries) and the cluster re-converges. ────────────────
mark STAGE_CONVERGE
for i in $(seq 1 50); do
  TOTAL=$(kubectl -n c8s-system get pods --no-headers 2>/dev/null | wc -l)
  READY=$(kubectl -n c8s-system get pods --no-headers 2>/dev/null | awk '{split($2,a,"/"); if (a[1]==a[2] && $3=="Running") r++} END {print r+0}')
  echo "@@CONVERGE $i ready=${READY:-0}/${TOTAL:-0}@@"
  [ "${TOTAL:-0}" -ge 6 ] && [ "${READY:-0}" = "${TOTAL:-0}" ] && { mark ALL_READY; break; }
  sleep 20
done
kubectl -n c8s-system get pods -o wide
NOTREADY=$(kubectl -n c8s-system get pods --no-headers 2>/dev/null | awk '{split($2,a,"/"); if (a[1]!=a[2] || $3!="Running") n++} END {print n+0}')
TOTAL=$(kubectl -n c8s-system get pods --no-headers 2>/dev/null | wc -l)
[ "${TOTAL:-0}" -ge 6 ] || fail "only ${TOTAL:-0} components (want >=6)"
[ "${NOTREADY:-1}" = "0" ] || fail "${NOTREADY} components not Ready"
mark COMPONENTS_READY

# ── the proof: CDS serves its CA over an az-tdx RA-TLS cert ───────────────────
mark STAGE_CDS_ATTEST
PLAT=$(kubectl -n c8s-system get deploy c8s-cds -o jsonpath='{.spec.template.spec.containers[0].args}' 2>/dev/null | grep -o 'ratls-platform=[a-z-]*')
echo "@@CDS_RATLS $PLAT@@"
echo "$PLAT" | grep -q 'ratls-platform=tdx' || fail "cds not on tdx ratls ($PLAT)"
# /ca 200 => CDS issued its RA-TLS serving cert, which required a valid az-tdx quote
kubectl -n c8s-system port-forward svc/c8s-cds 8443:8443 >/dev/null 2>&1 & PF=$!; sleep 4
CA_CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 https://127.0.0.1:8443/ca 2>/dev/null)
kill $PF 2>/dev/null || true
echo "@@CDS_CA_HTTP $CA_CODE@@"
[ "$CA_CODE" = "200" ] || fail "cds /ca returned $CA_CODE (az-tdx RA-TLS cert not served)"
mark CDS_ATTESTS_TDX

# ── vTPM attestation probe (the Azure-unique evidence path; platform=az-tdx) ──
mark STAGE_ATTEST_PROBE
kubectl -n c8s-system port-forward svc/c8s-attestation-api 8400:8400 >/dev/null 2>&1 & PF=$!; sleep 4
NONCE=$(head -c 32 /dev/urandom | base64 -w0)
# platform:auto matches every in-repo caller (getkubeconfig, attestclient,
# handoff_bootstrap); an omitted platform is an untested request shape.
HTTP=$(curl -s -m 30 -o /tmp/att.json -w '%{http_code}' -H 'content-type: application/json' -d "{\"platform\":\"auto\",\"report_data\":\"$NONCE\"}" http://127.0.0.1:8400/attest 2>/dev/null)
kill $PF 2>/dev/null || true
PLATFORM=$(python3 -c 'import json;print(json.load(open("/tmp/att.json")).get("platform",""))' 2>/dev/null)
echo "@@ATTEST /attest=$HTTP platform=$PLATFORM@@"
[ "$HTTP" = "200" ] || fail "/attest returned $HTTP"
echo "$PLATFORM" | grep -qiE 'az.?tdx|tdx' || fail "attest platform=$PLATFORM (want az-tdx)"
mark ATTEST_PROBE_OK

# ── consumption proof: allowlist the injected image set, workload goes Ready ──
mark STAGE_CONSUMPTION
kubectl apply -f /root/c8s/samples/nginx-confidential-pod.yaml || fail "sample apply"
sleep 15
IMGS=$(kubectl -n default get pods -l app=demo-nginx -o jsonpath='{range .items[0].spec.initContainers[*]}{.image}{"\n"}{end}{range .items[0].spec.containers[*]}{.image}{"\n"}{end}' 2>/dev/null | sort -u | grep -v '^$')
echo "injected image set:"; echo "$IMGS"
# allowlist writes go to CDS over its RA-TLS endpoint with the operator key;
# --attestation-api-url is NOT a flag on `allowlist add` (only on `c8s cds`) —
# passing it makes cobra reject the command. Don't mask the exit either: a
# failed add here otherwise surfaces 300s later as an opaque workload timeout.
kubectl -n c8s-system port-forward svc/c8s-cds 8443:8443 >/dev/null 2>&1 & PF1=$!
sleep 4
AL="--url https://127.0.0.1:8443 --operator-key /root/operator.key"
ADDED=0
while IFS= read -r img; do
  [ -n "$img" ] || continue
  for d in "$(crane digest "$img" 2>/dev/null)" "$(crane digest --platform linux/amd64 "$img" 2>/dev/null)"; do
    [ -n "$d" ] || continue
    if c8s allowlist add "$d" "$img" $AL; then ADDED=$((ADDED+1)); else echo "@@ALLOWLIST_ADD_FAIL $img $d@@"; fi
  done
done <<< "$IMGS"
kill $PF1 2>/dev/null || true
[ "$ADDED" -gt 0 ] || fail "no allowlist entries added (operator key / CDS write path)"
kubectl -n default wait --for=condition=Available deploy/demo-nginx --timeout=300s || fail "workload never Available"
kubectl -n default get pods -l app=demo-nginx -o jsonpath='{.items[0].spec.initContainers[*].name}' | grep -q 'c8s-cert' || fail "cert init not injected"
mark CONSUMPTION_OK

# ── NEGATIVE: a non-allowlisted image must not reach Ready (NRI fail-closed) ──
mark STAGE_NEGATIVE
kubectl run denied --image=busybox:1.36 --labels=app=denied \
  --annotations=confidential.ai/cw=denied-test --command -- sleep 300 2>/dev/null || true
sleep 45
PHASE=$(kubectl get pod denied -o jsonpath='{.status.phase}' 2>/dev/null)
READY=$(kubectl get pod denied -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)
echo "@@NEGATIVE phase=${PHASE:-none} ready=${READY:-none}@@"
if [ "$PHASE" = "Running" ] && [ "$READY" = "true" ]; then fail "non-allowlisted image RAN — enforcement inactive"; fi
mark NEGATIVE_OK

mark E2E_PASS
