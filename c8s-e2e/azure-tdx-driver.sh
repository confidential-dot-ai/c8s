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
# All SIX c8s components are required, nri-image-policy included. It was
# best-effort until 2026-07-23 on the theory that its NRI plugin could not
# register on a vanilla get.rke2.io node, a "substrate gap" the metal lane was
# said to sidestep via its rke2-node image. That theory was wrong twice over:
# `base-images` bakes no NRI configuration at all, and the metal lane pins
# `c8s_ref: 70aea72` (2026-07-15), which predates the nri v0.12.1 bump. The real
# cause was a stale plugin IMAGE. c8s#103 fixed a RemoveContainer signature that
# left the stub rejecting its own event mask; c8s#115 fixed the paths-filter
# glob that had aliased `:main` onto a two-month-old digest, so #103's fix never
# shipped. `:main` was rebuilt from b828a9b at 2026-07-23T02:29:20Z, half an
# hour AFTER the last run of this lane. No run here has ever exercised a
# correct plugin binary. Hence @@IMG_PROV@@ below: never trust an NRI result
# without knowing which binary produced it.
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

fail() {
  echo "@@E2E_FAIL $*@@"
  # emit the not-ready pods AS markers so they survive the poll's tail window
  # (the plain `get pods` dump below scrolls off before the job reads it).
  kubectl -n c8s-system get pods --no-headers 2>/dev/null | awk '{split($2,a,"/"); if (a[1]!=a[2] || $3!="Running") print "@@NOTREADY "$1" "$2" "$3"@@"}'
  diag_pods
  kubectl -n c8s-system get pods -o wide 2>/dev/null
  exit 0
}
mark() { echo "@@$*@@"; }

# ── NRI diagnostics ──────────────────────────────────────────────────────────
# The poller only ever sees @@markers@@ and the last 40 lines of an xtrace-heavy
# log, so EVERY diagnostic has to be a marker or it is lost. The harvest regex
# is `@@[A-Z][^@]*@@`: markers start uppercase and carry no `@`, hence the strip
# in m180. xtrace is off inside so the tail window holds signal, not trace.
#
# This block exists because the previous four runs threw away every piece of
# evidence: the NRI runtime wires a launched plugin's stdout and stderr to
# /dev/null, the DaemonSet's only long-running container is `sleep infinity`, so
# nothing is kubelet-captured, and the driver never dumped a log. The one
# surviving record is containerd's own, which on rke2 goes to a FILE, not
# journald: rke2 runs containerd as a child and redirects it to
# /var/lib/rancher/rke2/agent/containerd/containerd.log.
NRI_DS=c8s-nri-image-policy-worker
CTRD_DIR=/var/lib/rancher/rke2/agent/etc/containerd
CTRD_LOG=/var/lib/rancher/rke2/agent/containerd/containerd.log
HEALTH_SOCK=/var/run/nri-image-policy/health.sock
PLUGIN_BIN=/opt/nri/plugins/10-nri-image-policy
NRI_REV=""; NRI_BEHIND=""     # set by the provenance block; referenced under set -u

m180() { mark "$1 $(printf '%.180s' "${2//@/}")"; }

# pf_start <local-port> <port-forward args...>: start a forward and wait for it
# to actually accept. A fixed sleep loses this race on a loaded single node, and
# curl's 000 then reads as an attestation failure rather than a missing tunnel.
pf_start() {
  local port=$1 i; shift
  kubectl -n c8s-system port-forward "$@" >"/tmp/pf-$port.log" 2>&1 &
  PF=$!
  for i in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3<&- 3>&-; return 0; fi
    kill -0 "$PF" 2>/dev/null || break
    sleep 1
  done
  m180 D_PF "port $port never accepted: $(tail -2 "/tmp/pf-$port.log" 2>/dev/null | tr '\n' ' ')"
  return 1
}

# ── generic pod diagnostics ──────────────────────────────────────────────────
# diag_nri only covers NRI, so a tls-lb failure left us with a pod name and a
# 1/4. Markers are the only thing that survives the poller's window.
diag_pods() {
  set +x
  local P C l
  for P in $(kubectl -n c8s-system get pods --no-headers 2>/dev/null \
               | awk '{split($2,a,"/"); if (a[1]!=a[2] || $3!="Running") print $1}' | head -3); do
    m180 D_PS "$P $(kubectl -n c8s-system get pod "$P" -o jsonpath='{range .status.initContainerStatuses[*]}i/{.name}={.state.waiting.reason}{.state.terminated.reason}:rc={.state.terminated.exitCode} {end}{range .status.containerStatuses[*]}c/{.name}={.state.waiting.reason}{.state.terminated.reason} {end}' 2>/dev/null)"
    for C in $(kubectl -n c8s-system get pod "$P" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null); do
      while IFS= read -r l; do m180 "D_LOG_$C" "$l"; done \
        < <(kubectl -n c8s-system logs "$P" -c "$C" --tail=8 2>&1 | tail -8)
      while IFS= read -r l; do m180 "D_PRV_$C" "$l"; done \
        < <(kubectl -n c8s-system logs "$P" -c "$C" --previous --tail=6 2>/dev/null | tail -6)
    done
    while IFS= read -r l; do m180 D_EV "$l"; done \
      < <(kubectl -n c8s-system describe pod "$P" 2>/dev/null | sed -n '/^Events:/,$p' | tail -8)
  done
  set -x
}
diag_nri() {
  set +x
  PLINE=$(kubectl -n c8s-system get pods --no-headers 2>/dev/null | grep '^c8s-nri-image-policy' | head -1)
  PNAME=$(awk '{print $1}' <<<"$PLINE")
  mark "D_POD ${PLINE:-none}"

  # (a) is the plugin process alive, and does its health socket answer?
  #     curl_exit=7        -> socket absent/refused: never launched, or exited
  #     curl_exit=0 503    -> alive but not Ready: timing / CDS pull
  #     curl_exit=0 200    -> healthy
  HC=$(curl --unix-socket "$HEALTH_SOCK" -s -o /dev/null -w '%{http_code}' --max-time 3 http://localhost/healthz 2>/dev/null); CE=$?
  mark "D_HEALTH http=${HC:-none} curl_exit=$CE"
  PID=$(pgrep -f "$PLUGIN_BIN" 2>/dev/null | head -1)
  mark "D_HOST nrisock=$([ -S /var/run/nri/nri.sock ] && echo yes || echo NO) healthsock=$([ -S "$HEALTH_SOCK" ] && echo yes || echo NO) pid=${PID:-none} bin=$(stat -c '%s:%a' "$PLUGIN_BIN" 2>/dev/null || echo MISSING)"
  # a single stray file that does not match NN-name hard-aborts ALL discovery
  mark "D_PLUGDIR $(ls -1 /opt/nri/plugins 2>/dev/null | tr '\n' ',') cfg=$(ls -1 /etc/nri/conf.d 2>/dev/null | tr '\n' ',')"

  # (b) provenance of the binary that actually ran (see @@IMG_PROV@@)
  mark "D_IMG rev=${NRI_REV:0:12} behind=${NRI_BEHIND:-unknown}"

  # (c) containerd's side of the story, the only surviving record.
  J=$( { cat "$CTRD_LOG" 2>/dev/null; journalctl -u rke2-server --no-pager 2>/dev/null; } )
  mark "D_JCNT discovered=$(grep -ac 'discovered plugin' <<<"$J") start=$(grep -ac 'starting pre-installed NRI plugin' <<<"$J") failstart=$(grep -ac 'failed to start pre-installed NRI plugin' <<<"$J") failinit=$(grep -ac 'failed to initialize pre-installed NRI plugin' <<<"$J") valdisabled=$(grep -ac 'default validator is disabled' <<<"$J")"
  while IFS= read -r l; do m180 D_JERR "$l"; done \
    < <(grep -aE 'failed to (start|initialize) pre-installed NRI plugin|unhandled events' <<<"$J" | tail -3)

  # (d) the installer's own words, this attempt and the previous one. Identical
  #     text across both confirms the retry is a no-op (the restart is gated on
  #     containerd/binary/config having CHANGED, and after attempt 1 none have).
  if [ -n "$PNAME" ]; then
    while IFS= read -r l; do m180 D_INST "$l"; done < <(kubectl -n c8s-system logs "$PNAME" -c install --tail=5 2>/dev/null)
    while IFS= read -r l; do m180 D_INSTP "$l"; done < <(kubectl -n c8s-system logs "$PNAME" -c install --previous --tail=5 2>/dev/null)
  fi

  # (e) the EFFECTIVE merged containerd config, not the file on disk. Expect
  #     disable=false. imports=2 would mean duplicate root keys, which containerd
  #     refuses to start on, and this is a single-node control plane.
  mark "D_DROPIN $([ -f "$CTRD_DIR/config-v3.toml.d/nri-image-policy.toml" ] && echo present || echo MISSING) imports=$(grep -c '^[[:space:]]*imports[[:space:]]*=' "$CTRD_DIR/config.toml" 2>/dev/null) tmpl=$([ -f "$CTRD_DIR/config-v3.toml.tmpl" ] && echo present || echo absent)"
  m180 D_CFG "$(/var/lib/rancher/rke2/bin/containerd -c "$CTRD_DIR/config.toml" config dump 2>/dev/null | grep -aA10 'nri\.v1\.nri' | tr -d '\n"')"

  # (f) the last unobserved assumption. The plugin is a HOST process, so unlike
  #     the five components that converge it reaches CDS over a loopback
  #     NodePort. Any 3-digit code proves reachability; 000 is new information.
  mark "D_LOOPBACK cds=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1:30808/ca 2>/dev/null) att=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:30840/healthz 2>/dev/null) route_localnet=$(sysctl -n net.ipv4.conf.all.route_localnet 2>/dev/null)"
  set -x
}

# ── the substrate under test. Recorded, not pinned: a stale pin is precisely
#    how the metal lane hid this bug for a week. Pass rke2_version at dispatch
#    to freeze it when you need a reproducible comparison.
mark "SUBSTRATE rke2=$(rke2 --version 2>/dev/null | head -1 | awk '{print $3}') containerd=$(/var/lib/rancher/rke2/bin/containerd --version 2>/dev/null | awk '{print $3}')"

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

# ── provenance. The CLI is built from $C8S_REF, but every component IMAGE comes
#    from a registry tag: this build is unstamped, so version.Version is "dev"
#    and the install falls back to tag `:main`. That indirection is how a stale
#    plugin binary got tested four times without anyone noticing (c8s#115), so
#    assert what we are actually running before believing any NRI result.
#    A warning, not a fail: on a branch that touches plugin source the matching
#    image legitimately does not exist yet, and a reported run beats an aborted
#    one. Read this marker before trusting CONSUMPTION_OK / NEGATIVE_OK.
set +x
NRI_IMG=$(kubectl -n c8s-system get ds "$NRI_DS" \
  -o jsonpath='{.spec.template.spec.initContainers[?(@.name=="install")].image}' 2>/dev/null)
NRI_REV=$(crane config "$NRI_IMG" 2>/dev/null \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["config"]["Labels"].get("org.opencontainers.image.revision",""))' 2>/dev/null)
if [ -n "$NRI_REV" ]; then
  # commits on this ref that touch plugin source but are NOT in the image
  NRI_BEHIND=$(git -C /root/c8s log --oneline "$NRI_REV..HEAD" \
    -- internal/cmds/nri-image-policy cmd/nri-image-policy 2>/dev/null | wc -l | tr -d ' ')
else
  NRI_BEHIND=unknown   # never let an empty rev read as "behind=0"
fi
set -x
# --resolve-digests is on by default, so NRI_IMG is digest-pinned and carries a
# bare `@`. A marker containing one is invisible to the summary harvest regex
# (`@@[A-Z][^@]*@@` cannot cross it), which would silently drop the single most
# important assertion in this lane. Render the `@` as a field separator instead.
IMG_SHORT="${NRI_IMG##*/}"; IMG_SHORT="${IMG_SHORT//@/ digest=}"
mark "IMG_PROV img=${IMG_SHORT:-none} rev=${NRI_REV:0:12} plugin_commits_behind=${NRI_BEHIND:-unknown}"
[ "$NRI_BEHIND" = "0" ] \
  || mark "IMG_STALE_WARN plugin image is ${NRI_BEHIND} plugin-source commits behind this ref"

# ── converge. All SIX components are required. The 6th, nri-image-policy, IS
#    the image-admission enforcement plane. A lane that passes without it
#    proves nothing about enforcement, which is most of what this lane is for.
#    The two-tier loop is kept only so diagnostics fire after a bounded NRI
#    window instead of after all 50 iterations; the gate itself is hard. ───────
CORE='c8s-attestation-api c8s-cds c8s-operator c8s-ratls-mesh c8s-tls-lb'
core_ready() {
  for c in $CORE; do
    kubectl -n c8s-system get pods --no-headers 2>/dev/null \
      | awk -v p="$c" '$1 ~ "^"p {split($2,a,"/"); if (a[1]==a[2] && $3=="Running") ok=1} END {exit ok?0:1}' || return 1
  done
}
nri_ready() {
  kubectl -n c8s-system get pods --no-headers 2>/dev/null \
    | awk '$1 ~ /nri-image-policy/ {split($2,a,"/"); if (a[1]==a[2] && $3=="Running") ok=1} END {exit ok?0:1}'
}
mark STAGE_CONVERGE
NRI_UP=0
for i in $(seq 1 50); do
  READY=$(kubectl -n c8s-system get pods --no-headers 2>/dev/null | awk '{split($2,a,"/"); if (a[1]==a[2] && $3=="Running") r++} END {print r+0}')
  TOTAL=$(kubectl -n c8s-system get pods --no-headers 2>/dev/null | wc -l)
  echo "@@CONVERGE $i ready=${READY:-0}/${TOTAL:-0}@@"
  if core_ready; then
    nri_ready && { NRI_UP=1; mark ALL_READY; break; }
    [ "$i" -ge 25 ] && break   # core up, NRI over budget: stop and diagnose
  fi
  sleep 20
done
kubectl -n c8s-system get pods -o wide
core_ready || { diag_nri; fail "core control-plane not Ready (attestation-api/cds/operator/ratls-mesh/tls-lb)"; }
echo "@@CORE_READY nri_up=$NRI_UP@@"
# Always: on FAIL these markers ARE the answer, on PASS they are the healthy
# baseline the next regression gets compared against.
diag_nri
[ "$NRI_UP" = 1 ] || fail "nri-image-policy never became healthy (read the D_* markers)"
mark COMPONENTS_READY

# ── the proof: CDS serves its CA over an az-tdx RA-TLS cert ───────────────────
mark STAGE_CDS_ATTEST
PLAT=$(kubectl -n c8s-system get deploy c8s-cds -o jsonpath='{.spec.template.spec.containers[0].args}' 2>/dev/null | grep -o 'ratls-platform=[a-z-]*')
echo "@@CDS_RATLS $PLAT@@"
echo "$PLAT" | grep -q 'ratls-platform=tdx' || fail "cds not on tdx ratls ($PLAT)"
# /ca 200 => CDS issued its RA-TLS serving cert, which required a valid az-tdx quote
pf_start 8443 svc/c8s-cds 8443:8443 || fail "port-forward to cds never came up"
CA_CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 https://127.0.0.1:8443/ca 2>/dev/null)
kill $PF 2>/dev/null || true
echo "@@CDS_CA_HTTP $CA_CODE@@"
[ "$CA_CODE" = "200" ] || fail "cds /ca returned $CA_CODE (az-tdx RA-TLS cert not served)"
mark CDS_ATTESTS_TDX

# ── vTPM attestation probe (the Azure-unique evidence path; platform=az-tdx) ──
mark STAGE_ATTEST_PROBE
# c8s#304 removed the Service. The API binds loopback in the DaemonSet pod and a
# port-forward originates inside that netns, so it still reaches it.
AAPOD=$(kubectl -n c8s-system get pod -l app.kubernetes.io/component=attestation-api \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[ -n "$AAPOD" ] || fail "no attestation-api pod in c8s-system"
pf_start 8400 "pod/$AAPOD" 8400:8400 || fail "port-forward to attestation-api never came up"
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

# ── consumption + negative enforcement proofs. Unconditional: the converge gate
#    above already hard-failed if NRI is not healthy, so reaching here means
#    image admission is live and these two assertions are load-bearing. There is
#    deliberately no skip path: a soft gate plus a comment explaining it away
#    is exactly how this rotted for a week. If a green run is needed for an
#    unrelated reason, dispatch a known-good c8s_ref instead of reintroducing
#    the bypass. NOTE: enforcement here comes from the c8s plugin's own
#    fail-closed deny path (the chart default; this lane passes no -f), not from
#    containerd's default_validator, which the chart writes at the wrong TOML
#    nesting level and is therefore inert everywhere. Filed separately. ─────────

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
pf_start 8443 svc/c8s-cds 8443:8443 || fail "port-forward to cds never came up"
PF1=$PF
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
