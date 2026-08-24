#!/usr/bin/env bash
# Live-cluster verification that attested mesh-CA handoff works end to end:
# an attested probe pod (the deployed cds image running `request-handoff`)
# pulls the CA over /handoff and proves the material is the live trust root
# served on /ca, and a second probe with a wrong --measurements pin proves a
# mismatched peer is refused. Proves on a real cluster what unit tests
# cannot: real TEE evidence, a real EAR minted by the live CDS, the real
# measurement gate on the probe's own pin (accept and refuse), and the
# transfer over the cluster network.
#
# Needs: kubectl pointed at a node-as-CVM cluster running the chart's
# attestation-api DaemonSet (gke/aks-style installs) with
# cds.handoff.enabled=true, and a deployed cds image that includes the
# request-handoff subcommand. Kata (in-guest endpoint) and cvmMode=node
# (CDS's URL carries an unexpanded $(HOST_IP) the probe pod cannot resolve)
# are unsupported.
#
# Env:
#   CDS_NS                 namespace of the cds deployment (default: discover)
#   PROBE_TIMEOUT_SECONDS  wait for the accept probe pod to finish (default
#                          180); the wrong-pin probe gets a fixed 30s budget
set -euo pipefail
. "$(dirname "$0")/lib.sh"

probe_timeout="${PROBE_TIMEOUT_SECONDS:-180}"
cds_selector="app.kubernetes.io/name=c8s-operator,app.kubernetes.io/component=cds"

cds_ns=""
pod=""
bad_pod=""
kget_err=$(mktemp)
cleanup() {
  rm -f "$kget_err"
  if [ -n "$cds_ns" ] && [ -n "$pod" ]; then
    kubectl delete pod "$pod" "$bad_pod" -n "$cds_ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
}
# INT/TERM as well as EXIT: a Ctrl-C during a probe wait must not leave a
# probe pod (with the cds SA and pull rights) parked on the node.
trap cleanup EXIT INT TERM

# kget runs kubectl and, on failure, surfaces the real error instead of
# letting an empty result masquerade as "resource not found". stderr goes to
# a side file so a kubectl warning cannot corrupt the parsed output.
kget() {
  local out
  if ! out=$(kubectl "$@" 2>"$kget_err"); then
    fail "kubectl $* failed: $(cat "$kget_err")"
  fi
  printf '%s\n' "$out"
}

# --- discover the cds deployment ---------------------------------------------

ns_flag=(--all-namespaces)
[ -n "${CDS_NS:-}" ] && ns_flag=(-n "$CDS_NS")
read -r cds_ns cds_deploy < <(kget get deploy "${ns_flag[@]}" -l "$cds_selector" \
  -o jsonpath='{range .items[0]}{.metadata.namespace} {.metadata.name}{end}')
[ -n "${cds_deploy:-}" ] || fail "no cds deployment found (is the c8s chart installed? set CDS_NS to pick a namespace)"

# Wait for the deployment to be fully rolled out so any Running cds pod is the
# current generation, not a lingering old ReplicaSet pod (e.g. right after a
# `helm upgrade --set cds.handoff.enabled=true`).
kubectl rollout status deploy "$cds_deploy" -n "$cds_ns" --timeout=120s >/dev/null \
  || fail "cds deployment $cds_ns/$cds_deploy is not fully rolled out"

# The deployment's rendered args are the single source of truth for the
# probe's parameters; nothing is guessed or re-supplied by hand.
args=$(kget get deploy "$cds_deploy" -n "$cds_ns" \
  -o jsonpath='{range .spec.template.spec.containers[0].args[*]}{@}{"\n"}{end}')
arg() { sed -n "s/^--$1=//p" <<<"$args" | head -1; }

handoff_meas=$(arg handoff-measurements)
[ -n "$handoff_meas" ] || fail "cds runs without --handoff-measurements: /handoff is disabled. Enable it with: helm upgrade <release> ... --reuse-values --set cds.handoff.enabled=true (requires pinned cds.measurements). This script does not upgrade the release itself."

attest_url=$(arg attestation-api-url)
[ -n "$attest_url" ] || fail "cds args carry no --attestation-api-url"

ear_issuer=$(arg ear-issuer)
[ -n "$ear_issuer" ] || fail "cds args carry no --ear-issuer"

# Service by component + the named 'http' port, not positional indexes, so a
# prepended port or added sidecar does not shift the scrape.
read -r cds_svc cds_svc_port < <(kget get svc -n "$cds_ns" -l "$cds_selector" \
  -o jsonpath='{range .items[0]}{.metadata.name} {.spec.ports[?(@.name=="http")].port}{end}')
[ -n "${cds_svc:-}" ] || fail "no cds Service in $cds_ns"
[ -n "${cds_svc_port:-}" ] || fail "cds Service $cds_ns/$cds_svc has no port named http"
peer_url="https://${cds_svc}.${cds_ns}.svc:${cds_svc_port}"

# When cds reaches the attestation-api over its node-local Unix socket, the
# probe can only follow it with the socket directory mounted at the host path.
socket_mount=""
socket_volume=""
case "$attest_url" in
  unix://*/*)
    socket_dir=$(dirname "${attest_url#unix://}")
    socket_mount="
        - name: attestation-api-socket
          mountPath: $socket_dir
          readOnly: true"
    socket_volume="
    - name: attestation-api-socket
      hostPath:
        path: $socket_dir
        type: Directory"
    ;;
esac

# --- probe pod: deployed cds image, pinned to the cds node -------------------

# kubectl-only (no jq dependency, matching the sibling e2e scripts). Each
# pod field is read by name-keyed jsonpath so a sidecar cannot shift a
# positional index. One newline-joined read; sed splits the fields.
cds_pod=$(kget get pods -n "$cds_ns" -l "$cds_selector" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}')
[ -n "${cds_pod:-}" ] || fail "no Running cds pod in $cds_ns"

# Refuse kata (in-guest attestation) by the chart's real signal, the pod's
# runtimeClassName, rather than sniffing the attestation-api URL shape.
runtime_class=$(kget get pod "$cds_pod" -n "$cds_ns" -o jsonpath='{.spec.runtimeClassName}')
case "$runtime_class" in
  *kata*) fail "cds runs under kata (runtimeClassName=$runtime_class); this probe supports node-as-CVM mode only" ;;
esac

# ServiceAccount (image pull secrets), node (measurement match), tolerations
# (NoExecute applies even to nodeName-pinned pods), the cds container image,
# and both securityContext levels ride on the live cds pod so the probe never
# drifts from the chart or trips Pod Security. cds_selector is a container-name
# jsonpath filter for the image/securityContext so a sidecar cannot shift it.
c='?(@.name=="cds")'
pod_fields=$(kget get pod "$cds_pod" -n "$cds_ns" -o jsonpath="\
{.spec.serviceAccountName}{\"\n\"}\
{.spec.nodeName}{\"\n\"}\
{.spec.containers[$c].image}{\"\n\"}\
{.spec.tolerations}{\"\n\"}\
{.spec.securityContext}{\"\n\"}\
{.spec.containers[$c].securityContext}")
cds_sa=$(sed -n 1p <<<"$pod_fields")
cds_node=$(sed -n 2p <<<"$pod_fields")
cds_image=$(sed -n 3p <<<"$pod_fields")
tolerations=$(sed -n 4p <<<"$pod_fields"); [ -n "$tolerations" ] || tolerations='[]'
pod_sec_ctx=$(sed -n 5p <<<"$pod_fields"); [ -n "$pod_sec_ctx" ] || pod_sec_ctx='{}'
ctr_sec_ctx=$(sed -n 6p <<<"$pod_fields"); [ -n "$ctr_sec_ctx" ] || ctr_sec_ctx='{}'
[ -n "$cds_image" ] || fail "cds pod $cds_ns/$cds_pod has no container named cds"

pod="ca-handoff-probe-$$"
bad_pod="$pod-bad"
operator_keys_cm="${cds_deploy}-operator-keys"
kubectl get configmap "$operator_keys_cm" -n "$cds_ns" >/dev/null 2>&1 ||
  fail "CDS handoff requires operator keys, but ConfigMap $cds_ns/$operator_keys_cm is missing"
echo "cds: $cds_ns/$cds_deploy on $cds_node; peer $peer_url"

# run_probe <name> <measurements> [timeout-seconds]: launch the probe pod and
# print its terminal phase on stdout. Release namespace + cds ServiceAccount:
# image pull secrets ride along and the image digest is already in the
# allowlist floor. nodeName pins the probe to cds's node so its launch
# measurement matches --handoff-measurements and the node-local
# attestation-api attests the right node. The in-pod --timeout defaults to
# PROBE_TIMEOUT_SECONDS; the pod-watch runs 30s past it to observe the
# verdict.
run_probe() {
  local name=$1 meas=$2 timeout=${3:-$probe_timeout}
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: $cds_ns
spec:
  restartPolicy: Never
  nodeName: $cds_node
  serviceAccountName: $cds_sa
  automountServiceAccountToken: false
  tolerations: $tolerations
  securityContext: $pod_sec_ctx
  containers:
    - name: probe
      image: $cds_image
      # The copied --attestation-api-url keeps the chart's \$(HOST_IP) form
      # under cvmMode=node; kubelet expands it only if the pod defines the env.
      env:
        - name: HOST_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
      args:
        - request-handoff
        - --peer-url=$peer_url
        - --attestation-api-url=$attest_url
        - --measurements=$meas
        - --operator-keys=/etc/cds-operator-keys/keys.pem
        - --expected-issuer=$ear_issuer
        - --timeout=${timeout}s
      volumeMounts:
        - name: operator-keys
          mountPath: /etc/cds-operator-keys
          readOnly: true$socket_mount
      securityContext: $ctr_sec_ctx
  volumes:
    - name: operator-keys
      configMap:
        name: $operator_keys_cm$socket_volume
EOF
  local deadline=$((SECONDS + timeout + 30)) phase=""
  while :; do
    phase=$(kubectl get pod "$name" -n "$cds_ns" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    case "$phase" in Succeeded|Failed) break ;; esac
    if [ "$SECONDS" -ge "$deadline" ]; then
      kubectl describe pod "$name" -n "$cds_ns" >&2 || true
      fail "probe $name did not reach a terminal phase in $((timeout + 30))s (phase=${phase:-unknown})"
    fi
    sleep 3
  done
  printf '%s\n' "$phase"
}

# --- accept: the pinned probe pulls the live trust root -----------------------

phase=$(run_probe "$pod" "$handoff_meas")
kubectl logs "$pod" -n "$cds_ns" || true

# Pod phase is the verdict: Succeeded means the probe exited 0, which by
# construction requires the pulled CA to match the served trust root.
[ "$phase" = Succeeded ] || fail "handoff probe failed (see logs above)"
echo "ok: pinned probe pulled the CA over /handoff and matched the served trust root"

# --- negative: a wrong --measurements pin is refused --------------------------

# 48 zero bytes: well-formed SHA-384 hex no launch produces. The refusal is
# the probe's own RA-TLS client rejecting the peer cert, which surfaces as a
# plain *url.Error, so ClassifyPullError calls it PullTransient: the probe
# retries the settled verdict until --timeout and exits 3 — still Failed,
# with the mismatch text logged on every attempt. Hence the short 30s budget.
bad_meas=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
phase=$(run_probe "$bad_pod" "$bad_meas" 30)
bad_logs=$(kubectl logs "$bad_pod" -n "$cds_ns" 2>/dev/null || true)
printf '%s\n' "$bad_logs"
[ "$phase" = Failed ] || fail "probe with a wrong --measurements pin was not refused (phase=${phase:-unknown}; logs above)"
grep -q "launch measurement does not match any reference value" <<<"$bad_logs" \
  || fail "refused probe's log names no measurement mismatch (see above)"
echo "ok: wrong --measurements pin refused (log names the measurement mismatch)"

echo "PASS: mesh CA handoff verified end-to-end (EAR-gated transfer, served-CA match, wrong-pin refusal)"
