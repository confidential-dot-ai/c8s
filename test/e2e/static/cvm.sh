#!/usr/bin/env bash
# KubeVirt lifecycle of one TDX node CVM for the static lane, run from the
# host-side launcher runner (its SA is scoped to the image namespace):
#
#   cvm.sh create NAME          scratch PVC, bait cloud-init Secret and the VM
#   cvm.sh wait-running NAME    waits for the VMI and prints its address
#   cvm.sh assert-tdx NAME      qemu was launched with -object tdx-guest
#   cvm.sh wait-services ADDR   attestation-api :8400 (tdx), apiserver :6443, cred-release :8443
#   cvm.sh wait-stopped NAME SECONDS  the guest powered itself off
#   cvm.sh delete NAME          the VM, its Secrets and its scratch PVC
#
# The VM is the vendored tdx-metal-e2e.yml one (root disk read-only on the
# shared PVC, scratch disk with serial confai-scratch, bait cidata disk,
# launchSecurity tdx), with the launch attachments chosen by env:
#   NS                   namespace (required)
#   rootPvc              the shared node image PVC (required for create)
#   CVM_OPKEY_SECRET     Secret attached as the opkeydata disk (dynamic boot)
#   CVM_POLICYDATA_SECRET Secret attached as the policydata disk (static boot)
#   CVM_RUN_STRATEGY     Always (default) or RerunOnFailure. Under
#                        RerunOnFailure a guest power-off leaves the VMI
#                        Succeeded, the VM controller then deletes the VMI
#                        and the VM reports Stopped; wait-stopped accepts
#                        either observation.
#   CVM_MEMORY           guest memory (default 16Gi)
#   GITHUB_RUN_ID, GITHUB_REPOSITORY, GITHUB_SERVER_URL  reaper labels (optional)
set -euo pipefail
# shellcheck disable=SC1091  # resolved relative to this script at run time
. "$(dirname "$0")/lib.sh"

: "${NS:?KubeVirt namespace}"
cmd=${1:-}
name=${2:-}
[ -n "$cmd" ] && [ -n "$name" ] || fail "usage: cvm.sh <create|wait-running|assert-tdx|wait-services|wait-stopped|delete> <name|addr> [seconds]"

create() {
  : "${rootPvc:?node image PVC}"
  local run_id=${GITHUB_RUN_ID:-} repo=${GITHUB_REPOSITORY:-} server=${GITHUB_SERVER_URL:-}
  local strategy=${CVM_RUN_STRATEGY:-Always} memory=${CVM_MEMORY:-16Gi}
  local disks="" volumes=""
  if [ -n "${CVM_OPKEY_SECRET:-}" ]; then
    disks+=$'            - name: opkey\n              disk: {bus: virtio}\n'
    volumes+="        - name: opkey"$'\n'"          secret: {secretName: $CVM_OPKEY_SECRET, volumeLabel: opkeydata}"$'\n'
  fi
  if [ -n "${CVM_POLICYDATA_SECRET:-}" ]; then
    disks+=$'            - name: policydata\n              disk: {bus: virtio}\n'
    volumes+="        - name: policydata"$'\n'"          secret: {secretName: $CVM_POLICYDATA_SECRET, volumeLabel: policydata}"$'\n'
  fi
  kubectl apply -f - <<EOF_VM
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $name-scratch
  namespace: $NS
  labels: {ci.confidential.ai/managed: "true"}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 80Gi}}
  storageClassName: local-path
---
apiVersion: v1
kind: Secret
metadata: {name: $name-cloudinit, namespace: $NS}
type: Opaque
# Bait, not configuration: the node image disables cloud-init, so this host
# disk must be inert (the cidata tripwire asserts it).
stringData:
  userdata: |
    #cloud-config
    hostname: cidata-bait
---
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: $name
  namespace: $NS
  labels:
    ci.confidential.ai/managed: "true"
    ci.confidential.ai/run-id: "$run_id"
  annotations:
    ci.confidential.ai/repo: "$repo"
    ci.confidential.ai/run-url: "$server/$repo/actions/runs/$run_id"
spec:
  runStrategy: $strategy
  template:
    metadata:
      labels: {kubevirt.io/domain: $name}
    spec:
      nodeSelector:
        kubevirt.io/tdx: "true"
      domain:
        cpu:
          # host-passthrough is mandatory: QEMU rejects a named model for TDX.
          model: host-passthrough
          cores: 4
        devices:
          autoattachVSOCK: true
          disks:
            - name: rootdisk
              # dm-verity rootfs, never written; readonly takes a shared qemu
              # lock so concurrent CVMs on the same PVC coexist.
              disk: {bus: virtio, readonly: true}
            - name: scratch
              disk: {bus: virtio}
              # The initrd keys the encrypted overlay off this exact serial.
              serial: confai-scratch
$disks            - name: cloudinit
              disk: {bus: virtio}
          interfaces: [{name: default, masquerade: {}}]
          rng: {}
        firmware: {bootloader: {efi: {secureBoot: false}}}
        launchSecurity: {tdx: {}}
        memory: {guest: $memory}
        resources: {requests: {memory: $memory}}
      networks: [{name: default, pod: {}}]
      volumes:
        - name: rootdisk
          persistentVolumeClaim: {claimName: $rootPvc}
        - name: scratch
          persistentVolumeClaim: {claimName: $name-scratch}
$volumes        - name: cloudinit
          cloudInitNoCloud: {secretRef: {name: $name-cloudinit}}
EOF_VM
}

wait_running() {
  local phase="" ip=""
  for _ in $(seq 1 60); do
    phase=$(kubectl -n "$NS" get vmi "$name" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [ "$phase" = Running ] && break
    sleep 5
  done
  if [ "$phase" != Running ]; then
    kubectl -n "$NS" describe vmi "$name" 2>&1 | tail -25 >&2 || true
    fail "VMI $name not Running (phase=${phase:-none}). 'Insufficient devices.kubevirt.io/tdx' means virt-handler latched 0: rollout restart daemonset/virt-handler -n kubevirt"
  fi
  ip=$(kubectl -n "$NS" get vmi "$name" -o jsonpath='{.status.interfaces[0].ipAddress}')
  [ -n "$ip" ] || fail "VMI $name has no guest address"
  echo "VMI $name Running at $ip" >&2
  printf '%s' "$ip"
}

assert_tdx() {
  local pod count
  pod=$(kubectl -n "$NS" get pods -l kubevirt.io/domain="$name" -o name | head -1)
  [ -n "$pod" ] || fail "no virt-launcher pod for $name"
  # shellcheck disable=SC2016  # the substitution runs in the launcher pod
  count=$(kubectl -n "$NS" exec "$pod" -c compute -- \
    bash -c 'tr "\0" "\n" < /proc/$(pgrep -f qemu-system | head -1)/cmdline | grep -c "tdx-guest"' || true)
  [ "${count:-0}" -ge 1 ] || fail "qemu for $name has no tdx-guest object: not a genuine trust domain"
  echo "ok: $name launched with -object tdx-guest"
}

wait_services() {
  local addr=$name health="" code=""
  for _ in $(seq 1 90); do
    health=$(curl -s --connect-timeout 2 --max-time 4 "http://$addr:8400/health" 2>/dev/null || true)
    [ -n "$health" ] && { echo "attestation-api: $health"; break; }
    sleep 10
  done
  grep -q '"platform":"tdx"' <<<"$health" || fail "attestation-api at $addr did not report platform=tdx"
  for _ in $(seq 1 60); do
    code=$(curl -sk --max-time 4 -o /dev/null -w '%{http_code}' "https://$addr:6443/livez" 2>/dev/null || true)
    case "$code" in 200|401|403) echo "kube-apiserver: HTTP $code"; break ;; esac
    sleep 5
  done
  case "$code" in 200|401|403) ;; *) fail "kube-apiserver at $addr:6443 did not answer" ;; esac
  for _ in $(seq 1 60); do
    code=$(curl -sk --max-time 4 -o /dev/null -w '%{http_code}' "https://$addr:8443/" 2>/dev/null || true)
    [ -n "$code" ] && [ "$code" != 000 ] && { echo "cred-release: HTTP $code"; break; }
    sleep 5
  done
  [ -n "$code" ] && [ "$code" != 000 ] || fail "cred-release at $addr:8443 did not answer"
}

wait_stopped() {
  local budget=${3:?seconds to wait} phase="" seen="" vmstatus="" waited=0
  while [ "$waited" -lt "$budget" ]; do
    phase=$(kubectl -n "$NS" get vmi "$name" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [ -n "$phase" ] && seen=1
    case "$phase" in
      Succeeded) echo "ok: $name powered itself off after ${waited}s (VMI Succeeded)"; return 0 ;;
      Failed)
        kubectl -n "$NS" describe vmi "$name" | tail -25
        fail "$name crashed (VMI Failed) rather than powering off" ;;
      "")
        # RerunOnFailure deletes a Succeeded VMI and leaves the VM Stopped,
        # often between two polls. A fresh VM is also Stopped before its
        # VMI exists, hence the seen guard.
        vmstatus=$(kubectl -n "$NS" get vm "$name" -o jsonpath='{.status.printableStatus}' 2>/dev/null || true)
        if [ -n "$seen" ] && [ "$vmstatus" = Stopped ]; then
          echo "ok: $name powered itself off after ${waited}s (VM Stopped, VMI reaped)"; return 0
        fi ;;
    esac
    sleep 10
    waited=$((waited + 10))
  done
  kubectl -n "$NS" describe vm "$name" | tail -25
  fail "$name is still ${phase:-absent} (VM ${vmstatus:-unknown}) after ${budget}s; the guest did not power off"
}

delete() {
  set +e
  kubectl -n "$NS" delete vm "$name" --ignore-not-found --wait=true --timeout=120s
  kubectl -n "$NS" delete secret "$name-cloudinit" "${CVM_OPKEY_SECRET:-$name-opkey}" "${CVM_POLICYDATA_SECRET:-$name-policydata}" --ignore-not-found
  kubectl -n "$NS" delete pvc "$name-scratch" --ignore-not-found --wait=false
  set -e
}

case "$cmd" in
  create) create ;;
  wait-running) wait_running ;;
  assert-tdx) assert_tdx ;;
  wait-services) wait_services ;;
  wait-stopped) wait_stopped "$@" ;;
  delete) delete ;;
  *) fail "unknown command $cmd" ;;
esac
