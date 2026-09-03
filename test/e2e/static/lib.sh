#!/usr/bin/env bash
# Shared helpers for the static-allowlist e2e checks under test/e2e/static/.
# Source it after `set -euo pipefail`:
#
#   . "$(dirname "$0")/lib.sh"
#
# It pulls in test/e2e/lib.sh (fail) and adds the sealed-plugin denial
# probe, expect_deny, and the RTMR[3] arithmetic of pkg/runtimemeasure in
# shell (SHA-384 over openssl), so the lane can predict a register from the
# host without a Go toolchain on the assertion path.
# shellcheck disable=SC1091  # resolved relative to this file at run time
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

# sealed_denied is the waiting message the sealed plugin leaves on a refused
# container (internal/cmds/nri-image-policy/sealed_plugin.go sealedAdmit).
# shellcheck disable=SC2034  # read by the scripts that source this file
sealed_denied='container not admitted by the sealed allowlist'

# expect_deny <description> <expected-substring> -- <command...>
# Runs the command, requires it to fail, and requires the output to contain
# <expected-substring> so the check proves which guard fired.
expect_deny() {
  (( $# >= 3 )) || fail "expect_deny: usage: expect_deny <description> <expected-substring> -- <command...>"
  [[ $3 == -- ]] || fail "expect_deny: expected '--' before the command, got '$3'"
  local what=$1 want=$2
  shift 3
  (( $# > 0 )) || fail "expect_deny: missing command after '--'"
  local out
  if out=$("$@" 2>&1); then
    fail "$what was admitted; want denial matching '$want'. output: $out"
  fi
  grep -q -- "$want" <<<"$out" \
    || fail "$what was denied, but not by the expected guard (want '$want'): $out"
  echo "ok: $what denied"
}

# wait_container_denied <namespace> <pod> <status-list> <container>
# Polls the container's waiting message in .status.<status-list>
# (containerStatuses, initContainerStatuses or ephemeralContainerStatuses)
# until the sealed plugin's denial appears. A container that starts instead
# is a security regression.
wait_container_denied() {
  local ns=$1 pod=$2 list=$3 name=$4 msg="" state=""
  for _ in $(seq 1 "${E2E_DENY_WAIT:-90}"); do
    msg=$(kubectl -n "$ns" get pod "$pod" \
      -o jsonpath="{.status.${list}[?(@.name==\"${name}\")].state.waiting.message}" 2>/dev/null || true)
    case "$msg" in *"$sealed_denied"*) echo "ok: $pod/$name refused by the sealed allowlist"; return 0 ;; esac
    state=$(kubectl -n "$ns" get pod "$pod" \
      -o jsonpath="{.status.${list}[?(@.name==\"${name}\")].state}" 2>/dev/null || true)
    case "$state" in
      *running*|*terminated*)
        kubectl -n "$ns" describe pod "$pod" | tail -25
        fail "SECURITY REGRESSION: $pod/$name ran on a sealed node (state: $state)" ;;
    esac
    sleep 2
  done
  kubectl -n "$ns" describe pod "$pod" | tail -25
  fail "$pod/$name was neither refused nor started within the window (waiting message: ${msg:-none})"
}

# sha384_hex reads stdin and prints its SHA-384 as lowercase hex.
sha384_hex() { openssl dgst -sha384 | awk '{print $NF}'; }

# hex2bin writes the bytes of a hex string to stdout.
hex2bin() {
  local hex=$1 i
  for ((i = 0; i < ${#hex}; i += 2)); do
    printf '%b' "\\x${hex:i:2}"
  done
}

# hex2octal prints a hex string as the \ooo escapes a POSIX printf turns
# back into bytes, for a shell inside a container image that has no bash.
hex2octal() {
  local hex=$1 i
  for ((i = 0; i < ${#hex}; i += 2)); do
    printf '\\%03o' "0x${hex:i:2}"
  done
}

# extend_hex <register-hex> <event-hex> prints SHA384(register || event),
# the hardware extend (pkg/runtimemeasure Extend).
extend_hex() { { hex2bin "$1"; hex2bin "$2"; } | sha384_hex; }

# Mode events (pkg/runtimemeasure ModeStatic, ModeDynamic): SHA-384 of the
# ASCII label.
mode_static_hex() { printf '%s' 'c8s/rtmr3/mode/static/v1' | sha384_hex; }
mode_dynamic_hex() { printf '%s' 'c8s/rtmr3/mode/dynamic/v1' | sha384_hex; }

# bundle_index <static-allowlist.json> prints the index of a one-member
# bundle: pkg/policybundle Bundle.Index, the canonical JSON of
# {name: "sha256:<hex>"} over the member bytes.
bundle_index() {
  local sum
  sum=$(sha256sum "$1" | cut -d' ' -f1)
  printf '{"static-allowlist.json":"sha256:%s"}' "$sum"
}

# policy_event_hex <index> prints SHA384("c8s/rtmr3/policy/v1:" || index)
# (pkg/runtimemeasure PolicyEvent).
policy_event_hex() { printf 'c8s/rtmr3/policy/v1:%s' "$1" | sha384_hex; }

# static_rtmr3_hex <static-allowlist.json> prints the register a node sealed
# to the one-member bundle reports (pkg/runtimemeasure ForStaticAllowlist).
static_rtmr3_hex() {
  local zero
  zero=$(printf '%096d' 0)
  extend_hex "$(extend_hex "$zero" "$(mode_static_hex)")" "$(policy_event_hex "$(bundle_index "$1")")"
}

# operator_seed_hex <pubkey.pem> prints ForOperatorKey over the file's exact
# bytes: SHA384(0x00*48 || SHA384(pubkey)).
operator_seed_hex() {
  local zero
  zero=$(printf '%096d' 0)
  extend_hex "$zero" "$(sha384_hex < "$1")"
}

# dynamic_rtmr3_hex <pubkey.pem> prints the register a dynamic node launched
# with that operator key reports after the mode event
# (pkg/runtimemeasure ForDynamic(ForOperatorKey(pub))).
dynamic_rtmr3_hex() { extend_hex "$(operator_seed_hex "$1")" "$(mode_dynamic_hex)"; }

# cilium_copy_manifest <namespace> <pod> <image> <shell-script>
# Prints a pod that runs the node's own Cilium image privileged, with the
# host /sys bound at /host/sys and the given script as its command: the
# "privileged copy of cilium" the design names. Its digest is on the node's
# floor, so only the sealed rules stand between it and node root. The
# namespace must be one the chart's host-namespace admission policy exempts
# (kube-system, or the release namespace), or the API server refuses the
# hostPath volume before any node sees the container.
cilium_copy_manifest() {
  local ns=$1 pod=$2 image=$3 script=$4
  cat <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  namespace: $ns
spec:
  restartPolicy: Never
  enableServiceLinks: false
  volumes:
    - name: sys
      hostPath:
        path: /sys
  containers:
    - name: agent
      image: $image
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-c", $script]
      securityContext:
        privileged: true
      volumeMounts:
        - name: sys
          mountPath: /host/sys
YAML
}

# cilium_image prints the image the node's Cilium DaemonSet runs.
cilium_image() {
  local image
  image=$(kubectl -n kube-system get ds cilium \
    -o jsonpath='{.spec.template.spec.containers[?(@.name=="cilium-agent")].image}' 2>/dev/null || true)
  [ -n "$image" ] || fail "no cilium-agent container in the kube-system cilium DaemonSet"
  printf '%s' "$image"
}
