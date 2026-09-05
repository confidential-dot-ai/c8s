#!/bin/bash
# Root-free tests for the exact production psa-ready.sh. A fake kubectl models
# RKE2 AddOn readiness and admission outcomes; the gate itself is not copied or
# sourced, so changes to its control flow are exercised byte-for-byte.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${PSA_READY_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/psa-ready.sh"}
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAKE_KUBECTL="$WORK/kubectl"
CA_KEY="$WORK/client-ca.key"
KUBECONFIG_FILE="$WORK/rke2.yaml"
touch "$CA_KEY" "$KUBECONFIG_FILE"

cat >"$FAKE_KUBECTL" <<'EOF'
#!/bin/bash
set -u
: "${FAKE_MODE:?}"
: "${FAKE_LOG:?}"

positional=()
while (( $# > 0 )); do
    case "$1" in
        --kubeconfig|--cache-dir) shift 2 ;;
        --as=*) shift ;;
        *) positional+=("$1"); shift ;;
    esac
done
set -- "${positional[@]}"
printf '%s\n' "$*" >>"$FAKE_LOG"

if [[ ${1:-} == get ]]; then
    if [[ $FAKE_MODE == missing-policy && ${2:-} == validatingadmissionpolicy ]]; then
        exit 1
    fi
    exit 0
fi

if [[ ${1:-} == apply ]]; then
    cat >/dev/null
    [[ $FAKE_MODE != rbac-failure ]]
    exit
fi

if [[ ${1:-} == create ]]; then
    body=$(cat)
    if grep -q 'enforce: privileged' <<<"$body"; then
        case "$FAKE_MODE" in
            enforced|restricted-denied)
                echo "Error from server (Invalid): ValidatingAdmissionPolicy 'confos-psa-level' denied the request: pod-security.kubernetes.io/enforce may not be set below restricted" >&2
                exit 1
                ;;
            wrong-denial)
                echo "Error from server (Forbidden): denied by some-other-policy" >&2
                exit 1
                ;;
            fail-open) exit 0 ;;
        esac
    fi
    if [[ $FAKE_MODE == restricted-denied ]]; then
        echo "Error from server (Forbidden): restricted probe denied" >&2
        exit 1
    fi
    exit 0
fi

# Cleanup deletes are deliberately successful and logged.
if [[ ${1:-} == delete ]]; then
    exit 0
fi
exit 2
EOF
chmod +x "$FAKE_KUBECTL"

run_gate() {
    local mode=$1
    : >"$WORK/log"
    : >"$WORK/stdout"
    : >"$WORK/stderr"
    FAKE_MODE="$mode" FAKE_LOG="$WORK/log" \
        KUBECTL="$FAKE_KUBECTL" KUBECONFIG="$KUBECONFIG_FILE" \
        KUBECTL_CACHE_DIR="$WORK/cache" CLIENT_CA_KEY="$CA_KEY" \
        PSA_WAIT_ATTEMPTS=2 PSA_WAIT_SECONDS=0 \
        "$SCRIPT" >"$WORK/stdout" 2>"$WORK/stderr"
}

CASE="enforced policy"
ok "passes both live probes" run_gate enforced
ok "reports enforcement" grep -q 'is enforcing the restricted namespace floor' "$WORK/stdout"
ok "cleans the probe binding" grep -q '^delete clusterrolebinding confos-psa-readiness-probe ' "$WORK/log"
ok "cleans the probe role" grep -q '^delete clusterrole confos-psa-readiness-probe ' "$WORK/log"

CASE="AddOn absent"
ok "fails closed" not run_gate missing-policy
ok "names the missing policy" stderr_has 'ValidatingAdmissionPolicy confos-psa-level is not available'

CASE="binding present but policy fail-open"
ok "fails closed" not run_gate fail-open
ok "names the admitted privileged probe" stderr_has 'privileged namespace dry-run was admitted'

CASE="denied by the wrong guard"
ok "fails closed" not run_gate wrong-denial
ok "does not mistake an arbitrary denial for readiness" stderr_has 'denied by a different guard'

CASE="restricted request is over-denied"
ok "fails closed" not run_gate restricted-denied
ok "names the broken allow path" stderr_has 'restricted namespace dry-run was denied'

CASE="temporary RBAC cannot be installed"
ok "fails closed" not run_gate rbac-failure
ok "names the RBAC failure" stderr_has 'could not install the temporary readiness-probe RBAC'

summarize "psa-ready"
