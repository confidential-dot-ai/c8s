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
ns=
while (( $# > 0 )); do
    case "$1" in
        --kubeconfig|--cache-dir) shift 2 ;;
        --as=*|--as-group=*) shift ;;
        -n) ns=$2; shift 2 ;;
        *) positional+=("$1"); shift ;;
    esac
done
set -- "${positional[@]}"
printf '%s\n' "$*" >>"$FAKE_LOG"

# Guard comparison: replace --dry-run renders the reference copy, get -f the
# live objects. They agree unless a drift mode says otherwise.
if [[ ${1:-} == replace ]]; then
    [[ $FAKE_MODE == guard-rejected ]] && { echo "error: reference copy rejected" >&2; exit 1; }
    echo "fields-of-$(basename "$4")"
    exit 0
fi
if [[ ${1:-} == get && ${2:-} == -f ]]; then
    case "$FAKE_MODE:$(basename "$3")" in
        guard-missing:*) echo "Error from server (NotFound): not found" >&2; exit 1 ;;
        guard-drift:operator-scope-policy.yaml) echo "fields-of-tampered"; exit 0 ;;
        guard-drift-skipped:pod-exec-policy.yaml) echo "fields-of-tampered"; exit 0 ;;
    esac
    echo "fields-of-$(basename "$3")"
    exit 0
fi

if [[ ${1:-} == get ]]; then
    if [[ $FAKE_MODE == missing-policy && ${2:-} == validatingadmissionpolicy && ${3:-} == confos-psa-level ]]; then
        exit 1
    fi
    if [[ $FAKE_MODE == missing-exec-policy* && ${2:-} == validatingadmissionpolicy && ${3:-} == confos-pod-exec ]]; then
        exit 1
    fi
    if [[ $FAKE_MODE == missing-scope-policy && ${2:-} == validatingadmissionpolicybinding && ${3:-} == confos-operator-scope ]]; then
        exit 1
    fi
    if [[ $FAKE_MODE == missing-log-reader-binding && ${2:-} == clusterrolebinding && ${3:-} == c8s-log-readers ]]; then
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
    if grep -q 'kind: ConfigMap' <<<"$body"; then
        scope_denial="Error from server (Invalid): ValidatingAdmissionPolicy 'confos-operator-scope' denied the request: c8s credentials may not write in the PodSecurity-exempt namespaces (kube-system, local-path-storage)"
        case "$FAKE_MODE:$ns" in
            scope-fail-open:*) exit 0 ;;
            scope-over-denied:default) echo "$scope_denial" >&2; exit 1 ;;
            scope-wrong-denial:kube-system) echo "Error from server (Forbidden): denied by some-other-policy" >&2; exit 1 ;;
            *:kube-system) echo "$scope_denial" >&2; exit 1 ;;
            *) exit 0 ;;
        esac
    fi
    if grep -q 'enforce: privileged' <<<"$body"; then
        case "$FAKE_MODE" in
            enforced|restricted-denied|missing-exec-policy-dev|scope-fail-open|scope-over-denied|scope-wrong-denial|guard-*)
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

MANIFESTS="$WORK/manifests"
DEV_MANIFESTS="$WORK/manifests-dev"
GUARDS="$WORK/guards"
EMPTY_GUARDS="$WORK/guards-empty"
mkdir -p "$MANIFESTS" "$DEV_MANIFESTS" "$GUARDS" "$EMPTY_GUARDS"
touch "$DEV_MANIFESTS/pod-exec-policy.yaml.skip"
for g in psa-level-policy pod-exec-policy operator-scope-policy cred-release-rbac log-reader-rbac; do
    echo "kind: reference" >"$GUARDS/$g.yaml"
done

run_gate() {
    local mode=$1 manifests=$MANIFESTS guards=$GUARDS
    [[ $mode == *-dev ]] && manifests=$DEV_MANIFESTS
    [[ $mode == guard-none ]] && guards=$EMPTY_GUARDS
    : >"$WORK/log"
    : >"$WORK/stdout"
    : >"$WORK/stderr"
    FAKE_MODE="$mode" FAKE_LOG="$WORK/log" \
        KUBECTL="$FAKE_KUBECTL" KUBECONFIG="$KUBECONFIG_FILE" \
        KUBECTL_CACHE_DIR="$WORK/cache" CLIENT_CA_KEY="$CA_KEY" \
        MANIFESTS_DIR="$manifests" GUARDS_DIR="$guards" \
        PSA_WAIT_ATTEMPTS=2 PSA_WAIT_SECONDS=0 \
        "$SCRIPT" >"$WORK/stdout" 2>"$WORK/stderr"
}

CASE="enforced policy"
ok "passes both live probes" run_gate enforced
ok "reports enforcement" grep -q 'is enforcing the restricted namespace floor' "$WORK/stdout"
ok "reports operator scope" grep -q 'confos-operator-scope is enforcing the operator scope' "$WORK/stdout"
ok "reports guard match" grep -q 'live guards match' "$WORK/stdout"
ok "renders every reference copy server-side" [ "$(grep -c '^replace --dry-run=server -f ' "$WORK/log")" = 5 ]
ok "fetches the live objects of every guard" [ "$(grep -c '^get -f ' "$WORK/log")" = 5 ]

CASE="a live guard differs from its read-only copy"
ok "fails closed" not run_gate guard-drift
ok "names the drifted guard" stderr_has 'guard operator-scope-policy: live objects differ from the read-only reference copy'

CASE="a live guard object is missing"
ok "fails closed" not run_gate guard-missing
ok "names the missing objects" stderr_has 'live objects are not all present'

CASE="the reference copy is not admitted"
ok "fails closed" not run_gate guard-rejected
ok "names the rejected copy" stderr_has 'reference copy is not admitted by the apiserver'

CASE="no reference copies at all"
ok "fails closed" not run_gate guard-none
ok "names the empty directory" stderr_has 'no guard reference copies in'

CASE="a skipped guard is not compared (dev build)"
ok "passes with the skipped guard drifted" run_gate guard-drift-skipped-dev
ok "never renders the skipped guard" not grep -q '^replace --dry-run=server -f .*pod-exec-policy.yaml' "$WORK/log"
ok "cleans the probe binding" grep -q '^delete clusterrolebinding confos-psa-readiness-probe ' "$WORK/log"
ok "cleans the probe role" grep -q '^delete clusterrole confos-psa-readiness-probe ' "$WORK/log"

CASE="AddOn absent"
ok "fails closed" not run_gate missing-policy
ok "names the missing policy" stderr_has 'ValidatingAdmissionPolicy confos-psa-level is not available'

CASE="log-reader binding absent"
ok "fails closed" not run_gate missing-log-reader-binding
ok "names the missing binding" stderr_has 'ClusterRoleBinding c8s-log-readers is not available'

CASE="pod-exec policy absent"
ok "fails closed" not run_gate missing-exec-policy
ok "names the missing policy" stderr_has 'ValidatingAdmissionPolicy confos-pod-exec is not available'

CASE="pod-exec policy skipped by the dev build"
ok "passes without the policy" run_gate missing-exec-policy-dev
ok "never waits for the skipped policy" not grep -q '^get validatingadmissionpolicy confos-pod-exec' "$WORK/log"

CASE="operator-scope binding absent"
ok "fails closed" not run_gate missing-scope-policy
ok "names the missing binding" stderr_has 'ValidatingAdmissionPolicyBinding confos-operator-scope is not available'

CASE="operator-scope policy fail-open"
ok "fails closed" not run_gate scope-fail-open
ok "names the admitted kube-system write" stderr_has 'dry-run in kube-system was admitted'

CASE="operator-scope over-denies tenant namespaces"
ok "fails closed" not run_gate scope-over-denied
ok "names the broken allow path" stderr_has 'dry-run in default was denied'

CASE="operator-scope denied by the wrong guard"
ok "fails closed" not run_gate scope-wrong-denial
ok "does not mistake an arbitrary denial for readiness" stderr_has 'kube-system was denied by a different guard'

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
