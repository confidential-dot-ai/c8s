#!/usr/bin/env bash
# Idempotent register / rename of a confidential runner scale set, with the
# GitHub credential handled BY REFERENCE (never inlined into helm values).
#
# Tier-1 hardening this script encodes:
#  - #2 secret-by-reference: the token is written to a K8s Secret and referenced
#    by name (githubConfigSecret=<name>), so it never lands in `helm get values`
#    (which is how it leaked before). Supply it via $GH_RUNNER_TOKEN — it is
#    never echoed. For git/GitOps storage, seal that Secret (see SECURITY.md);
#    this script never writes the token to disk.
#  - #3 idempotent rename: renaming an ARC scale set without purging leftover CRs
#    leaves the listener crash-looping on a stale ephemeralrunnerset
#    ("... not found", assigned job=0). RENAME_FROM does the clean cycle:
#    uninstall/delete old -> purge its CRs -> restart controller -> install new.
#
# Rotation (#1) is a GitHub-account action (revoke + mint a fresh credential) —
# see SECURITY.md. Once you have a new credential, re-run with $GH_RUNNER_TOKEN.
#
# Examples:
#   # bare-metal (Rancher proxy -> template mode):
#   GH_RUNNER_TOKEN=*** ORG_URL=https://github.com/cifrai SCALE_SET=cvm-launcher \
#     MODE=template SA=bm-e2e KUBECONFIG=~/dev/conf/github-runner.yaml ./register.sh
#   # GKE:
#   GH_RUNNER_TOKEN=*** ORG_URL=https://github.com/cifrai SCALE_SET=confidential-gcp \
#     SA=arc-e2e RUNNER_IMAGE=us-central1-docker.pkg.dev/.../confidential-runner-gcp:v2 \
#     KUBE_CONTEXT=gke_conf-500518_us-central1-a_arc-host ./register.sh
#   # rename (clean): RENAME_FROM=confidential-e2e SCALE_SET=confidential-gcp ... ./register.sh
#   # company org via GitHub App (org prod — see org-setup.md; release name differs
#   # from the cifrai scale set so both coexist, but the runs-on LABEL stays
#   # `cvm-launcher` via RUNNER_SCALE_SET_NAME):
#   APP_ID=… APP_INSTALLATION_ID=… APP_PRIVATE_KEY_FILE=app.pem \
#     ORG_URL=https://github.com/confidential-dot-ai SCALE_SET=cvm-launcher-conf \
#     RUNNER_SCALE_SET_NAME=cvm-launcher RUNNER_GROUP=confidential \
#     MODE=template SA=bm-e2e KUBECONFIG=~/dev/conf/github-runner.yaml ./register.sh
set -euo pipefail

# Credential: a PAT (GH_RUNNER_TOKEN) or a GitHub App (APP_ID +
# APP_INSTALLATION_ID + APP_PRIVATE_KEY_FILE). App is the org-prod path —
# scoped to "Self-hosted runners: rw", revocable, not tied to a person.
GH_RUNNER_TOKEN="${GH_RUNNER_TOKEN:-}"
APP_ID="${APP_ID:-}"; APP_INSTALLATION_ID="${APP_INSTALLATION_ID:-}"; APP_PRIVATE_KEY_FILE="${APP_PRIVATE_KEY_FILE:-}"
if [ -z "$GH_RUNNER_TOKEN" ] && { [ -z "$APP_ID" ] || [ -z "$APP_INSTALLATION_ID" ] || [ -z "$APP_PRIVATE_KEY_FILE" ]; }; then
  echo "credential missing: set GH_RUNNER_TOKEN=<PAT>  OR  APP_ID= + APP_INSTALLATION_ID= + APP_PRIVATE_KEY_FILE=<key.pem>" >&2
  exit 1
fi
[ -n "$APP_PRIVATE_KEY_FILE" ] && [ ! -r "$APP_PRIVATE_KEY_FILE" ] && { echo "APP_PRIVATE_KEY_FILE not readable: $APP_PRIVATE_KEY_FILE" >&2; exit 1; }
: "${ORG_URL:?set ORG_URL=https://github.com/<org>  (or a repo URL)}"
SCALE_SET="${SCALE_SET:-cvm-launcher}"
NS="${NS:-arc-runners}"
SYS_NS="${SYS_NS:-arc-systems}"
SECRET="${SECRET:-runner-github}"
MODE="${MODE:-helm}"                  # helm | template (template = Rancher-proxy clusters)
CHART_VER="${CHART_VER:-0.14.2}"
MIN_RUNNERS="${MIN_RUNNERS:-0}"
MAX_RUNNERS="${MAX_RUNNERS:-2}"
RUNNER_IMAGE="${RUNNER_IMAGE:-}"      # optional container image override
SA="${SA:-}"                          # optional template.spec.serviceAccountName
RENAME_FROM="${RENAME_FROM:-}"        # optional old scale-set name to purge first
RUNNER_GROUP="${RUNNER_GROUP:-}"      # optional org runner group (must exist first)
RUNNER_SCALE_SET_NAME="${RUNNER_SCALE_SET_NAME:-}"  # optional runs-on label override (default: $SCALE_SET)
VALUES_FILE="${VALUES_FILE:-}"        # optional helm values overlay (runner pod spec:
                                      # nodeSelector/tolerations/device mounts — e.g.
                                      # place azure-cvm runners on the confidential pool)
CTX_ARG=(); [ -n "${KUBE_CONTEXT:-}" ] && CTX_ARG=(--kube-context "$KUBE_CONTEXT")
KCTX_ARG=(); [ -n "${KUBE_CONTEXT:-}" ] && KCTX_ARG=(--context "$KUBE_CONTEXT")
CHART_SS=oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
CHART_CTL=oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller
WORK="$(mktemp -d)"

k(){ kubectl "${KCTX_ARG[@]}" "$@"; }
h(){ helm "${CTX_ARG[@]}" "$@"; }
ensure_ns(){ k create ns "$1" --dry-run=client -o yaml | k apply -f - >/dev/null; }

ensure_controller(){
  if k -n "$SYS_NS" get deploy arc-gha-rs-controller >/dev/null 2>&1; then
    echo "controller: present"; return
  fi
  echo "controller: installing ($MODE)"
  ensure_ns "$SYS_NS"
  if [ "$MODE" = template ]; then
    h pull "$CHART_CTL" --version "$CHART_VER" --untar -d "$WORK" >/dev/null
    k apply --server-side -f "$WORK"/gha-runner-scale-set-controller/crds/ >/dev/null
    h template arc "$WORK"/gha-runner-scale-set-controller -n "$SYS_NS" | k apply --server-side -f - >/dev/null
  else
    h install arc "$CHART_CTL" --version "$CHART_VER" -n "$SYS_NS" --wait
  fi
  k -n "$SYS_NS" rollout status deploy/arc-gha-rs-controller --timeout=180s
}

upsert_secret(){
  ensure_ns "$NS"
  if [ -n "$APP_ID" ]; then
    k create secret generic "$SECRET" -n "$NS" \
      --from-literal=github_app_id="$APP_ID" \
      --from-literal=github_app_installation_id="$APP_INSTALLATION_ID" \
      --from-file=github_app_private_key="$APP_PRIVATE_KEY_FILE" \
      --dry-run=client -o yaml | k apply -f - >/dev/null
    echo "secret: $NS/$SECRET upserted (GitHub App by reference — not in helm values)"
  else
    k create secret generic "$SECRET" -n "$NS" \
      --from-literal=github_token="$GH_RUNNER_TOKEN" \
      --dry-run=client -o yaml | k apply -f - >/dev/null
    echo "secret: $NS/$SECRET upserted (token by reference — not in helm values)"
  fi
}

purge(){  # $1 = scale-set name to remove cleanly
  local n="$1"; [ -z "$n" ] && return 0
  echo "purge: $n (clean cycle to avoid the stale-listener crashloop)"
  h uninstall "$n" -n "$NS" 2>/dev/null || true
  k -n "$NS" delete autoscalingrunnerset "$n" --ignore-not-found >/dev/null 2>&1 || true
  for ers in $(k -n "$NS" get ephemeralrunnerset -o name 2>/dev/null | grep "/$n-" || true); do
    k -n "$NS" delete "$ers" --ignore-not-found >/dev/null 2>&1 || true
  done
  for l in $(k -n "$SYS_NS" get autoscalinglistener -o name 2>/dev/null | grep "/$n-" || true); do
    k -n "$SYS_NS" delete "$l" --ignore-not-found >/dev/null 2>&1 || true
  done
  k -n "$SYS_NS" rollout restart deploy/arc-gha-rs-controller >/dev/null 2>&1 || true
  k -n "$SYS_NS" rollout status deploy/arc-gha-rs-controller --timeout=120s >/dev/null 2>&1 || true
}

install(){
  local sets=(
    --set githubConfigUrl="$ORG_URL"
    --set githubConfigSecret="$SECRET"
    --set minRunners="$MIN_RUNNERS" --set maxRunners="$MAX_RUNNERS"
  )
  [ -n "$RUNNER_IMAGE" ] && sets+=(--set "template.spec.containers[0].name=runner" --set "template.spec.containers[0].image=$RUNNER_IMAGE")
  [ -n "$SA" ] && sets+=(--set "template.spec.serviceAccountName=$SA")
  [ -n "$RUNNER_GROUP" ] && sets+=(--set runnerGroup="$RUNNER_GROUP")
  [ -n "$RUNNER_SCALE_SET_NAME" ] && sets+=(--set runnerScaleSetName="$RUNNER_SCALE_SET_NAME")
  [ -n "$VALUES_FILE" ] && sets+=(-f "$VALUES_FILE")   # runner pod overlay (last -> wins)
  if [ "$MODE" = template ]; then
    h template "$SCALE_SET" "$CHART_SS" --version "$CHART_VER" -n "$NS" \
      "${sets[@]}" \
      --set controllerServiceAccount.name=arc-gha-rs-controller \
      --set controllerServiceAccount.namespace="$SYS_NS" \
      | k apply --server-side -f -
  elif h status "$SCALE_SET" -n "$NS" >/dev/null 2>&1; then
    h upgrade "$SCALE_SET" "$CHART_SS" --version "$CHART_VER" -n "$NS" "${sets[@]}"
  else
    h install "$SCALE_SET" "$CHART_SS" --version "$CHART_VER" -n "$NS" "${sets[@]}"
  fi
}

verify(){
  echo "verify: waiting for the listener to reach 'Getting next message'..."
  local pod
  for _ in $(seq 1 20); do
    sleep 6
    pod=$(k -n "$SYS_NS" get pods -o name 2>/dev/null | grep "$SCALE_SET-.*-listener" | head -1 || true)
    [ -z "$pod" ] && continue
    if k -n "$SYS_NS" logs "$pod" --tail=20 2>/dev/null | grep -q "Getting next message"; then
      echo "listener: healthy ($pod)"; return 0
    fi
  done
  echo "WARN: listener not healthy yet — inspect: kubectl -n $SYS_NS logs <listener>"
}

echo "== register '$SCALE_SET' -> $ORG_URL  (mode=$MODE ns=$NS) =="
ensure_controller
upsert_secret
[ -n "$RENAME_FROM" ] && purge "$RENAME_FROM"
install
verify
echo "done. runs-on: ${RUNNER_SCALE_SET_NAME:-$SCALE_SET}   (repos must be PRIVATE — see OPEN-SOURCE.md)"
