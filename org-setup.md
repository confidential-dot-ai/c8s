# Deploying the confidential runner ORG-WIDE

You are **not** deploying to a repo. Org-wide self-hosted runners register to the
**org**; repos opt in with a `runs-on:` label scoped by a runner group. The only
repo involved is an infra repo (`conf` or a dedicated `confidential-ci`) that
holds these values — runners don't attach to it.

## Prerequisites (your decisions/actions)

1. **The org** that owns the confidential stack repos (attestation-rs, C8s, …).
2. **A GitHub App on that org** (org registration needs org admin; a `gh` token
   with only `repo`+`read:org` is not enough). App route is recommended over a
   PAT-with-`admin:org`.
3. **A cluster to host runners** — reuse the existing kind cluster to validate
   org registration now; move ARC to a cloud cluster for production.

## Step 1 — GitHub App (one-time, org admin)

Org → Settings → Developer settings → GitHub Apps → New GitHub App:
- Permissions → Repository: `Actions: Read`, `Administration: Read & write`,
  `Metadata: Read`. Organization: `Self-hosted runners: Read & write`.
- Create → note the **App ID** → generate a **private key** (.pem).
- Install the App on the org (All repositories, or selected) → note the
  **Installation ID** (from the install URL or the API).

## Step 2 — runner group (scopes which repos can use it)

Org → Settings → Actions → Runner groups → New group `confidential` → choose the
repos allowed to use it (e.g. attestation-rs, C8s). The scale set joins it via
`runnerGroup: confidential` in `values-org.yaml`.

## Step 3 — install the org-scoped scale set (ARC controller already installed)

```bash
helm install confidential-e2e \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n arc-runners --create-namespace \
  --set githubConfigUrl="https://github.com/<ORG>" \
  --set githubConfigSecret.github_app_id="<APP_ID>" \
  --set githubConfigSecret.github_app_installation_id="<INSTALL_ID>" \
  --set-file githubConfigSecret.github_app_private_key="<app-key.pem>" \
  --set runnerGroup="confidential" \
  -f runner-image/values-org.yaml
```

Verify: `kubectl -n arc-runners get autoscalingrunnerset` and the org
Settings → Actions → Runners shows the scale set online.

## Step 4 — repos use it

Any allowed org repo adds `.github/workflows/e2e-confidential.yml` with
`runs-on: confidential-e2e`. On push it spins up an ephemeral Confidential GKE
cluster (Model B), runs the E2E, tears it down.

## Where things live

- **Registration target:** the org (`githubConfigUrl`).
- **Runner deploy config:** this repo (`slices/runner/`) — the infra/ops repo.
- **Consumers:** the stack repos, via `runs-on:` + the workflow.
- `b0xtch/confidential-runner` was the repo-level proof only — retire it.

## Production note

For prod, run ARC on a cloud cluster (e.g. a small GKE cluster) rather than
local kind, and bind the runner's K8s SA to the GCP SA via Workload Identity
Federation (see `e2e/README.md`) so Model-B provisioning needs no static keys.

## Concrete: confidential-dot-ai rollout (2026-07-14)

Verified constraints: b0xtch is org **member** (all `orgs/…/actions/runners`
endpoints → 403 — registration needs org admin or the runners fine-grained
role); org plan is **enterprise** (custom runner groups available). So the only
**org-owner** action is minting the App (~3 min):

1. Owner: Org → Settings → Developer settings → GitHub Apps → **New GitHub App**
   — name `confidential-ci-runners`, homepage
   `https://github.com/confidential-dot-ai/confidential-ci`, **Webhook: Active
   unchecked**, Organization permissions → **Self-hosted runners: Read & write**
   (nothing else; Metadata:Read is implied). Create → note **App ID** →
   **Generate a private key** (.pem downloads) → sidebar **Install App** →
   confidential-dot-ai → **All repositories**. Hand off App ID + .pem
   (installation ID is discoverable from the .pem via the API).
2. Us, with the .pem (no owner needed): look up the installation ID, create the
   `confidential` runner group via the API, then register on the metal cluster —
   **the cifrai scale set stays** (test-org regression harness); the release
   name differs but the `runs-on` label is identical in both orgs:

```bash
APP_ID=<id> APP_INSTALLATION_ID=<inst> APP_PRIVATE_KEY_FILE=<key.pem> \
  ORG_URL=https://github.com/confidential-dot-ai SCALE_SET=confidential-bm-conf \
  RUNNER_SCALE_SET_NAME=confidential-bm RUNNER_GROUP=confidential \
  MODE=template SA=bm-e2e KUBECONFIG=~/dev/conf/github-runner.yaml ./register.sh
```

3. Smoke: a private confidential-dot-ai repo (e.g. `confidential-ci` itself)
   runs a `runs-on: confidential-bm` job. Repos must be **private** and in the
   runner group's allow-list.
