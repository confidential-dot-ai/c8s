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
