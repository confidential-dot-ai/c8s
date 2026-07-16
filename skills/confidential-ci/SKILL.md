---
name: confidential-ci
description: |
  Use this skill whenever the task involves confidential CI: self-hosted GitHub
  Actions runners running in or provisioning TEEs (confidential VMs), attested
  build pipelines, or confidential end-to-end tests. Triggers include: setting up
  self-hosted runners for a confidential stack, GitHub Actions Runner Controller
  (ARC) on Kubernetes, runner scale sets and runner registration, GKE Confidential
  Nodes (SEV-SNP / TDX) in CI, ephemeral confidential clusters per test run,
  Kettle attested builds with SLSA provenance, supply-chain-sensitive builds that
  must produce measurable artifacts, jobs stuck "Waiting for a runner", or any
  question about why GitHub-hosted runners cannot run TEE workloads. If the user
  mentions "confidential CI", "confidential runners", "attested build", or
  "runs-on: confidential-*", use this skill.
---

# Confidential CI — self-hosted GitHub Actions runners for TEE workloads

## Overview

GitHub-hosted runners have no TEE access: they cannot attest hardware, launch
confidential VMs, or provision Confidential GKE nodes. Any CI that tests a
confidential stack (spin up a confidential cluster, attest it, run E2E, tear it
down) or produces attested builds therefore needs **self-hosted runners** with
access to confidential-computing machinery. This skill covers deploying those
runners with Actions Runner Controller (ARC) on Kubernetes, baking a runner
image with the provisioning + attestation toolchain, and the two workflow
shapes that run on them: an attested build (Kettle) and a confidential E2E
(ephemeral Confidential GKE cluster per run).

## How it works

Two placement models decide where the TEE lives. Use both, per target:

- **Model A — runner ON confidential nodes.** Runner pods are scheduled onto
  confidential VMs / bare-metal SEV-SNP/TDX hosts. The job attests local
  hardware and launches CVMs directly. Required for bare metal (no cloud API to
  provision) and for tests that must attest the runner's own hardware/GPU.
- **Model B — runner PROVISIONS an ephemeral confidential cluster.** Runner
  pods run on a cheap normal pool but hold scoped cloud credentials; each job
  creates a fresh Confidential GKE (or AKS-CVM) cluster, tests it, and destroys
  it. This is the industry-standard confidential-K8s E2E pattern: no long-lived
  confidential infra to babysit, clean cost control, per-run isolation.

Recommendation: **Model B for GCP/Azure, Model A for bare metal.** The runner
scale set is identical either way — only pod placement and the job's
provisioning step differ.

The moving parts:

1. **ARC controller** (`gha-runner-scale-set-controller` Helm chart) — once per
   host cluster.
2. **Runner scale set** (`gha-runner-scale-set` chart) — registered to a repo
   (PAT, quick proof) or to the **org** (GitHub App + runner group, production).
   Ephemeral pods, `minRunners: 0`, one fresh pod per job — the K8s analog of
   "fresh CVM per build, no cross-build contamination".
3. **Custom runner image** — bakes gcloud + `gke-gcloud-auth-plugin`, kubectl,
   helm, kettle, ccvm so jobs need no per-run installs.
4. **Workflows** in the consuming (private!) repos target the scale set via
   `runs-on: <scale-set-name>`.

## Quick agent flow

1. Confirm the consuming repo is **private** (see Critical guidelines #1).
2. Install the ARC controller on the host cluster (once).
3. Build and push the runner image from `runner-image/Dockerfile.gcp`.
4. Register a scale set: repo-level via `register.sh` (PAT) to validate, then
   org-level via GitHub App + runner group for production.
5. Verify: `kubectl -n arc-runners get autoscalingrunnerset` and the runner
   appears under GitHub Settings → Actions → Runners.
6. Copy `workflows/e2e-confidential.yml` (or `confidential-build.yml`) into the
   stack repo's `.github/workflows/`, push, and watch a runner pod spin up.

## Critical guidelines

- **#1 gotcha: PUBLIC repos cannot use these runners.** GitHub policy blocks
  self-hosted runners for public repositories by default (anyone can fork and
  open a PR that executes arbitrary code on your infrastructure). The symptom
  is silent: jobs sit forever at "Waiting for a runner to pick up this job" —
  no error, no log. The repo consuming the runners **must be private**. Check
  repo visibility before debugging anything else.
- **Registration tokens are short-lived and sensitive — never commit them.**
  PATs, GitHub App private keys (.pem), and runner registration tokens grant
  the ability to register machines that execute your org's code. Pass them via
  environment variables or `--set-file` at install time only. Prefer a GitHub
  App over a PAT for org scope (a PAT needs `admin:org`; the App needs only
  narrow permissions and its key can be rotated).
- **Never invent gcloud/kubectl/gh/helm flags.** Confidential-node flags vary
  by gcloud version, GKE version, and region (Confidential GKE Nodes with
  SEV-SNP/TDX are GA on GKE >= 1.32.2; confidential H100 on A3 needs >= 1.32.2
  with manual driver install or >= 1.33.3 for auto). Verify a flag exists
  (`gcloud container clusters create --help`) before running it.
- **Always-run teardown.** Every provisioning step must be paired with a
  teardown step under `if: always()` plus a hard `timeout-minutes` — a failed
  E2E must never leak a confidential cluster (cost + attack surface).
- **No long-lived cloud keys.** Bind the runner's Kubernetes ServiceAccount to
  a cloud service account via Workload Identity Federation (GCP) / Managed
  Identity (Azure), scoped to a dedicated CI project. Bare metal: node-local,
  no cloud creds at all.
- **`runs-on` = the Helm release name.** The scale set's label is its install
  name (`helm install confidential-e2e-gcp …` → `runs-on: confidential-e2e-gcp`).
  A mismatch also manifests as jobs queueing forever.
- **Match chart versions.** The `gha-runner-scale-set` chart version (e.g.
  `0.14.2`) must match the installed controller version.

## Core workflows

### 1. Install the ARC controller (once per host cluster)

```bash
helm install arc \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller \
  -n arc-systems --create-namespace
```

### 2. Build and push the runner image

`runner-image/Dockerfile.gcp` starts from `ghcr.io/actions/actions-runner:latest`
and bakes: kubectl, helm, the Google Cloud SDK **plus `gke-gcloud-auth-plugin`**
(without it, `kubectl` against GKE fails), kettle (attested builds), and ccvm
(TEE verification). It sets `USE_GKE_GCLOUD_AUTH_PLUGIN=True`.

```bash
docker build --platform linux/amd64 -f runner-image/Dockerfile.gcp \
  -t REGISTRY/confidential-runner-gcp:latest .
docker push REGISTRY/confidential-runner-gcp:latest
```

Build for the cloud target (`linux/amd64`) even from an ARM laptop. Pin tool
releases in production — the sample Dockerfile installs ccvm best-effort from
`latest`.

### 3a. Register a repo-level scale set (quick proof — PAT)

`register.sh` is the one step that touches your GitHub account, kept separate
and explicit:

```bash
GITHUB_CONFIG_URL=https://github.com/YOUR_ORG/YOUR_REPO \
GITHUB_PAT=ghp_xxx \
./register.sh
```

It runs `helm install confidential-builders …gha-runner-scale-set` with
`minRunners=0 maxRunners=3` and `containerMode.type=kubernetes`. Workflows then
use `runs-on: confidential-builders`. A classic PAT with `repo` scope suffices
for repo-level only.

### 3b. Register org-wide (production — GitHub App + runner group)

Org registration needs org admin; a token with `repo`+`read:org` is not enough.
One-time setup (see `org-setup.md`):

1. **GitHub App** on the org — permissions: Repository `Actions: Read`,
   `Administration: Read & write`, `Metadata: Read`; Organization
   `Self-hosted runners: Read & write`. Note the App ID, generate a private
   key, install on the org, note the Installation ID.
2. **Runner group** — Org → Settings → Actions → Runner groups → new group
   `confidential`, allow only the stack repos. This scopes which repos may
   target the runners.
3. Install the scale set against the **org URL**:

```bash
helm install confidential-e2e \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n arc-runners --create-namespace \
  --set githubConfigUrl="https://github.com/YOUR_ORG" \
  --set githubConfigSecret.github_app_id="APP_ID" \
  --set githubConfigSecret.github_app_installation_id="INSTALL_ID" \
  --set-file githubConfigSecret.github_app_private_key="app-key.pem" \
  --set runnerGroup="confidential" \
  -f runner-image/values-org.yaml
```

Verify: `kubectl -n arc-runners get autoscalingrunnerset` and the org's
Settings → Actions → Runners page shows the scale set online.

### 4. GCP bootstrap for Model B (once, ~15 min)

```bash
PROJECT=YOUR_CI_PROJECT; REGION=us-central1
gcloud config set project "$PROJECT"
gcloud services enable container.googleapis.com iamcredentials.googleapis.com

# GCP service account the runner assumes, scoped to THIS project only
gcloud iam service-accounts create arc-gcp-e2e
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:arc-gcp-e2e@$PROJECT.iam.gserviceaccount.com" \
  --role="roles/container.admin"

# Then bind the arc-runners/arc-gcp-e2e K8s SA to this GCP SA via
# Workload Identity Federation (standard GKE WIF binding) — no static keys.
```

### 5. The confidential E2E (Model B, per push)

`workflows/e2e-confidential.yml` runs on `runs-on: confidential-e2e-gcp` with a
`concurrency` group (one confidential cluster per ref at a time) and
`timeout-minutes: 60`:

provision → run → collect (`if: always()`) → teardown (`if: always()`).

- `e2e/provision-gcp.sh` creates the ephemeral cluster:

```bash
gcloud container clusters create "conf-e2e-${GITHUB_RUN_ID}" \
  --project "$GCP_PROJECT" --location "$LOCATION" \
  --machine-type n2d-standard-4 --num-nodes 1 \
  --enable-confidential-nodes \
  --confidential-node-type sev_snp \
  --enable-ip-alias --no-enable-basic-auth \
  --labels "e2e=confidential,run=${GITHUB_RUN_ID}" --quiet
```

  `CONF_TYPE` selects the TEE: `sev_snp`/`tdx` add
  `--confidential-node-type`; legacy `sev` uses only
  `--enable-confidential-nodes` and has the **broadest zone capacity** — fall
  back to it when SEV-SNP stocks out. Machine types: SEV/SEV-SNP → n2d/c3d,
  TDX → c3, GPU → a3-highgpu-1g. The script records the cluster name in
  `/tmp/e2e-cluster-name` so teardown finds it even if later steps fail.

- `e2e/run.sh` is the shared, platform-agnostic body. It performs a **real**
  confidentiality check — never trust the label:

```bash
gcloud container clusters describe "$CL" --project "$GCP_PROJECT" \
  --location "$LOCATION" --format='value(confidentialNodes.enabled)'
# must print True, else FAIL
```

  then waits for nodes Ready, hooks into `attestation-cli`/ccvm for an in-guest
  hardware quote, and runs your stack's deploy + assertions via the
  `STACK_DEPLOY` env hook.

- `e2e/teardown-gcp.sh` deletes the cluster unconditionally.

### 6. The attested build (Kettle)

`workflows/confidential-build.yml` runs on `runs-on: confidential-builders`:
checkout → install Rust + Kettle → `kettle build <project>` (emits SLSA
provenance at `<project>/kettle-build/provenance.json`) → on TEE-capable
runners only (`if: ${{ vars.HAVE_TEE == 'true' }}`) `kettle attest` +
`kettle verify`, which checks the hardware signature, the allow-listed launch
measurement, and the provenance digest bound in `report_data`. Off-TEE the
attest step is skipped — no quote is possible, and faking one defeats the
point. The build digest is extracted from the provenance and handed to the
deploy allow-list.

## Configuration reference

Scale-set values (`runner-image/values-gcp.yaml` / `values-org.yaml`):

| Key | Meaning |
|---|---|
| `githubConfigUrl` | Repo URL (repo-level) or `https://github.com/YOUR_ORG` (org-level) |
| `githubConfigSecret.github_token` | Classic PAT, repo-level only |
| `githubConfigSecret.github_app_*` | App ID / Installation ID / private key, org-level |
| `runnerGroup` | Org runner group that scopes which repos may use the runners |
| `minRunners: 0` | Ephemeral: no idle runners, pod per job |
| `maxRunners` | Cap concurrent confidential jobs (3–5 typical) |
| `template.spec.serviceAccountName` | K8s SA federated to the cloud SA (WIF) |
| `template.spec.containers[0].image` | Your pushed runner image |

Runner-pod / script environment:

| Variable | Meaning |
|---|---|
| `GCP_PROJECT` | Dedicated CI project (blast-radius boundary) |
| `GCP_REGION` / `GCP_LOCATION` | Region = HA (3 nodes); zone = cheap single-node test |
| `CONF_TYPE` | `sev` (broadest capacity) \| `sev_snp` \| `tdx` |
| `MACHINE` | `n2d-standard-4` default; must match `CONF_TYPE` family |
| `GKE_VERSION` | Optional pin; confidential nodes need >= 1.32.2 |
| `E2E_CLUSTER` | Override cluster name (default `conf-e2e-$GITHUB_RUN_ID`) |
| `STACK_DEPLOY` | Path to the stack-under-test's deploy+assert script |

## Troubleshooting

- **Job stuck "Waiting for a runner to pick up this job".** In order: (1) is
  the repo public? Make it private — this is the #1 cause and produces no
  error. (2) Does `runs-on` exactly match the Helm release name? (3) Is the
  repo allowed in the runner group? (4) Is the scale set online
  (`kubectl -n arc-runners get autoscalingrunnerset`, GitHub runners page)?
- **`ZONE ... does not have enough resources` / silent MIG retry loop.**
  SEV-SNP zone stockout is normal. Retry another zone or fall back to
  `CONF_TYPE=sev`. Verified live: SEV-SNP N2D stocked out in one us-central1
  zone while plain SEV came up fine in another.
- **Teardown fails with "incompatible operation".** A mid-create cluster
  cannot be deleted and the create op cannot be cancelled — teardown must
  wait-and-retry until the create settles. Do not mask delete failures with
  `|| true` in production, or you will leak clusters.
- **`kubectl` auth errors against the new cluster.** The
  `gke-gcloud-auth-plugin` is missing. It is baked into the runner image; for
  local runs: `gcloud components install gke-gcloud-auth-plugin`.
- **Org registration rejected.** You need org admin via a GitHub App (or a PAT
  with `admin:org`); `repo`+`read:org` scopes are insufficient.
- **Helm install fails or runners crash-loop.** Check the scale-set chart
  version matches the controller, and that the image was built for
  `linux/amd64`.
- **`kettle attest` fails.** The runner is not on a TEE node — expected for
  Model B pool runners. Gate attest/verify behind `vars.HAVE_TEE` and run them
  only on Model A (confidential-node) runners.

## Additional resources

- `README.md`, `deploy-plan.md` (multi-platform plan, Model A/B decision, Nix
  vs Bazel), `org-setup.md` (org rollout), `e2e/README.md` (GCP bootstrap +
  verified live-run notes) in the confidential-ci repo.
- ARC docs: https://github.com/actions/actions-runner-controller
- Confidential GKE Nodes: https://cloud.google.com/kubernetes-engine/docs/how-to/confidential-gke-nodes
- Kettle (attested builds, SLSA provenance): https://github.com/lunal-dev/kettle
- GitHub self-hosted runner security model:
  https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners
