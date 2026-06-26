# confidential-ci

Self-hosted, **confidential-computing** GitHub Actions runners + the confidential
E2E pipeline they run. This folder is self-contained — lift it into its own repo
(`confidential-ci`) and it's the single source of truth for the CI infra.

It exists because GitHub-hosted runners have no TEE access, so confidential-stack
tests (spin up a confidential K8s cluster, attest it, test it) can't run on them.
These runners do. See `deploy-plan.md` for the multi-platform plan and the
Nix-over-Bazel decision; `org-setup.md` for org-wide rollout.

## What you deploy (it's infra, not a repo)

1. **ARC controller** on a Kubernetes cluster (`helm install … gha-runner-scale-set-controller`).
2. A **runner scale set** registered to the **org** (`githubConfigUrl=https://github.com/<ORG>`),
   authed by a **GitHub App**, scoped by a **runner group**.
3. A **runner image** (`runner-image/Dockerfile.gcp`) baking the toolchain
   (gcloud, kubectl, helm, kettle, ccvm) so jobs need no per-run installs.
Repos then opt in with `runs-on: confidential-e2e-gcp`.

## Layout

```
confidential-ci/
├── README.md            you are here
├── config.env.example   all per-account knobs (project/region/registry/org) in one place
├── RUNNER-MATRIX.md     which CI jobs run on confidential; arm/macOS scoping
├── OPEN-SOURCE.md       fork/public-repo safety model for OSS repos
├── MONITORING.md        ops/monitoring commands + gotchas + teardown
├── deploy-plan.md       bare-metal + GCP + Azure plan; Model B; Nix vs Bazel
├── org-setup.md         org-wide rollout (GitHub App, runner group, install)
├── host/                always-on host that runs ARC (GKE; NOT confidential)
│   ├── create-host-cluster.sh   small zonal GKE cluster (e2-medium, autoscaling)
│   ├── install-arc.sh           ARC controller + org-wide scale set
│   └── wire-wif.sh              Workload Identity → keyless GCP (no static keys)
├── register.sh          one-command repo/org scale-set registration
├── runner-image/
│   ├── Dockerfile.gcp   runner image (amd64): build-essential+gcloud+kubectl+helm+kettle+ccvm
│   ├── cloudbuild.yaml  native-amd64 build → Artifact Registry
│   ├── values-gcp.yaml  scale set values (repo/proj demo)
│   └── values-org.yaml  scale set values (ORG-scoped, GitHub App, runner group)
├── e2e/                 the confidential E2E body (Model B: ephemeral cluster/run)
│   ├── provision-gcp.sh  create ephemeral Confidential GKE cluster
│   ├── run.sh            assert confidential + attest + deploy stack
│   ├── collect.sh        gather logs/evidence
│   ├── teardown-gcp.sh   delete cluster (always)
│   └── README.md         GCP bootstrap + verified live-run notes
├── workflows/           copy into a stack repo's .github/workflows/
│   ├── e2e-confidential.yml   spin up → attest → teardown (matrix: gcp[/azure/baremetal])
│   └── confidential-build.yml kettle attested build
└── examples/model-server/     sample project the build/e2e use
```

## Always-on host (GKE)

The runners need a persistent cluster to live on (a laptop kind cluster only
works while it's awake). The host is a small **non-confidential** GKE cluster —
it just runs ARC; the confidential clusters are the ephemeral ones the runners
provision per E2E (Model B).

```bash
GCP_PROJECT=conf-500518 bash host/create-host-cluster.sh        # ~1x e2-medium, zonal
ORG_URL=https://github.com/<org> GH_RUNNER_TOKEN="$(gh auth token)" bash host/install-arc.sh
bash host/wire-wif.sh                                           # keyless GCP creds (Workload Identity)
# build the gcloud-equipped runner image (native amd64) and point the scale set at it:
gcloud builds submit runner-image --config runner-image/cloudbuild.yaml --project conf-500518
helm upgrade confidential-e2e oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n arc-runners --reuse-values \
  --set template.spec.containers[0].name=runner \
  --set template.spec.containers[0].image=us-central1-docker.pkg.dev/conf-500518/confidential-ci/confidential-runner-gcp:latest
```

`wire-wif.sh` binds the runner's K8s SA (`arc-e2e`) to a GCP SA with
`container.admin`, so Model-B provisioning needs **no static keys**. The runner
image carries gcloud/kubectl/helm/kettle/ccvm so jobs run the e2e scripts directly.

## Deploy into another GCP account (e.g. the company's main project)

Nothing is fundamentally tied to the demo project — the host scripts read env
vars (defaulting to the demo), `cloudbuild.yaml` derives its image path from the
build's own `$PROJECT_ID` + substitutions, and the runner image is set per
account. To retarget:

```bash
cp config.env.example config.env        # edit GCP_PROJECT/ZONE/REGION/ORG_URL/...
set -a; source config.env; set +a

# 1. AR repo + runner image in the target project
gcloud artifacts repositories create "$AR_REPO" --repository-format=docker \
  --location="$GCP_REGION" --project "$GCP_PROJECT"
gcloud builds submit runner-image --config runner-image/cloudbuild.yaml \
  --project "$GCP_PROJECT" \
  --substitutions=_REGION=$GCP_REGION,_REPO=$AR_REPO,_IMAGE=$IMAGE,_TAG=$IMAGE_TAG

# 2. host cluster + ARC + WIF (all read config.env)
bash host/create-host-cluster.sh
ORG_URL="$ORG_URL" GH_RUNNER_TOKEN="$(gh auth token)" bash host/install-arc.sh
bash host/wire-wif.sh

# 3. point the scale set at the new image
helm upgrade confidential-e2e oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n arc-runners --reuse-values \
  --set template.spec.containers[0].image="$RUNNER_IMAGE"
```

For org-wide prod, swap the PAT for a **GitHub App** (see `org-setup.md` /
`values-org.yaml`). The only non-negotiable: the repos that use these runners must
be **private/internal** (`OPEN-SOURCE.md`). Terraform-ising this (cluster + AR +
IAM + WIF) is the natural next step for a repeatable company rollout.

## Quickstart (org-wide)

```bash
# 1. controller (once per cluster)
helm install arc oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller \
  -n arc-systems --create-namespace

# 2. build + push the runner image
docker build --platform linux/amd64 -f runner-image/Dockerfile.gcp -t REGISTRY/confidential-runner-gcp:latest .
docker push REGISTRY/confidential-runner-gcp:latest

# 3. org-scoped scale set (GitHub App creds) — see org-setup.md
helm install confidential-e2e oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n arc-runners --create-namespace \
  --set githubConfigUrl="https://github.com/<ORG>" \
  --set githubConfigSecret.github_app_id=… --set githubConfigSecret.github_app_installation_id=… \
  --set-file githubConfigSecret.github_app_private_key=app-key.pem \
  --set runnerGroup=confidential -f runner-image/values-org.yaml

# 4. stack repos add workflows/e2e-confidential.yml and push
```

## How the workflow finds the e2e scripts

Two options: vendor `e2e/` into each stack repo, or (recommended) **bake `e2e/`
into the runner image** so `provision-gcp.sh` etc. are on PATH and the workflow
calls them directly. The workflows here assume repo-root-relative `./e2e/…`;
adjust to taste when you split this into its own repo.

## Status — proven end-to-end

- **Full real CI matrix, green:** attestation-rs `check`, `test`, `audit`, and
  `release-build · x86_64-linux` run on the GKE-hosted confidential runner;
  `release-build` for arm64-linux + macOS and `docker-build` run on GitHub-hosted
  runners — all green on a live push. Per-job routing in `RUNNER-MATRIX.md`.
- **Eligibility (don't skip):** the CI repo must be **private/internal** — GitHub
  silently refuses self-hosted runners on public repos (`assigned job=0`, runner
  idle). This was the real cause of "runs queued, nothing picked up." See
  `MONITORING.md`.
- **Dispatch latency (optional):** default `minRunners: 0` (scale to zero, no idle
  cost). Once eligibility is correct, scale-from-zero works; set `minRunners: 1`
  only if you want instant pickup.
- **Keyless:** runner pods use Workload Identity (`arc-e2e` KSA → GCP SA with
  `container.admin`) — verified able to provision/list Confidential GKE clusters
  with no static keys.
- **Model-B GCP path verified:** ephemeral SEV Confidential GKE cluster created,
  asserted confidential, torn down (see `e2e/README.md`).
- **Org-wide:** registered to a GitHub org; any non-fork **private** org repo
  opts in via `runs-on`.

### Coverage & caveats
- Which jobs run where (and why macOS is verify-only / arm has no confidential
  VM): see **`RUNNER-MATRIX.md`**.
- Ops, monitoring, and the gotchas (forks/detached-forks can't use self-hosted
  runners, version pinning, AR read, the YAML colon trap): see **`MONITORING.md`**.
- Azure + bare-metal: planned (`deploy-plan.md`).
