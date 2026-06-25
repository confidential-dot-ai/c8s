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
├── deploy-plan.md       bare-metal + GCP + Azure plan; Model B; Nix vs Bazel
├── org-setup.md         org-wide rollout (GitHub App, runner group, install)
├── register.sh          one-command repo/org scale-set registration
├── runner-image/
│   ├── Dockerfile.gcp   runner image (amd64): gcloud+kubectl+helm+kettle+ccvm
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

## Status

GCP path live-run verified (real SEV Confidential GKE in conf-500518; see
`e2e/README.md`). Azure + bare-metal are planned (`deploy-plan.md`). Runner
orchestration (ARC, ephemeral, push-triggered) proven end-to-end.
