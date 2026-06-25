# Confidential E2E runners — v1 GCP (Model B)

Industry-standard confidential-K8s E2E: on push, a self-hosted runner spins up
an **ephemeral Confidential GKE cluster**, attests it, runs the E2E, and tears
it down. The runner pods run on a normal pool; the cluster they create is the
confidential one (so no long-lived confidential infra to babysit).

See `../deploy-plan.md` for the full multi-platform plan and the Nix decision.

## Files

| File | Role |
|---|---|
| `provision-gcp.sh` | create the ephemeral Confidential GKE cluster |
| `run.sh` | platform-agnostic E2E body (assert confidential + attest + stack) |
| `collect.sh` | gather logs/evidence (`if: always()`) |
| `teardown-gcp.sh` | delete the cluster (`if: always()` — never leak it) |
| `e2e-confidential.yml` | the workflow (copy to the stack repo's `.github/workflows/`) |
| `../runner-image/Dockerfile.gcp` | runner image: gcloud + kubectl + helm + kettle + ccvm |
| `../runner-image/values-gcp.yaml` | ARC scale set (WIF service account, image, env) |

## One-time GCP bootstrap (operator, ~15 min)

Decisions only the team can make: the **CI project** and **region**. Then:

```bash
PROJECT=your-ci-project; REGION=us-central1
gcloud config set project "$PROJECT"
gcloud services enable container.googleapis.com iamcredentials.googleapis.com

# 1) build + push the runner image (amd64 cloud target)
docker build --platform linux/amd64 -f ../runner-image/Dockerfile.gcp -t REGISTRY/confidential-runner-gcp:latest ..
docker push REGISTRY/confidential-runner-gcp:latest

# 2) GCP service account the runner assumes (scoped to THIS project)
gcloud iam service-accounts create arc-gcp-e2e
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:arc-gcp-e2e@$PROJECT.iam.gserviceaccount.com" \
  --role="roles/container.admin"

# 3) Workload Identity Federation: bind the K8s SA -> GCP SA (no static keys)
#    (run on the cluster that hosts ARC; standard WIF binding for the
#     arc-runners/arc-gcp-e2e KSA — see GKE Workload Identity docs)
```

## Install the runner scale set

```bash
helm install confidential-e2e-gcp \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n arc-runners --create-namespace \
  --set githubConfigUrl="https://github.com/<org>" \
  --set githubConfigSecret.github_token="$(gh auth token)" \
  -f ../runner-image/values-gcp.yaml
```

Then copy `e2e-confidential.yml` into the stack repo and push. A runner pod
picks up the job, provisions a Confidential GKE cluster, runs `run.sh`, and
tears it down.

## Status / boundary

**Live-run verified (2026-06-25, project conf-500518):** a real SEV Confidential
GKE cluster came up in us-central1-b — `confidentialNodes.enabled=True`, node a
genuine Confidential VM (`enableConfidentialCompute=True, type SEV`) — and was
torn down. Lessons baked into the scripts:

- **Zone stockout is normal.** SEV-SNP N2D stocked out in us-central1-a
  (`ZONE ... does not have enough resources`); the MIG looped silently. CI must
  fall back across zones, and to legacy SEV (`CONF_TYPE=sev`) when SEV-SNP is
  scarce. (TODO: add automatic zone-fallback to `provision-gcp.sh`.)
- **A mid-create cluster can't be deleted** ("incompatible operation") and the
  create op can't be cancelled — teardown must wait-and-retry until the create
  settles. Don't mask delete failures with `|| true`.
- **`kubectl` needs `gke-gcloud-auth-plugin`.** It's baked into `Dockerfile.gcp`
  (CI is fine); for a LOCAL run first do
  `gcloud components install gke-gcloud-auth-plugin`.

Wire `run.sh` step 3 to the real stack (attestation-rs / C8s) via `STACK_DEPLOY`;
the PoC in `../../k8s` is the worked example. Confirm confidential-node flags
against your gcloud/GKE version (GA on GKE >= 1.32.2).
