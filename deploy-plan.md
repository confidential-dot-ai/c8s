# Plan: confidential CI runners for E2E on bare metal + GCP + Azure

Scope (the core use case, nothing more): self-hosted GitHub runners that **have
access to confidential-computing machinery**, so that on push to a
confidential-stack repo (attestation-rs / C8s) CI can **spin up a confidential
cluster, attest it, run the E2E, tear it down**. Today's runners (and
GitHub-hosted) can't, because they have no TEE access. We already have the
runner *orchestration* working (ARC, ephemeral, push-triggered — see
`README.md`); this plan adds the **confidential substrate** on three targets.

## The one design decision: where the TEE lives

Two models; we use both, per target.

- **Model A — runner ON confidential nodes.** Runner pods are scheduled onto
  confidential VMs / bare-metal SEV-SNP/TDX hosts. The job can attest local
  hardware and launch CVMs directly. Needed for **bare metal** (no cloud API to
  provision) and for tests that must attest the runner's own hardware/GPU.
- **Model B — runner provisions an ephemeral confidential cluster.** Runner
  pods run anywhere (even a cheap normal pool) but hold scoped cloud creds; the
  job spins up a fresh Confidential GKE / AKS-CVM cluster per run, tests it,
  destroys it. This is the industry-standard confidential-K8s E2E pattern
  (Constellation does this) and gives clean cost control + isolation.

**Recommendation:** Model B for **GCP/Azure** (ephemeral cluster per E2E),
Model A for **bare metal**. Hybrid is fine — the runner scale set is the same;
only placement + the job's provisioning step differ.

## Target substrates

### GCP (best-supported today)
- **Confidential GKE Nodes** — TDX or SEV-SNP, GKE ≥1.32.2. Confidential **H100
  on A3** is GA (GKE ≥1.32.2 manual driver / ≥1.33.3 auto) for the GPU
  attestation tests.
- Model B: job runs `gcloud container clusters create … --enable-confidential-nodes`
  (+ `--confidential-node-type=sev_snp|tdx`), deploys the stack, tests, deletes.
- Model A: a confidential GKE node pool hosts the runners directly.

### Azure
- AKS **Confidential Containers** (Kata + SEV-SNP, `KataCcIsolation`) is
  **preview, sunsetting ~March 2026** → don't build production E2E on it.
- Use **GA Confidential VMs** (DCasv5/ECasv5, 3rd-gen EPYC SEV-SNP) as an AKS
  **confidential node pool**, or provision Confidential VMs directly. Confidential
  **H100 on NCC-v5** for GPU tests. Attestation via Azure MAA or local.
- Model B: job provisions an AKS CVM-node cluster (or CVMs) per run via `az`.

### Bare metal
- AMD EPYC (SEV-SNP) and/or Intel Xeon (TDX) hosts, BIOS/firmware enabled, host
  kernel with SEV-SNP/TDX, `/dev/kvm` + `/dev/sev-guest` + configfs-tsm, QEMU /
  cloud-hypervisor / Kata to launch CVMs.
- Run a small k3s/k8s on the hosts; ARC runner pods scheduled there (Model A)
  with device access to launch the CVM-based test cluster. This is the gnarliest
  target (privileged pods, device passthrough, firmware management) — stage it
  last.

## Runner layer (mostly reuse what's built)

- **ARC** controller + **org-level** runner scale set (GitHub App, not PAT, for
  org scope) so any confidential repo can target it.
- **Per-platform labels** so the E2E can matrix: `runs-on: confidential-e2e-gcp`
  / `-azure` / `-baremetal`. Each label = its own scale set / node placement.
- **Custom runner image** (we proved this): bake `gcloud`/`az`/`terraform`,
  `kubectl`/`helm`, `kettle`, `attestation-cli`/`ccvm`, and the stack's test
  deps. One image per platform family.
- **Secrets**: Workload Identity Federation (GCP) / Managed Identity (Azure) so
  the runner gets short-lived cloud creds with NO long-lived keys; scope to a
  dedicated CI project/subscription. Bare metal: node-local, no cloud creds.
- **Safety**: private repos only; ephemeral runners; `concurrency` + hard
  `timeout-minutes`; **always-run teardown** (`if: always()`) so a failed E2E
  never leaks a confidential cluster (cost + security).

## E2E workflow shape (skeleton)

```yaml
on: { push: { branches: [main] }, workflow_dispatch: {} }
jobs:
  e2e:
    strategy:
      matrix: { target: [gcp, azure, baremetal] }
    runs-on: confidential-e2e-${{ matrix.target }}
    timeout-minutes: 60
    concurrency: e2e-${{ matrix.target }}   # one cluster per target at a time
    steps:
      - uses: actions/checkout@v4
      - name: Provision confidential cluster        # Model B (gcp/azure); no-op on baremetal (Model A, local)
        run: ./test/e2e/provision-${{ matrix.target }}.sh
      - name: Deploy stack + run attested E2E
        run: ./test/e2e/run.sh                       # deploy C8s/attestation-rs, assert attestation + key release + raTLS
      - name: Collect evidence / logs
        if: always()
        run: ./test/e2e/collect.sh
      - name: Tear down
        if: always()                                 # never leak a confidential cluster
        run: ./test/e2e/teardown-${{ matrix.target }}.sh
```

The `provision`/`teardown` scripts are the only per-platform bits; `run.sh`
(the actual confidential assertions) is shared. The `HAVE_TEE` gate from the
current workflow becomes unconditional here — these runners *are* TEE-capable.

## Nix vs Bazel — recommend Nix (scoped)

Neither is required to stand up the runners; a Dockerfile is fine for v1. The
question is what builds the **runner image and the CVM/node images** the E2E
relies on. For *this* stack, Nix wins:

- **Reproducibility → attestation.** Confidential computing needs *bit-stable*
  artifacts so launch measurements are predictable reference values. Nix gives
  that natively; that's the entire point.
- **It's already on-stack.** Kettle (their attested-build system) supports
  **nix** (+ Cargo, pnpm) and **not Bazel**; their reproducible base (Stagex) is
  Nix-aligned. Nix lets you **Kettle-attest the runner image itself** — the
  runner that runs attested builds becomes an attested build. Clean closure.
- **Bazel** shines for large polyglot monorepos (build graph + remote cache),
  but it doesn't produce measurable/reproducible images without extra work
  (`rules_nixpkgs`), and it's off-stack here. Adopt it only if there's already a
  Bazel monorepo demanding its caching — and even then bridge to Nix for the
  reproducible-artifact layer.

**Call:** Nix for the image/artifact layer (v2), Dockerfile for v1 bring-up.
Skip Bazel unless an existing monorepo forces it.

## Phased rollout

1. **v1 — GCP, Model B.** Reuse the ARC setup; new GCP runner image
   (Dockerfile) + WIF creds; `provision/run/teardown` for Confidential GKE
   Nodes (SEV-SNP first, then TDX, then A3/H100). Green E2E on push. Best
   ROI — GCP's confidential support is the most GA.
2. **v2 — Azure, Model B.** Same shape on AKS Confidential VM node pools
   (avoid the sunsetting CoCo preview). Add to the matrix.
3. **v3 — bare metal, Model A.** k3s on SEV-SNP/TDX hosts, privileged runners
   with device passthrough, local CVM provisioning. Hardest; do last.
4. **v4 — Nix.** Reproducible runner + node images, Kettle-attested, feeding
   the deploy allow-list (closes source→build→deploy→test for the CI infra too).

## What we already have vs what's new

Have (reusable as-is): ARC controller + scale set, ephemeral push-triggered
runners, custom-image pattern, repo/org registration, the `HAVE_TEE`-gated
workflow, and the build→deploy provenance gate.
New (this plan): confidential node placement / cloud provisioning, per-platform
labels + images, cloud identity federation, the matrixed spin-up→attest→
teardown E2E, and (v4) Nix-reproducible attestable images.
