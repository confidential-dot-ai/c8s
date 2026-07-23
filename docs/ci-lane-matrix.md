# Confidential CI lane matrix

> merge to main → integrate on **real TEE hardware** → surface issues

The hub repo **confidential-dot-ai/confidential-ci** owns the shared primitive
(`cvm-e2e.yml`), the standing-runner provisioners, and the c8s-on-cloud lanes.
Three consumer surfaces test on merge, in three structurally different shapes.

## The map

```
  MODEL 1 · NODE-as-CVM        c8s   (the confidential Kubernetes distro itself)
  ──────────────────────────────────────────────────────────────────────────────────────────────

     merge to c8s main              c8s repo (PUBLIC)                 runs on the metal        boots an EPHEMERAL
                                                                      SNP launcher HOST        measured CVM = the cluster:
      push ─▶ "Docker"           confidential-e2e.yml                 ────────────────         install THIS c8s commit, attest
              image build ─▶       └─▶ e2e-c8s.yml        ──────▶     label: cvm-launcher      the launch measurement, prove a
              └─▶ workflow_run         └─▶ cvm-e2e.yml                                          workload gets a CDS cert, teardown
                                       (vendored primitive)

     LANE snp-metal  ✓ ON-MERGE   run 29978275402 (VMI Running + attested)
     LANE azure-snp / azure-tdx   ◐ exist HUB-side (MODEL 3), not wired to a c8s merge

        ┌──────────────────────────────────────────┐
        │  SEV-SNP BARE METAL   EPYC Genoa         │
        │  /dev/sev-guest   IGVM measured boot     │
        │  shared ROX rootdisk, readonly (PR#24)   │
        └──────────────────────────────────────────┘


  MODEL 2 · RUNNER-in-CVM      attestation-rs & kettle   (libraries: run the suite INSIDE a standing runner)
  ──────────────────────────────────────────────────────────────────────────────────────────────

     merge to main ─▶  attestation-rs : confidential-e2e.yml  ( job `tee`, matrix )
                       kettle         : e2e.yml               ( job `tee`, matrix + roundtrip* )
                       each matrix cell = runs-on: <label> ─▶ cargo nextest --features attest --run-ignored all

     LANE snp-metal               LANE azure-snp               LANE azure-tdx               LANE tdx-metal
     runs-on: snp-metal-cvm       runs-on: azure-snp-cvm       runs-on: azure-tdx-cvm       runs-on: tdx-metal-cvm
         ▼                            ▼                            ▼                            ▼
     ┌────────────────────┐       ┌────────────────────┐       ┌────────────────────┐       ┌────────────────────┐
     │ SEV-SNP BARE METAL │       │ Azure SEV-SNP      │       │ Azure Intel TDX    │       │ Intel TDX METAL    │
     │ EPYC Genoa         │       │ AKS node = CVM     │       │ VM (DC4es_v6)      │       │                    │
     │ /dev/sev-guest     │       │ vTPM /dev/tpmrm0   │       │ vTPM + /acc/tdquote│       │ ✗ NO host          │
     │                    │       │ scale-to-zero      │       │                    │       │ ✗ NO TDX image     │
     └────────────────────┘       └────────────────────┘       └────────────────────┘       └────────────────────┘
     ars ✓  kettle ✓              ars ✓  kettle ✓              ars ✓  kettle ✓              ✗ commented out,
     29979358753 / 29979359926    6/6 az_snp_live              14/14 az_tdx_live            no runner exists


  MODEL 3 · c8s-on-CLOUD       confidential-ci hub    (full c8s CLUSTER on cloud · NIGHTLY / DISPATCH, not merge)
  ──────────────────────────────────────────────────────────────────────────────────────────────

     azure-e2e.yml     ─▶ ephemeral confidential AKS (Model B, DC4as_v5 SEV-SNP) ─▶ c8s install --cvm-mode aks,
                                                                                   6 components, NRI enforce,
                                                                                   consumption + NEGATIVE deny
                                                                                   ✓ 29979488305 (busybox NRI-denied)
     azure-tdx-e2e.yml ─▶ ephemeral Azure Intel TDX VM + RKE2 (AKS refuses TDX)  ─▶ c8s install, az-tdx RA-TLS attest
                                                                                   ✓ 29979489430 (E2E_PASS @ 320s)


  STANDING-RUNNER PROVISIONERS (confidential-ci, dispatch)          POD-as-CVM / kata
  ───────────────────────────────────────────────────────           ─────────────────
  provision-snp-metal-cvm.yml ─▶ snp-metal-cvm (readonly ROX)       ✗ NO e2e lane anywhere.
  provision-azure-cvm.yml     ─▶ azure-snp-cvm (Model A)            kata-guest-base.yml only BUILDS
  provision-azure-tdx-cvm.yml ─▶ azure-tdx-cvm (standing TDX VM)    the guest image; nothing
  provision-tdx-metal-cvm.yml ─▶ tdx-metal-cvm ✗ 0 runs (stub)      installs/attests it.

   * kettle roundtrip = GitHub-hosted HTTP client to the REMOTE orchestrator (build.confidential.ai); not a self-hosted runner.
```

## Status grid

| REPO \ LANE | snp-metal | azure-snp | azure-tdx | tdx-metal | pod/kata |
|---|---|---|---|---|---|
| **c8s** (node-as-cvm) | ✅ ON-MERGE (boots ephemeral CVM) | ◐ hub nightly (Model B, AKS) | ◐ hub dispatch (ephemeral TDX VM) | ⛔ stub (no host/image) | ⛔ none |
| **attestation-rs** (runner-in-cvm) | ✅ ON-MERGE | ✅ ON-MERGE | ✅ ON-MERGE | ⛔ commented | ⛔ none |
| **kettle** (runner-in-cvm) | ✅ ON-MERGE | ✅ ON-MERGE | ✅ ON-MERGE | n/a | ⛔ none |

`✅` verified green on merge · `◐` green but hub-triggered (nightly / dispatch), not on a c8s merge · `⛔` not wired

## Per-lane reference

| Repo | Lane | File | Trigger | Runs on / driver | TEE hardware | Dispatch (no merge) |
|---|---|---|---|---|---|---|
| c8s | snp-metal | `confidential-e2e.yml` → `e2e-c8s.yml` → `cvm-e2e.yml` | `workflow_run[Docker]` + dispatch | `cvm-launcher` boots ephemeral SNP CVM | SEV-SNP metal (EPYC Genoa) | `gh workflow run confidential-e2e.yml --repo confidential-dot-ai/c8s --ref main` |
| attestation-rs | snp-metal / azure-snp / azure-tdx | `confidential-e2e.yml` job `tee` (matrix) | `push:main` + dispatch | `runs-on: <label>` (runner-in-cvm) | SEV-SNP metal / Azure SNP / Azure TDX | `gh workflow run confidential-e2e.yml --repo confidential-dot-ai/attestation-rs --ref main` |
| kettle | snp-metal / azure-snp / azure-tdx | `e2e.yml` job `tee` (matrix) | `push:main` + dispatch + nightly | `runs-on: <label>` (runner-in-cvm) | SEV-SNP metal / Azure SNP / Azure TDX | `gh workflow run e2e.yml --repo confidential-dot-ai/kettle --ref main` |
| c8s-on-cloud | azure-snp (Model B) | hub `azure-e2e.yml` | dispatch + nightly | ubuntu → `az aks create` ephemeral cluster | Azure SEV-SNP AKS node | `gh workflow run azure-e2e.yml --repo confidential-dot-ai/confidential-ci --ref main` |
| c8s-on-cloud | azure-tdx | hub `azure-tdx-e2e.yml` | dispatch | ubuntu → `az vm` DC4es_v6 + RKE2 | Azure Intel TDX VM | `gh workflow run azure-tdx-e2e.yml --repo confidential-dot-ai/confidential-ci --ref main` |

## The two real gaps

- **tdx-metal**: commented out in c8s (`e2e-c8s.yml`) and attestation-rs; no `tdx-metal-cvm` / `cvm-launcher-tdx` runner exists; no TDX rke2-node image; `provision-tdx-metal-cvm.yml` has **0 runs**. Blocked on a TDX CI host + the TDX node image.
- **pod-as-cvm / kata**: no e2e lane anywhere. `kata-guest-base.yml` only builds and pushes the guest rootfs image; nothing installs c8s in a kata pod-CVM and attests it.

## Verification sweep (2026-07-23, all `workflow_dispatch`, no merges/commits)

| Lane | Run | Proof |
|---|---|---|
| c8s snp-metal | 29978275402 | `VMI Running` + `attested` |
| attestation-rs (3 cells) | 29979358753 | snp-metal ✅ · azure-snp **6/6 az_snp_live** · azure-tdx **14/14 az_tdx_live** (0 skipped) |
| kettle (3 cells + roundtrip) | 29979359926 | all cells ✅ · **Verification PASSED ×4** |
| c8s on azure-snp (Model B) | 29979488305 | install + **NRI negative-deny** (busybox blocked at container create) |
| c8s on azure-tdx | 29979489430 | **E2E_PASS @ 320s**, az-tdx RA-TLS attested |
