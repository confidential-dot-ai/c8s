# Confidential CI lane matrix

> merge to main → integrate on **real TEE hardware** → surface issues

The hub repo **confidential-dot-ai/confidential-ci** owns the shared primitive
(`cvm-e2e.yml`), the standing-runner provisioners, and the c8s-on-cloud lanes.
Three consumer surfaces test on merge, in three structurally different shapes.

Since 2026-07-24 the fourth column is real hardware too: **Intel TDX bare metal**
(`tdx-gh-runner`) boots a measured TD guest, installs c8s in it console-free, and
serves an in-guest ARC runner. What is still missing there is CI *wiring*, not
infrastructure.

## The map

```
  MODEL 1 · NODE-as-CVM        c8s   (the confidential Kubernetes distro itself)
  ──────────────────────────────────────────────────────────────────────────────────────────────

     merge to c8s main              c8s repo (PUBLIC)                 runs on the metal        boots an EPHEMERAL
                                                                      SNP / TDX launcher HOST  measured CVM = the cluster:
      push ─▶ "Docker"           confidential-e2e.yml                 ───────────────────────  install THIS c8s commit, attest
              image build ─▶       └─▶ e2e-c8s.yml        ──────▶     label: cvm-launcher      the launch measurement, prove a
              └─▶ workflow_run         └─▶ cvm-e2e.yml                   or cvm-launcher-tdx     workload gets a CDS cert, teardown
                                       (vendored primitive)

     LANE snp-metal  ✓ ON-MERGE   run 29978275402 (VMI Running + attested)
     LANE tdx-metal  ◐ PROVEN     c8s installs + attests inside a TD guest on tdx-gh-runner
                                  (hand-run, console-free); e2e-c8s.yml row still commented out
     LANE azure-snp / azure-tdx   ◐ exist HUB-side (MODEL 3), not wired to a c8s merge

        ┌──────────────────────────────────────────┐   ┌──────────────────────────────────────────┐
        │  SEV-SNP BARE METAL   EPYC Genoa         │   │  INTEL TDX BARE METAL   tdx-gh-runner    │
        │  /dev/sev-guest   IGVM measured boot     │   │  /dev/tdx_guest   TDVF boot, MRTD        │
        │  shared ROX rootdisk, readonly (PR#24)   │   │  readonly rootdisk + encrypted scratch   │
        └──────────────────────────────────────────┘   └──────────────────────────────────────────┘


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
     │ EPYC Genoa         │       │ AKS node = CVM     │       │ VM (DC4es_v6)      │       │ tdx-gh-runner      │
     │ /dev/sev-guest     │       │ vTPM /dev/tpmrm0   │       │ vTPM + /acc/tdquote│       │ /dev/tdx_guest     │
     │                    │       │ scale-to-zero      │       │                    │       │ MRTD measured boot │
     └────────────────────┘       └────────────────────┘       └────────────────────┘       └────────────────────┘
     ars ✓  kettle ✓              ars ✓  kettle ✓              ars ✓  kettle ✓              runner LIVE ✓
     29979358753 / 29979359926    6/6 az_snp_live              14/14 az_tdx_live            ars/kettle cells ◐


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
  provision-tdx-metal-cvm.yml ─▶ tdx-metal-cvm ◐ 0 runs (hand)      installs/attests it.
                                 (live runner stood up by hand;
                                  workflow needs the path fix)

   * kettle roundtrip = GitHub-hosted HTTP client to the REMOTE orchestrator (build.confidential.ai); not a self-hosted runner.
   ◐ tdx-metal = hardware, node image and runners are LIVE and hand-verified; the matrix cells in c8s,
     attestation-rs and kettle are still commented out, so nothing fires there on merge yet.
```

## Status grid

| REPO \ LANE | snp-metal | azure-snp | azure-tdx | tdx-metal | pod/kata |
|---|---|---|---|---|---|
| **c8s** (node-as-cvm) | ✓ ON-MERGE (boots ephemeral CVM) | ◐ hub nightly (Model B, AKS) | ◐ hub dispatch (ephemeral TDX VM) | ◐ install + attest PROVEN by hand; matrix row commented | ✗ none |
| **attestation-rs** (runner-in-cvm) | ✓ ON-MERGE | ✓ ON-MERGE | ✓ ON-MERGE | ◐ runner LIVE; cell still commented | ✗ none |
| **kettle** (runner-in-cvm) | ✓ ON-MERGE | ✓ ON-MERGE | ✓ ON-MERGE | ◐ runner LIVE; cell not added yet | ✗ none |

`✓` verified green on merge · `◐` green but not merge-triggered (hand-run / hub nightly / dispatch) · `✗` not wired

## Per-lane reference

| Repo | Lane | File | Trigger | Runs on / driver | TEE hardware | Dispatch (no merge) |
|---|---|---|---|---|---|---|
| c8s | snp-metal | `confidential-e2e.yml` → `e2e-c8s.yml` → `cvm-e2e.yml` | `workflow_run[Docker]` + dispatch | `cvm-launcher` boots ephemeral SNP CVM | SEV-SNP metal (EPYC Genoa) | `gh workflow run confidential-e2e.yml --repo confidential-dot-ai/c8s --ref main` |
| c8s | tdx-metal | `cvm-e2e.yml` cell `tdx-metal/rke2-node` (via `e2e-c8s.yml`) | none yet: the matrix row is commented out in `e2e-c8s.yml` | `cvm-launcher-tdx` boots a measured TD guest (launchSecurity.tdx + TDVF, no IGVM) | Intel TDX metal (`tdx-gh-runner`) | `gh workflow run probe-cvm.yml --repo confidential-dot-ai/confidential-ci -f platform=tdx-metal -f flavor=rke2-node -f runner=cvm-launcher-tdx` |
| attestation-rs | snp-metal / azure-snp / azure-tdx | `confidential-e2e.yml` job `tee` (matrix) | `push:main` + dispatch | `runs-on: <label>` (runner-in-cvm) | SEV-SNP metal / Azure SNP / Azure TDX | `gh workflow run confidential-e2e.yml --repo confidential-dot-ai/attestation-rs --ref main` |
| kettle | snp-metal / azure-snp / azure-tdx | `e2e.yml` job `tee` (matrix) | `push:main` + dispatch + nightly | `runs-on: <label>` (runner-in-cvm) | SEV-SNP metal / Azure SNP / Azure TDX | `gh workflow run e2e.yml --repo confidential-dot-ai/kettle --ref main` |
| attestation-rs / kettle | tdx-metal | same `tee` matrix, one more cell | none yet: cell commented (ars) / absent (kettle) | `runs-on: tdx-metal-cvm`, an in-guest ARC scale set (minRunners 0) | Intel TDX metal (`tdx-gh-runner`) | uncomment/add the cell, then the repo's normal dispatch above |
| confidential-ci | tdx-metal (runner) | `provision-tdx-metal-cvm.yml` | dispatch | `cvm-launcher-tdx` boots the standing CVM, console-installs ARC into it | Intel TDX metal (`tdx-gh-runner`) | `gh workflow run provision-tdx-metal-cvm.yml --repo confidential-dot-ai/confidential-ci --ref main` |
| c8s-on-cloud | azure-snp (Model B) | hub `azure-e2e.yml` | dispatch + nightly | ubuntu → `az aks create` ephemeral cluster | Azure SEV-SNP AKS node | `gh workflow run azure-e2e.yml --repo confidential-dot-ai/confidential-ci --ref main` |
| c8s-on-cloud | azure-tdx | hub `azure-tdx-e2e.yml` | dispatch | ubuntu → `az vm` DC4es_v6 + RKE2 | Azure Intel TDX VM | `gh workflow run azure-tdx-e2e.yml --repo confidential-dot-ai/confidential-ci --ref main` |

## The remaining gaps

- **tdx-metal is not ON-MERGE yet.** The blocker is no longer hardware, an image,
  or the provisioner; it is two commented matrix cells:
  - `e2e-c8s.yml`: the row `# - { platform: tdx-metal, runner: cvm-launcher-tdx }`
    is still commented with the reason "needs a TDX rke2-node image". That reason
    is stale; the image and its `tdx-rke2-image-refs` ConfigMap exist.
  - attestation-rs and kettle: the `tdx-metal` / `runs-on: tdx-metal-cvm` cell of
    the `tee` matrix is commented (ars) or not present (kettle), even though the
    runner is registered and scales to zero.

  FIXED HERE, recorded because the failure mode is silent: the runner overlay
  mounts **`/dev/tdx_guest`** (underscore). The hyphen spelling applies cleanly
  and fails only later, at attest time, because kubelet happily creates an empty
  directory for a missing hostPath. The overlay also pins `type: CharDevice`, so
  a missing device now fails the pod at admission rather than at attest, and
  mounts `/sys/kernel/config`. Note that qemu's `-object tdx-guest` is a
  different string and stays hyphenated.
- **pod-as-cvm / kata**: no e2e lane anywhere. `kata-guest-base.yml` only builds
  and pushes the guest rootfs image; nothing installs c8s in a kata pod-CVM and
  attests it. TDX metal makes this cheaper now (the host carries the qemu-tdx
  shims), but the lane still does not exist.

## Verification sweep (2026-07-23, all `workflow_dispatch`, no merges/commits)

| Lane | Run | Proof |
|---|---|---|
| c8s snp-metal | 29978275402 | `VMI Running` + `attested` |
| attestation-rs (3 cells) | 29979358753 | snp-metal ✓ · azure-snp **6/6 az_snp_live** · azure-tdx **14/14 az_tdx_live** (0 skipped) |
| kettle (3 cells + roundtrip) | 29979359926 | all cells ✓ · **Verification PASSED ×4** |
| c8s on azure-snp (Model B) | 29979488305 | install + **NRI negative-deny** (busybox blocked at container create) |
| c8s on azure-tdx | 29979489430 | **E2E_PASS @ 320s**, az-tdx RA-TLS attested |

## TDX metal bring-up (2026-07-24, hand-built on `tdx-gh-runner`, no run id yet)

Everything below was executed by hand end to end. It is the spec the tdx-metal
lane has to reproduce, and every line of it is a thing that silently breaks the
boot if you get it wrong.

| Step | What actually works |
|---|---|
| node image | `ghcr.io/confidential-dot-ai/c8s-base@sha256:20582959f163acd7b3c0927c3ce2c395da162bb5993890d4f387b46147f4258a` (`:rke2-cdi-64b6d7a`). Refs live in ConfigMap `tdx-rke2-image-refs`, namespace `confai-images`: `image`, `rootPvc=c8s-root-20582959f163`, `mrtd=9309eaae9c151e76...27198ba1` (48 B), `c8sRef=64b6d7a`, `cdiTag` |
| CVM shape | `nodeSelector kubevirt.io/tdx=true` · `launchSecurity: {tdx: {}}` · cpu **`host-passthrough`** (named CPU models are rejected for TDX) · firmware EFI with `secureBoot: false` · `autoattachVSOCK: true` · `memory: 16Gi` (**17 to 63 GiB is a dead zone: the guest silently boot-loops**) · masquerade interface |
| disks | `rootdisk` from the PVC with `disk: {bus: virtio, readonly: true}` (`readonly` is a field **of** `disk`, not a sibling) · `scratch` PVC >= 64Gi carrying `serial: confai-scratch` (the initrd keys its encrypted overlay off that serial) · `opkey` Secret volume with `volumeLabel: opkeydata`, the Secret holding one key `pubkey` = the operator EC public key PEM, which the initrd SHA384s into RTMR[3] · `cloudinit` NoCloud secretRef (hostname only) |
| access | console-free. Poll `http://<vmi-ip>:8400/health` until it reports `platform=tdx`, `https://<ip>:6443/livez` (200/401/403) and `https://<ip>:8443` (any non-000), then `c8s get-kubeconfig --node <ip> --operator-key <key> --out <file> --timeout 180s` yields `identity=operator`, groups `system:masters` |
| c8s CLI | build at the ConfigMap's `c8sRef`: `git clone .../c8s.git && git checkout 64b6d7a && go install ./cmd/c8s`. An unstamped build reports version `dev`, so **`--image-tag 64b6d7a` is mandatory** |
| install | `c8s install --cvm-mode node --single-node --hardware-platform tdx --image-tag 64b6d7a --operator-keys <pub> --measurements <mrtd> --resolve-digests=true -f <extra-values>` |
| ARC in the guest | apply a `helm.cattle.io/v1` HelmChart CR in `kube-system` (klipper-helm is PSA and NRI exempt there), `targetNamespace` `arc-systems` / `arc-runners`; label **both** namespaces `pod-security.kubernetes.io/{enforce,warn,audit}=privileged` (the image bakes a restricted PSA default) |
| runner pod | digest-pinned `ghcr.io/actions/actions-runner` **2.336.0** (2.331.0 is deprecated by GitHub: "Runner version is deprecated and cannot receive messages") · `command: ["/home/runner/run.sh"]` · `RUNNER_ALLOW_RUNASROOT=1` · `securityContext {privileged: true, runAsUser: 0}` · hostPath `/dev/tdx_guest` with `type: CharDevice` plus `/sys/kernel/config` (`type: Directory`) |
| allowlist | the chart path `ghcr.io/actions/actions-runner-controller-charts/...` is **not** the image path: the controller runs `ghcr.io/actions/gha-runner-scale-set-controller`, and the listener reuses the controller image, so controller + listener = one digest, runner image = a second. Allowlist **by digest** (`crane digest`, the index digest) |
| durability | runtime `c8s allowlist add <digest> <image> --url https://<ip>:30808 ...` entries are **lost on a CDS restart** (`cds.persistence.enabled` defaults false). Digests belong at install time under `nriImagePolicy.bootstrapAllowlist.digests` as `digest -> "repo@digest"` |
| labels produced | `tdx-metal-cvm` (the in-guest ARC runner, MODEL 2) · `cvm-launcher-tdx` (the host-side driver, MODEL 1) |
