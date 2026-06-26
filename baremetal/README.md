# Bare-metal confidential runner (RKE2 + KubeVirt SEV-SNP)

The GKE path (`../`) runs runners on Confidential GKE nodes. On the company's
bare-metal platform (`conf/bare-metal-infra-management`: RKE2 + KubeVirt + custom
IGVM QEMU), confidentiality is a **SEV-SNP KubeVirt VM** (verity rootfs, IGVM
measured boot) — not a confidential node. So **Model A** is the fit:

- The **runner orchestrator** runs as normal ARC pods on the SNP-capable host.
- Each **CI job launches an ephemeral SEV-SNP KubeVirt VM** as the confidential
  target (`snp-vm-e2e.yaml`), attests/tests inside it, tears it down.
- Mirrors the GKE Model B (`../e2e/`), adapted to KubeVirt instead of GKE.

## What's proven (live, on `github-runner-dev` / `sev-snp-gh-runner`)

- **ARC installed** on the Rancher-managed RKE2 cluster via `install-arc-rancher.sh`
  (proxy-safe: CRDs applied individually + `helm template | kubectl apply`, because
  the Rancher proxy rejects the controller chart's oversized helm release secret).
- **Scale set `confidential-bm`** registered to the **cifrai org** (private),
  listener connected (scale-set id 3).
- **Smoke job green:** a `runs-on: confidential-bm` job ran on the box — confirmed
  `AMD EPYC 8224P`, kernel flags `sev / sev_es / sev_snp` present. The runner
  picks up cifrai jobs and tears the ephemeral pod down.
- **KubeVirt RBAC** (`kubevirt-rbac.yaml`): `bm-e2e` SA, scoped to launch VMs in
  `confai-images`; runner pods bound to it.

## What's blocked (cluster provisioning, not this infra)

Launching the SNP **target VM** fails today because the cluster's confidential-VM
image stack is only **partially provisioned** — a `lunal-dev → confidential-dot-ai`
rename migration gap:

| Component | Expected | On this cluster |
|---|---|---|
| Custom IGVM virt-launcher | `ghcr.io/confidential-dot-ai/virt-launcher-snp@sha256:2f60cda4…` (KubeVirt CR patch) | a launched VM still came up on **stock `quay.io/kubevirt/virt-launcher:v1.7.0`** — the custom-launcher patch isn't taking effect |
| IGVM hook sidecar | a digest that exists in **this** registry | dev-vm chart / `group_vars` pin `ghcr.io/lunal-dev/igvm-hook-sidecar@sha256:7450bb…` → **`NotFound`** (stale org; should be `confidential-dot-ai`) |
| `igvm-files` PVC | present | ✅ present |
| base rootdisk PVC | present | ✅ `cpu-image-rootdisk-0df2ca7d5549` |

### Workaround we use (no repo PR needed)

We don't wait on the repo fix: our runner authors its **own** VM spec, so
`snp-vm-e2e.yaml` pins the sidecar at **`ghcr.io/confidential-dot-ai/igvm-hook-sidecar@sha256:7450bb…`**
directly. **Proven 2026-06-26:** that VM reaches `Running` and is a *genuine*
SEV-SNP guest — qemu runs `/usr/local/qemu-igvm/bin/qemu-system-x86_64` with
`confidential-guest-support` + a `{"qom-type":"sev-snp-guest",…}` object and
`igvm-cfg file=guest-smp2.igvm`. (The stock `virt-launcher:v1.7.0` *image label*
is a red herring — the custom IGVM qemu is mounted in, so the guest is really
confidential.) So the only thing the repo PR (#58/#60) buys us is fixing the
chart default for *other* consumers; our E2E is unblocked today.

**Hand-off to the bare-metal owners (Ameen):** to fix it for chart/CLI consumers —
1. Publish/point the **IGVM hook sidecar** to the `confidential-dot-ai` org (match
   the launcher), and update the dev-vm chart / `group_vars` (`igvm_sidecar_image`)
   off the stale `lunal-dev` digest.
2. Ensure the KubeVirt CR's `VIRT_LAUNCHER_IMAGE` patch actually takes (the probe
   VM used the stock launcher — restart/verify `virt-controller`).

Once VMs launch, fill the placeholders in `snp-vm-e2e.yaml` (sidecar image, rootPvc,
`guest-smp<cores>.igvm`) and wire it into a `runs-on: confidential-bm` workflow:
apply → wait VMI `Running` → assert `launchSecurity.snp` + SNP-node placement →
(then in-guest SNP report verification) → delete.

## Files
- `install-arc-rancher.sh` — proxy-safe ARC install + scale-set registration + RBAC
- `kubevirt-rbac.yaml` — scoped SA/Role/RoleBinding for VM lifecycle in confai-images
- `snp-vm-e2e.yaml` — the confidential SNP target VM (placeholders to fill)
- `smoke.yml` — the trivial `runs-on: confidential-bm` proof workflow

## Production hardening (when wiring the real E2E)
- **CDI-clone** the base rootdisk per run instead of mounting the shared PVC
  directly (RWO serializes runs; avoids touching the canonical base image).
- Bake `kubectl`/`helm`/`virtctl` into a runner image (push to the cluster's GHCR
  org) rather than installing in-job.
- In-guest attestation: fetch the SNP report bound to a nonce and verify with
  attestation-go/-rs — the real confidential assertion (beyond platform-level).
