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
  `confai-images` (incl. `pods/exec` for in-guest assertion); runner pods bound to it.
- **SNP-VM E2E green** (`snp-e2e.yml`): a `runs-on: confidential-bm` job launches
  the SEV-SNP VM, waits `Pending→Scheduled→Running`, **asserts a genuine
  `sev-snp-guest` + IGVM measured boot** by reading the qemu cmdline inside the
  launcher, then tears down. End-to-end confidential-VM CI on bare metal.
- **Full attestation-rs CI matrix green** — `cifrai/attestation-rs-ci` run with
  `check`, `test`, `release-build·x86_64`, `audit` on **`confidential-bm`** (arm64
  /macOS/docker on GitHub-hosted). Functionally identical to the GKE run, and far
  faster on the 24-core EPYC: x86 release ~3 min (vs ~20 on the GKE e2-medium),
  `cargo-audit` compile ~1 min (vs ~23). `audit` correctly flags the same real CVE
  (`RUSTSEC-2026-0185`, quinn-proto) — the attestation-rs team's triage call.
  Diff vs the GKE workflow: `runs-on` + an in-job apt step (stock runner image,
  no baked deps — a baked image needs a registry we can push to).

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

## Watching it run

All against the Rancher kubeconfig (the bare-metal cluster):

```bash
export KUBECONFIG=~/dev/conf/github-runner.yaml
```

Runners are **ephemeral** — with `minRunners: 0` they only exist *while a job
runs*, so `arc-runners` is empty when idle. Start a watch, then trigger a job:

```bash
# the CI job's runner pod (one per job; name = confidential-bm-<id>-runner-<id>)
kubectl get pods -n arc-runners -o wide -w

# trigger something to watch (any runs-on: confidential-bm job)
gh workflow run smoke   --repo cifrai/confidential-bm-smoke      # trivial job
gh workflow run snp-e2e --repo cifrai/confidential-bm-smoke      # launches the SNP VM
```

| Want to see | Command |
|---|---|
| Runner pod (the CI job), with node | `kubectl get pods -n arc-runners -o wide -w` |
| Scaler/listener (always on — why a runner did/didn't start) | `kubectl logs -n arc-systems -l app.kubernetes.io/component=runner-scale-set-listener -f` |
| Controller + listener health | `kubectl get pods -n arc-systems -o wide` |
| The confidential VM (only during `snp-e2e`) | `kubectl get pods,vmi -n confai-images -o wide -w` |
| Prove the guest is really SNP | `kubectl exec -n confai-images <virt-launcher-bm-e2e-snp-…> -c compute -- bash -lc "cat /proc/*/cmdline \| tr '\0' '\n' \| grep -E 'sev-snp-guest\|igvm'"` |

`-o wide` shows the node (`sev-snp-gh-runner`) and pod IP. Job/run status from the
GitHub side: `gh run watch <id> --repo cifrai/<repo>`.

## Files
- `install-arc-rancher.sh` — proxy-safe ARC install + scale-set registration + RBAC
- `kubevirt-rbac.yaml` — scoped SA/Role/RoleBinding for VM lifecycle in confai-images
- `snp-vm-e2e.yaml` — the confidential SNP target VM (confirmed working values)
- `snp-e2e.yml` — the SNP-VM E2E workflow (launch → assert sev-snp-guest → teardown)
- `smoke.yml` — the trivial `runs-on: confidential-bm` proof workflow

## Production hardening (when wiring the real E2E)
- **CDI-clone** the base rootdisk per run instead of mounting the shared PVC
  directly (RWO serializes runs; avoids touching the canonical base image).
- Bake `kubectl`/`helm`/`virtctl` into a runner image (push to the cluster's GHCR
  org) rather than installing in-job.
- In-guest attestation: fetch the SNP report bound to a nonce and verify with
  attestation-go/-rs — the real confidential assertion (beyond platform-level).
