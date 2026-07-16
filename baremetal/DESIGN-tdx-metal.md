# tdx-metal lane — design (build deferred until triggers+consumers land)

> Status: DESIGN-ONLY (2026-07-15 decision). The hardware EXISTS and is
> provisioned — `tdx-dev-host-1` (OVH Scale-i1, Intel TDX): RKE2 + KubeVirt
> v1.9.0-beta.0 (TDVF/QGS), DCAP configured (qgsd + tdx-qgs-bridge vsock),
> TDX rootdisk PVC pre-imported (`tdx-cpu-image-cdi@sha256:…`). What's missing
> is CI plumbing, not infrastructure.

## Sequence (each step is independently verifiable)

1. **ARC scale set `cvm-launcher-tdx`** on tdx-dev-host-1's cluster — existing
   `register.sh` APP mode, same GitHub App (4309649), new
   `RUNNER_SCALE_SET_NAME=cvm-launcher-tdx`, runner pods node-pinned to the TDX
   host. Same honest-naming rule: the runner is a HOST-side launcher, not a TEE.
2. **cluster-prep parity**: `tdx-image-refs` CM (rootPvc = the imported
   tdx-cpu-image-cdi PVC, igvm/TDVF refs), plus the RBAC + egress CNP from
   `baremetal/` applied to that cluster. Verify with `where-am-i` +
   `probe-cvm.yml` (platform: tdx-metal) before any consumer.
3. **Primitive gains the `tdx-metal/base-cpu` case** in cvm-e2e.yml's
   platform-config:
   - `launchSecurity: { tdx: {} }` instead of `snp: {}`; no `EPYC-Genoa` cpu
     model (Intel host); firmware via KubeVirt v1.9 TDVF path.
   - boot assertion greps the qemu cmdline for the TDX guest object
     (`tdx-guest`), not `sev-snp-guest`.
   - **$MEAS discovery must branch per platform**: configfs-tsm `outblob` on
     TDX is a TDREPORT, not an SNP report — MRTD is NOT at offset 0x90.
     VERIFY the offset against the TDREPORT struct (TDINFO at 512; MRTD at
     TDINFO+16 = 528, 48 bytes) before trusting it; better, parse with a tiny
     python struct reader that switches on report size.
4. **First consumer = attestation-rs, NOT c8s**: the attestation-rs lane's
   base-cpu vehicle (nextest archive) rebuilt `--features attest` runs the TDX
   attest/verify paths natively (`/dev/tdx_guest`, configfs-tsm, QGS vsock).
   This needs NO new image work. c8s-on-TDX waits for a **TDX rke2-node image**
   — that's base-images' long pole, not ours; don't block the lane on it.
5. c8s TDX cell later: c8s already supports `--hardware-platform tdx`
   (chart: `cds.ratlsPlatform=tdx`, `teeDevices.tdxGuest`, preflight requires
   nodes labeled `confidential.ai/tdx=true`).

## Known blockers (tracked, not ours to fix here)

- **TDX rke2-node image** — gates the c8s cell (step 5), and possibly step 4
  too (see caveat below). **CONFIRMED IN FLIGHT (2026-07-16, joaosa): "not
  yet, but I am working on one (it includes a few more things like
  attestation-api and NRI)".** Asks to relay so it lands CI-drivable:
  1. **Autologin shell on the serial console** (parity with the SNP rke2
     image). The primitive's delivery requires it — the SNP base-cpu image is
     console-dead (probed 2026-07-15: silent after the EFI stub) and therefore
     unusable for CI payloads. Even better: bake a small in-guest HTTP agent
     (research/guest-transport.md) and the console dependency disappears for
     every future image.
  2. **Publish producer refs** (the base-image-refs/rke2-image-refs CM pattern,
     confidential-metal#60): rootdisk PVC/OCI ref, TDVF/firmware ref, and the
     pinned smp/cores — MRTD depends on boot config, so the pin ships with the
     image.
  3. **SNP parity question**: if attestation-api + NRI are joining the TDX
     image, does the SNP rke2 image get the same? Today ratlsMesh +
     nriImagePolicy are DISABLED in the SNP lane (missing kernel netfilter
     modules); if the new image generation fixes that, both cells can enable
     those rows and SNP/TDX coverage stays symmetric.
- **Step-4 caveat (found after this doc was written):** the "no new image
  work" claim assumed the imported `tdx-cpu-image` can take console payloads —
  but its SNP sibling (base-cpu) proved console-dead. FIRST action when this
  lane starts: `probe-cvm` against the tdx-cpu image. If it's also
  console-dead, joaosa's rke2 image gates step 4 as well, and the lane's start
  should align with his image's ETA.
- `attestation-cli` v0.4.0 lacks `--expected-mrtd/rtmr*` (release pipeline
  wedged) — irrelevant for step 4 (the library tests verify in-process), only
  matters if a lane wants CLI-based golden pinning.
- KubeVirt v1.9.0-beta.0 on that host: `confidentialCompute.tdx` CRD is beta;
  expect API drift on upgrades.

## Azure (notes — the lane with UNIQUE coverage)

Azure is not "another TDX cell": it's the ONLY place attestation-rs's
`az_snp_live` / `az_tdx_live` tests can run (they need the Azure vTPM + IMDS,
features `az-snp`/`az-tdx`). c8s-fleet's `aks_provisioner` role + the
`confidential-aks-dev` cluster already exist. Shape: mirror the gke-e2e design
(nodes are CVMs, no console), SEV-SNP node pools GA (`Standard_DC4as_v5`);
TDX via DCes_v5. AKS CoCo (pod-level kata) preview sunsets ~Mar 2026 — target
node-level CVMs only.
