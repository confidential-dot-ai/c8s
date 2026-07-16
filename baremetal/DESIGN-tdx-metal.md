# tdx-metal lane — design (PRIORITIZED 2026-07-16: next cell after the consumer PRs land)

> Status: was design-only/deferred (2026-07-15); **bumped to the FRONT of the
> matrix on maintainer guidance (2026-07-16 call)** — CoreWeave is
> TDX-on-bare-metal and setting up NOW; João named TDX CI as the thing to keep
> working. Hardware EXISTS and is provisioned — `tdx-dev-host-1` (OVH
> Scale-i1, Intel TDX): RKE2 + KubeVirt v1.9.0-beta.0 (TDVF/QGS), DCAP
> configured (qgsd + tdx-qgs-bridge vsock), TDX rootdisk PVC pre-imported
> (`tdx-cpu-image-cdi@sha256:…`). What's missing is CI plumbing, not
> infrastructure. OPEN (ask Ameen): run CI on tdx-dev-host-1, or provision a
> dedicated `tdx-gh-runner` mirroring sev-snp-gh-runner's dedicated-CI
> pattern.

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

## The TDX rke2-node image — it's confos PR #51, and it's buildable NOW

**Reframed 2026-07-16 (user pointed at confidential-os-builder).** The image is
NOT base-images' opaque long pole — it's a **confos mkosi profile**, in flight
as **`confidential-dot-ai/confidential-os-builder` PR #51 (`feat/c8s-profile`):
"measured RKE2 node-image profile for c8s"** (joaosa's "attestation-api + NRI"
work — first target is CoreWeave TDX bare metal). Everything c8s installs via
privileged DaemonSets is baked into the dm-verity root so the launch
measurement covers it: RKE2 v1.34.5 (airgap image bundles baked → no first-boot
egress), nri-image-policy (fail-closed), attestation-api by profile
composition.

**June's "wall" is gone.** The fat kernel needing BOTH confidential-guest AND
k8s-networking symbols now exists: `kernel/c8s.config` = `gpu.config` verbatim +
base-images `rke2/kernel/container.config` (VETH/BRIDGE/VXLAN/USER_NS/… all =y,
no runtime modprobe). That was the one thing we couldn't produce; the PR
produces it.

**confos is dual-platform by design** (README): same rootfs, `--platform tdx`
switches the measured-boot path to TDVF + `manifest.json` `{mrtd, rtmr1,
rtmr2}` (vs SNP's IGVM + launch digest). And **`bin/build-c8s` already defaults
`--platform tdx`** (line 66) — the c8s node image is TDX-first out of the box.

**So "build it ourselves" = build from PR #51's branch:**
```
git checkout feat/c8s-profile           # confos PR #51
bin/setup                                # mkosi v26, qemu, swtpm, rust
C8S_STOCK_ATTEST=1 C8S_NO_GPU=1 bin/build-c8s
#   → confos build c8s --profile attest --profile c8s --platform tdx
#   → output/c8s/{disk.raw, manifest.json (mrtd/rtmr1/rtmr2), roothash}
#     + a :c8s-cdi KubeVirt CDI artifact
```
Then stage on tdx-dev-host-1 exactly like the SNP rke2 image: import the CDI
rootdisk as a PVC, publish `tdx-image-refs` (rootPvc + the manifest's mrtd as
the golden), boot via the primitive's `tdx-metal` case. `C8S_STOCK_ATTEST=1` is
CI's mode (stock attest profile, serves TDX quotes — the GPU-evidence digest
isn't needed for our cell).

**The honest catch (why this is "help land #51", not "race joaosa"):** PR #51
is UNMERGED and its own validation plan (docs/C8S-IMAGE.md S0–S5:
kernel-fragment → GPU-less boot → full compose → CVM-on-CoreWeave → `c8s
install` → CI publish) is **"not yet run — this PR is the build tooling."** So
building ourselves means being the FIRST to actually run its build+boot — which
is precisely joaosa's S0–S5, and precisely what our primitive automates. The
high-leverage move is to offer our harness as the **CI that executes PR #51's
validation**, not to fork it. Build host: needs real Linux + userns/sudo (not a
mac, not a rootless container) + ~3.5G pinned downloads; a confos runner or an
ephemeral cloud VM.

## Legacy asks (now mostly answered by PR #51 — keep only the parity item)

Relay to joaosa on the image (most of these PR #51 already addresses):
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
