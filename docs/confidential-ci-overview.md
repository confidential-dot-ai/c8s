# Confidential CI/CD — Overview & Status

> 📄 Shared copy in Notion (Confidential AI → Docs): <https://app.notion.com/p/39f47d37a53d81be9cbbda976f7b323f>. This markdown is the version-controlled source of truth; the two are kept in sync by hand.

**Repo:** [`confidential-dot-ai/confidential-ci`](https://github.com/confidential-dot-ai/confidential-ci) · **Status as of 2026-07-16:** flagship lane green (incl. nightly), two consumer lanes proven pre-merge, three PRs open awaiting review.

> **What this is.** Automated CI that runs our tests **inside real confidential VMs** (SEV-SNP today, TDX/cloud designed) so the whole confidential-computing stack is tested on every change — replacing the test clusters we stand up by hand each week. The one-line goal: **merge to main → integration happens in a CVM → issues surfaced.**

---

## 1. The goal

> The ability to run CI inside CVMs so we can test features that require confidential computing — which is more or less our whole stack. Example: push a change to the attestation lib → run e2e tests to make sure it still produces valid attestations on all platforms (TDX and SEV-SNP, cloud and bare metal). Today we do this by hand; confidential CI/CD automates it. The ultimate goal is end-to-end integration tests on c8s so we stop spinning up test clusters by hand every week: push to c8s → spin up a test cluster on every platform → e2e each one.

Two customer surfaces the platform matrix maps onto:
- **Bare metal** — customers who plug in power cords (CoreWeave, Nebius, Humain).
- **Cloud** — customers who rent infra (Baseten, Modal, RunPod).

Both are co-equal must-haves. The immediate unlock we were missing: *merge → integration → issues surfaced* as instant feedback, instead of agent-driven manual testing.

---

## 2. Architecture — four independent knobs

The vision has four variables; each gets its own knob so they change independently.

| Question | Knob | Lives in |
|---|---|---|
| **WHAT** to test (c8s? attestation-rs? kettle? — the whole stack) | the **payload** | the consumer repo |
| **WHERE** (SNP/TDX × metal/cloud) | the **platform matrix** | consumer matrix rows → primitive |
| **WHEN** (merge → integration → issues surfaced) | the **trigger** | the consumer |
| **HOW** a CVM boots/attests/tears down | the **primitive** | `confidential-ci` (shared) |

**The primitive** — [`.github/workflows/cvm-e2e.yml`](https://github.com/confidential-dot-ai/confidential-ci/blob/main/.github/workflows/cvm-e2e.yml) — is the one generic thing: boot a measured CVM on a platform → assert it's a genuine `sev-snp-guest` → self-discover its runtime launch measurement (configfs-tsm) → run a caller **payload** inside it → stream progress → tear down (always) + reap leaked CVMs. It knows nothing about c8s.

**A consumer** owns only WHAT + WHEN (~15–40 lines). Adding a platform = adding a matrix row. Adding a repo = a new consumer file with a different payload on the *same* primitive. That's how one primitive gives whole-stack coverage.

---

## 3. Platform support matrix

The matrix is the two customer surfaces (bare metal × cloud) crossed with the two
TEE technologies (SEV-SNP × TDX). Each cell is one **platform** value the primitive
knows how to boot; adding a cell = adding a matrix row on a consumer, not new
infra per repo.

|  | **Bare metal** — plug in power cords (CW · Nebius · Humain) | **Cloud** — rent infra (Baseten · Modal · RunPod) |
|---|---|---|
| **SEV-SNP** (AMD) | ✅ **live** — `snp-metal` | 📐 designed — `gke-snp` |
| **Intel TDX** | 📐 designed — `tdx-metal` | 📝 notes — `gke-tdx` / Azure |

**Legend:** ✅ live & green · 📐 designed (spec written, hardware/seam identified, buildable) · 📝 notes (direction only).

| Cell | Runner / host | Boot model | Status | Gating next step | Design |
|---|---|---|---|---|---|
| **`snp-metal`** | `cvm-launcher` / `sev-snp-gh-runner` | KubeVirt SNP VM (IGVM), serial console | ✅ **live & green** (flagship) | — in production | this doc + `c8s-e2e/DESIGN.md` |
| **`tdx-metal`** | `cvm-launcher-tdx` / `tdx-dev-host-1` | KubeVirt TDX VM (TDVF/QGS) | 📐 hardware provisioned, not wired | ARC scale set + `tdx-image-refs` + a TDX RKE2-node image (the long pole) | `baremetal/DESIGN-tdx-metal.md` |
| **`gke-snp`** | GitHub-hosted → provisions GKE | Confidential GKE nodes **are** the CVMs (no console; apiserver directly reachable) | 📐 designed, proven once (cifrai era) | a separate `gke-e2e.yml` + WIF + the c8s-fleet `gke_provisioner` seam | `e2e/DESIGN-gke-snp.md` |
| **`gke-tdx`** | GitHub-hosted → GKE (C3) | Confidential GKE TDX nodes | 📝 notes | TDX provisioning config; confirm attestation-rs `gcp-tdx` verify path; quota | `e2e/DESIGN-gke-snp.md` (notes) |
| **Azure** (SNP/TDX) | GitHub-hosted → AKS / CVM | Azure CVM (SNP `DCas_v5` / TDX `DCes_v5`) + vTPM | 📝 notes | c8s-fleet `aks_provisioner` wiring; **uniquely runs the `az_*_live` tests** (needs Azure vTPM + IMDS) | `baremetal/DESIGN-tdx-metal.md` (notes) |

**Boot model differs by surface — and it shapes the transport.** On metal the guest
is a KubeVirt VM reached over the serial console (the CIDR collision blocks the pod
network). In cloud the **nodes themselves are confidential VMs**, the apiserver is
directly reachable, and there is no console at all — which is the second reason the
in-guest HTTP agent (primitive v2, §9) matters: it's the only transport that works
on both surfaces.

**Golden measurement per surface:** on metal **we own the IGVM**, so the runtime
launch measurement is ours to compute and enforce (done — `snp-metal` pins it). In
cloud the launch measurement is provider-managed, so those cells verify by **policy**
(valid VCEK/quote, debug off, TCB floor) rather than a pinned digest.

**Sequencing (decided):** build the non-metal cells only after the triggers +
consumers land on `snp-metal`; the designs exist now so a cell is a wiring task,
not a redesign. TDX-metal is closest (hardware ready); Azure earns its slot by
being the only place the Azure-specific attestation tests can run.

---

## 4. How the flagship lane works

`e2e-c8s.yml` (the c8s consumer) on every trigger:

1. **Build the payload** (GitHub-hosted) — package the c8s chart **from source** at the exact sha under test, resolve each component image tag, embed the install script.
2. **Boot a measured CVM** (primitive, on bare-metal SNP) — a fresh RKE2-node-as-CVM; assert genuine SEV-SNP + IGVM measured boot; self-discover the runtime launch measurement via configfs-tsm.
3. **Run the payload in-guest** — install that exact c8s commit in-cluster (rke2 helm-controller), pin CDS to the discovered measurement, and prove a confidential workload gets its CDS-issued cert.
4. **Tear down** (always) + reap any leaked CVMs from finished runs.

**Why install in-cluster over the serial console, not from the runner:** the host Cilium network and the in-CVM rke2 both use `10.42.0.0/16`, so the guest apiserver is unreachable from the runner (a CIDR collision). The payload is delivered once over the serial console and reports progress via `@@markers@@` polled host-side.

**Why the workload-cert step is the real test:** under `MEAS_ENFORCED`, CDS only issues that cert if the node attests the pinned measurement. So "the workload got its cert" *is* the attestation assertion — not a separate check.

---

## 5. What's built and proven

| Piece | State | Evidence |
|---|---|---|
| The primitive (boot/attest/payload/teardown/reap) | ✅ green | many runs |
| Flagship c8s lane, measurement-enforced | ✅ green | run 29474257566 — tested a sha with **no published chart or image tags**, end-to-end with `MEAS_ENFORCED` + `CERT_INJECTED` + `PAYLOAD_OK` |
| Nightly drift lane | ✅ green | scheduled run 2026-07-16 09:02 UTC |
| Golden-measurement enforcement | ✅ real | pinned to runtime value `15bc9953…`, warn-on-drift live |
| Zero credentials in the payload | ✅ | whole c8s pull chain is anonymously public |

**Runner:** label `cvm-launcher` (org ARC scale set, GitHub App id 4309649). Deliberately named — it is a host-side container that *launches* CVMs, **not** a TEE itself (proven with a `where-am-i` probe: `systemd-detect-virt=docker`, no `/dev/sev-guest`; the `sev_snp` cpuinfo flags are the host's capability leaking in). Only the payload runs in the TEE.

---

## 6. The consumers (three open PRs)

| PR | What it adds | Pre-merge verification |
|---|---|---|
| [kettle #51](https://github.com/confidential-dot-ai/kettle/pull/51) | Merge → kettle CLI (built from HEAD) verifies a live attested build fail-closed (signature, SLSA provenance, checksums, nonce, + launch-measurement/dm-verity bind). Runs on `ubuntu-latest` — the TEE is the remote orchestrator's CVM. | **Rehearsal green** (run 29478952315) |
| [attestation-rs #63](https://github.com/confidential-dot-ai/attestation-rs/pull/63) | Merge → the library's own test suite runs **inside a real SNP CVM** against `/dev/sev-guest` + configfs-tsm, including the `#[ignore]`d TEE tests + live DCAP. | **Rehearsal green — 263/263 tests passed inside the CVM** (run 29480502992) |
| [c8s #83](https://github.com/confidential-dot-ai/c8s/pull/83) | Merge → "push to c8s main → test cluster in a CVM → e2e → issues surfaced" via a post-merge `workflow_run` off Docker (the `kata-guest-base` precedent). | Underlying pipeline green ×3; trigger only fires post-merge |

**Pre-merge rehearsals:** because GitHub can't dispatch a workflow that isn't yet on a repo's default branch, we added dispatchable rehearsal workflows in `confidential-ci` that run each PR branch's exact jobs. They proved both lanes end-to-end *before* merge and caught four real issues (two nextest-invocation bugs; two one-time package-permission steps now documented in PR #63). The rehearsal workflows are deleted once the PRs merge.

---

## 7. Hard-won findings

- **Both c8s publish workflows are path-gated.** `chart.yml` (on `internal/helmchart/**`) and `docker.yml` (on source paths) skip commits that don't touch their paths — so a given merge sha often has **no chart tag and no image tags of its own**. Fix: package the chart from the source tarball at the exact sha (inlined via HelmChart `chartContent`); resolve each image to the newest existing sha tag ≤ the commit (ancestry walk). This is what makes the lane self-sufficient.
- **The image manifest's `snp_launch_digest` is NOT the runtime launch measurement** (it's computed under different boot assumptions — wrong twice, caused `403 measurement_denied`). The authoritative value is what the node reports at runtime via configfs-tsm (`/sys/kernel/config/tsm/report` → `outblob`, MEASUREMENT at offset 0x90). The primitive self-discovers it and pins CDS to it.
- **`base-cpu` image is console-dead** (silent after the EFI stub, no autologin) — unusable for console-delivered payloads. TEE payloads ride the `rke2-node` flavor for now (same genuine measured SNP guest, proven console); base-cpu returns with a base-image fix or the agent transport.
- **Secret hygiene:** anything typed over the serial console lands in `guest-console-log` + the Actions log. The flagship lane now carries **no credentials at all**; consumers pull test artifacts anonymously from public ghcr packages.

---

## 8. What we learned from prior art

Deep-read of three repos that solved adjacent problems:

- **NVIDIA/aicr** → gave the primitive its mechanics: out-of-band driver delivery + `@@marker@@` progress, reap-before-provision gated on live run status, run-metadata labels on every resource. Their evidence bundle is *signer-identity*-bound, not *hardware*-bound — binding the SNP launch measurement into evidence is exactly the physicality proof they lack (**our moat**).
- **NVIDIA/k8s-test-infra** → validated our choices (out-of-band node access and bash-over-ginkgo are industry norm) and taught **"prove consumption, not registration"** — don't stop at "CDS is up"; schedule the confidential workload and require its cert. That assertion caught the golden-measurement bug.
- **[kettle-orchestrator](https://github.com/confidential-dot-ai/kettle-orchestrator)** → the transport endgame: an **in-guest HTTP agent** (job spec as JSON POST, progress as SSE, results as a tarball) that demotes the console to boot-logs-only and keeps secrets off it entirely. This is the designated **primitive v2** — it deletes the flakiest machinery and is the only viable transport for cloud lanes (which have no console). See [`research/guest-transport.md`](https://github.com/confidential-dot-ai/confidential-ci/blob/main/research/guest-transport.md).

---

## 9. Roadmap

| Phase | Scope | State |
|---|---|---|
| 0 | Stabilize flagship lane (self-sufficient chart+image resolution, forensics) | ✅ done, green incl. nightly |
| 1a | kettle roundtrip consumer | ⏳ PR #51 open (rehearsal green) |
| 1b | attestation-rs suite-in-CVM + the toolchain-less-guest vehicle | ⏳ PR #63 open (rehearsal green, 263/263) |
| 2 | c8s post-merge trigger — the immediacy unlock | ⏳ PR #83 open |
| 1b+ | kettle `bin/test-integration` in-CVM (copies the 1b vehicle) | after 1b |
| 3 | Platform matrix: gke-snp, tdx-metal, azure (designs written; TDX metal host exists) | designed, deferred |
| 4 | Hardening: golden fail-closed promotion, agent transport (primitive v2), ARC-in-CVM (`confidential-cvm`) | designed |

**Deliberately later — "run the whole workflow in a TEE" (`confidential-cvm`, ARC-in-CVM).** Not required by the goal: test fidelity needs the *system under test* in the TEE (it is), not the CI plumbing. Whole-workflow-in-TEE serves ergonomics + trusted-CI, and only becomes meaningful with attestation-gated runner registration (the CDS key-release path). It's the north star, not the next step.

---

## 10. Reference

- **Adopt the primitive:** [`USING-THE-PRIMITIVE.md`](https://github.com/confidential-dot-ai/confidential-ci/blob/main/USING-THE-PRIMITIVE.md) — ~15-line consumer contract, payload contract, flavors, trigger precedent.
- **Deep-dive design docs (in-repo):** [`c8s-e2e/DESIGN.md`](https://github.com/confidential-dot-ai/confidential-ci/blob/main/c8s-e2e/DESIGN.md) (architecture + NVIDIA lessons), [`attest/DESIGN.md`](https://github.com/confidential-dot-ai/confidential-ci/blob/main/attest/DESIGN.md), [`kettle-e2e/DESIGN.md`](https://github.com/confidential-dot-ai/confidential-ci/blob/main/kettle-e2e/DESIGN.md), [`conformance/DESIGN.md`](https://github.com/confidential-dot-ai/confidential-ci/blob/main/conformance/DESIGN.md), [`research/guest-transport.md`](https://github.com/confidential-dot-ai/confidential-ci/blob/main/research/guest-transport.md).
- **Hardware:** SNP metal host `sev-snp-gh-runner` (single node, KubeVirt); TDX metal host `tdx-dev-host-1` (provisioned, awaiting a scale set + images).
- **Key labels/ids:** runner `cvm-launcher`; GitHub App id 4309649; golden measurement `15bc9953…`.

*This page mirrors [`docs/confidential-ci-overview.md`](https://github.com/confidential-dot-ai/confidential-ci/blob/main/docs/confidential-ci-overview.md) in the repo, which is the version-controlled source of truth. Deep technical detail lives in the in-repo `DESIGN.md` files linked above.*
