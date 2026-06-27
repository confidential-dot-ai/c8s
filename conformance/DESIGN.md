# Confidential conformance harness — design

> **P0 BUILT & GREEN (2026-06-27).** `confidential-conformance.yml` on
> `confidential-bm` spun **3 SEV-SNP CVMs from one CI job** (per-run CDI clones) and
> verified each is a genuine, fresh, non-debug TEE — `platform=snp`,
> `signature_valid`, `report_data_match`, `debug_allowed:false` — **fail-closed**,
> then tore them all down (cluster verified clean, no leftovers). Run
> `28301387338`. This is proof point #1 (multi-CVM-from-CI), now a reusable harness.

> **Thesis: the host we have access to *today* (`sev-snp-gh-runner`) can test *all*
> of c8s — using KubeVirt SNP VMs, deferring kata until the one test that truly
> requires it.** Two proof points:
>
> 1. **We can spin multiple CVMs from CI.** `multi-cvm-attest` already launches N
>    SEV-SNP VMs on this host and attests each, fail-closed (green). That's the
>    multi-CVM-from-CI capability, proven.
> 2. **We can run c8s itself node-as-CVM** inside a KubeVirt SNP VM (no kata) —
>    which covers ~all of c8s's surface (bring-up, CDS-as-TEE, identity, host-side
>    digest-allowlist enforcement, mesh, node attestation).
>
> **Real only, never simulated. KubeVirt all the way until the test** — kata enters
> only for the single bare-metal-specific case (per-pod-as-its-own-CVM enforcement),
> and not before.

## Why KubeVirt tests almost all of c8s — the two c8s deployment models

c8s ships in **two** shapes, and **kata is only one of them**:

- **node-as-CVM** (cloud model): the **node** is a confidential VM; c8s components
  run as ordinary (runc) pods inside it; `nri-image-policy` enforces the digest
  allowlist **host-side** (and "host" *is* the confidential node); CDS runs as a
  plain pod and attests because the node *is* an SNP guest (`/dev/sev-guest`).
  **No kata.** → we get this with a **KubeVirt SNP VM as the node**.
- **pod-as-CVM** (bare-metal model): each pod is its own `kata-qemu-snp` CVM;
  `policy-monitor` enforces *inside each guest*. **This is the only part needing kata.**

So on **KubeVirt SNP VMs, with no kata**, we can test almost the whole grid:

| c8s capability | KubeVirt / node-as-CVM (no kata) |
|---|---|
| bring-up (operator / CDS / webhook / CRD) | ✅ |
| CDS = genuine TEE | ✅ (node is an SNP guest) |
| workload identity / cert issuance | ✅ |
| **digest-allowlist enforcement** | ✅ host-side `nri-image-policy`, inside the confidential node |
| RA-TLS mesh | ✅ host-side `ratls-mesh` |
| node attestation | ✅ (the VM's SNP report) |
| **per-pod-as-its-own-CVM enforcement** (in-guest `policy-monitor` SIGKILL) | ❌ **kata-only — deferred to last** |

It's real confidentiality (the node is a genuine SNP VM), and node-as-CVM is c8s's
actual **cloud** deployment — not a simulation.

## Why both backends exist at all (hardware-forced)
| Backend | Where | Confidential unit | Status |
|---|---|---|---|
| **KubeVirt / VM** | cloud (GCP, Azure) + bare-metal VMs | the **VM**/node is the CVM | **have it** (`snp-e2e`, `multi-cvm-attest`) |
| **kata / pod** | bare-metal (c8s pod-as-CVM) | each **pod** is the CVM (`kata-qemu-snp`) | **last** (kata role on our node) |

You can't nest `kata-qemu-snp` inside a cloud confidential VM (nested SNP is
unsupported) → cloud is VM-based; bare-metal you own the host → pod-based. Same
finding, opposite conclusions per environment.

## Architecture: one assertion layer, swappable launch adapter

```
            ┌──────────── common, backend-agnostic ────────────┐
ARC job ──▶ │ orchestrate (Lease: serialize the SNP node)       │
            │ ── launch(spec) ──▶  [ADAPTER]                     │ ◀── the only seam
            │ attest(cvm)  → attestation-rs/go verify           │
            │ assert conformance (below)  → fail-closed         │
            │ teardown (always; per-run isolation)              │
            └───────────────────────────────────────────────────┘
   ADAPTER = KubeVirt SNP VM (P0/P1)   |   kata-qemu-snp pod (LAST)   |   cloud CVM (later)
```

Only `launch(spec)` / `teardown` differ per backend. The attestation engine, the
conformance assertions, ARC orchestration, the `Lease`, guaranteed teardown, and
per-run unique naming are all shared.

## Conformance assertions (common, what "genuine TEE" means)
- hardware signature valid (AMD/Intel vendor chain);
- `report_data` == our fresh nonce (freshness);
- launch measurement bound to the expected image (when we have a golden);
- debug disabled;
- (c8s) digest-allowlist enforced; CDS-as-TEE; RA-TLS mesh; node attestation.

Asserted by the same `attestation-rs/go` engine everything else already uses.

## Design principles (from k8s CI + the single-binary thread)
- **Real only** — no non-confidential simulation, ever. Both backends are real SNP.
- **KubeVirt until the test** — defer kata to the single pod-as-CVM case; everything
  else uses KubeVirt SNP VMs on the host we already have.
- **Minimal infra** — ARC (have it) + a self-contained conformance binary/script +
  a `Lease`. No Prow/Argo/Tekton/Jenkins. The test *is* the binary; ARC triggers it.
- **Short-lived, self-cleaning jobs; no long-running controller; minimal CRDs.**
- **Serialize the scarce resource** — one SNP node, KDS-429 limits → a `Lease`
  (Boskos-lite) so runs don't collide with each other or the ARC runners.
- **Provision ≠ run** — the launch adapter provisions CVMs; the suite just asserts.

## Phases — KubeVirt first, kata last
| Phase | Scope | kata? | Substrate |
|---|---|---|---|
| **P0 ✅ DONE** | KubeVirt spine + the common harness — **spin N SNP VMs from CI**, attest each, conformance, serialize (concurrency group), guaranteed teardown — `confidential-conformance.yml`, green at N=3 | no | `sev-snp-gh-runner` (have it now) |
| **P1** | **c8s node-as-CVM** in a KubeVirt SNP VM — bring-up + CDS-as-TEE + identity + **host-side allowlist enforcement** + mesh + node attestation (~all of c8s) | **no** | same host |
| **LAST** | the one kata-only thing: **per-pod-as-CVM** enforcement (in-guest `policy-monitor`) | yes | our node + kata role |
| **later** | cloud KubeVirt adapter (GCP/Azure) — own scoping (vTPM/TDX measurement model) | no | cloud |

## P0 — concrete ✅ DONE (KubeVirt, on the host we have)
Shipped as `confidential-conformance.yml` (in `cifrai/confidential-bm-smoke` +
mirrored to `baremetal/`). Built on `multi-cvm-attest`; green at N=3 (run
`28301387338`): 3 SEV-SNP CVMs spun from one CI job, each verified fail-closed, all
torn down, cluster clean. `launch`/`teardown` are the KubeVirt seam; `attest+assert`
is backend-agnostic (consumes name+IP), ready for the kata adapter to swap in.
What it does:
1. **Common harness skeleton** with the `launch/attest/assert/teardown` seam (so the
   kata adapter slots in later without rework) — simple, not a heavyweight abstraction.
2. **KubeVirt adapter:** parameterized launch of N SNP VMs (per-run CDI clones,
   unique names) from a spec `(count, image)` — "the CVMs could be anything" via the
   image field; today the base attestation-api image, later a c8s node image (P1).
3. **`Lease`** on the SNP node so concurrent runs serialize (and don't fight the runners).
4. **Guaranteed teardown** (`if: always()`), per-run isolation.
5. Run as an **ARC job** on `confidential-bm` (`sev-snp-gh-runner`).

Net: P0 turns our proven `multi-cvm-attest` into the reusable conformance harness —
**proving this host can spin multiple CVMs from CI** — and P1 runs c8s node-as-CVM on
top of it, getting us to "this host tests ~all of c8s" with **zero kata** until the
final pod-as-CVM test.
