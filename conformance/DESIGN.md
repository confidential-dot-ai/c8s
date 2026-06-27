# Confidential conformance harness — design

> A CI harness that proves, on real hardware, *"this is a genuine TEE running what
> we expect"* — across **both** confidential backends the product spans. **Real
> only, never simulated.** Built KubeVirt-first because that's what we have access
> to today (`sev-snp-gh-runner`).

## Why two backends (forced by hardware, not preference)

| Backend | Where | Confidential unit | Status |
|---|---|---|---|
| **KubeVirt / VM** | cloud (GCP, Azure) + bare-metal VMs | the **VM** is the CVM (launchSecurity.snp / confidential node) | **have it** (`snp-e2e`, `multi-cvm-attest`) |
| **kata / pod** | bare-metal (c8s) | the **pod** is the CVM (`kata-qemu-snp`) | P1 (kata role on our node) |

On cloud you get the provider's confidential VM and **can't nest `kata-qemu-snp`
inside it** (nested SNP is unsupported) → the VM is the unit. On bare-metal you own
the host, install kata → the pod is the unit. Same finding (no nested SNP), opposite
conclusions per environment. The product runs both, so the harness must test both.

## Architecture: one assertion layer, swappable launch adapter

```
            ┌──────────── common, backend-agnostic ────────────┐
ARC job ──▶ │ orchestrate (Lease: serialize the SNP node)       │
            │ ── launch(spec) ──▶  [ADAPTER]                     │ ◀── the only seam
            │ attest(cvm)  → attestation-rs/go verify           │
            │ assert conformance (below)  → fail-closed         │
            │ teardown (always; per-run isolation)              │
            └───────────────────────────────────────────────────┘
   ADAPTER = KubeVirt SNP VM  (P0)  |  kata-qemu-snp pod (P1)  |  cloud CVM (later)
```

Only `launch(spec)` / `teardown` differ per backend. Everything else — the
attestation engine, the conformance assertions, ARC orchestration, the `Lease`,
guaranteed teardown, per-run unique naming — is shared.

## Conformance assertions (common, what "genuine TEE" means)
- hardware signature valid (AMD/Intel vendor chain);
- `report_data` == our fresh nonce (freshness);
- launch measurement bound to the expected image (when we have a golden);
- debug disabled;
- (c8s, later) digest-allowlist enforced inside the CVM; CDS-as-TEE; RA-TLS mesh.

Asserted by the same `attestation-rs/go` engine everything else already uses.

## Design principles (from k8s CI + the single-binary thread)
- **Real only** — no non-confidential simulation, ever. (Both backends are real SNP.)
- **Minimal infra** — ARC (have it) + a self-contained conformance binary/script +
  a `Lease`. No Prow/Argo/Tekton/Jenkins. The test *is* the binary; ARC triggers it.
- **Short-lived, self-cleaning jobs; no long-running controller; minimal CRDs.**
- **Serialize the scarce resource** — one SNP node, KDS-429 limits → a `Lease`
  (Boskos-lite) so runs don't collide with each other or the ARC runners.
- **Provision ≠ run** — the launch adapter provisions CVMs; the suite just asserts.

## Phases
| Phase | Scope | Substrate |
|---|---|---|
| **P0** | KubeVirt adapter + the common harness — launch N SNP VMs, attest each, conformance, `Lease`, guaranteed teardown | `sev-snp-gh-runner` (have it now) |
| **P1** | kata adapter — `kata-qemu-snp` pods (the bare-metal c8s runtime) | our node + kata role |
| **P2** | c8s components on the kata adapter (cds/get-cert/policy-monitor) + per-component conformance | bare-metal kata |
| **later** | cloud KubeVirt adapter (GCP/Azure) — needs its own scoping (vTPM/TDX measurement model) | cloud |

## P0 — concrete (build now, KubeVirt, on our host)
Build on what's green (`multi-cvm-attest`):
1. **Common harness skeleton** with the `launch/attest/assert/teardown` seam (so P1 kata slots in without rework) — kept simple, not a heavyweight abstraction.
2. **KubeVirt adapter:** parameterized launch of N SNP VMs (per-run CDI clones, unique names) from a spec `(count, image)` — "the CVMs could be anything" via the image field; today the base attestation-api image.
3. **`Lease`** on the SNP node so concurrent runs serialize (and don't fight the ARC runners).
4. **Guaranteed teardown** (trap/`if: always()`), per-run isolation.
5. Run as an **ARC job** on `confidential-bm` (`sev-snp-gh-runner`).

Net: P0 turns our proven `multi-cvm-attest` into the reusable, backend-pluggable
conformance harness — KubeVirt first, kata and cloud as later adapters under the
same assertions.
