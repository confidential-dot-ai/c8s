# In-guest attestation — design (scope #4)

> **Status: Phase-1 evidence flow VERIFIED LIVE (2026-06-26); not yet wired into
> CI.** Big finding: the full attestation flow already exists in the company's
> `confai` CLI — we **integrate it, not rebuild**. We pulled a real, nonce-bound
> SEV-SNP report from the confidential guest end-to-end (details below).

## Phase 1 — what we found (verified live on `github-runner-dev`)

The earlier "we'll bake our own attester" plan is **moot** — the bare-metal base
image and `confai` already implement RATS end-to-end:

- **Attester is in the guest, on by default.** `base-cpu-image` runs
  `attestation-api` on **:8400**; `POST /attest` with `{"report_data":
  "<base64(32-byte nonce)>"}` returns `{"platform":"snp","evidence":
  {"attestation_report":"…"}}`. Verified live: **HTTP 200, 1653-byte SNP report,
  with our nonce embedded in `report_data`** (freshness proven). No base-image
  change needed.
- **Verifier exists:** `confai verify --vm <name> --image-dir <dir> --smp N`
  (`pkg/confai/verify.go` `VerifyLive`): computes the expected launch digest
  (`confai measure`), resolves the VM's LB IP, generates a nonce, POSTs `/attest`,
  shells out to `attestation-cli verify` (attestation-rs) for signature + report_data,
  then asserts `claims.launch_digest == expected`. Offline variant compares an
  IGVM file's digest instead.
- **Golden measurement exists:** `confai measure --smp N <image-dir>` — so the
  reference value is computed from source, not pinned.

So **Phase 1 = wire `confai verify` into `snp-e2e`, fail closed on `!Pass`.** What
remains (all mechanical):
1. `confai` + `attestation-cli` on the runner — `make` in `cmd/confai` (clones
   steep + attestation-rs, `cargo build --features attest`; Linux + libtss2 — the
   bm runner has these). Build in-job first; bake into the runner image later (#7).
2. **Network path runner → guest `/attest`.** The runner's egress policy (#6)
   blocks east-west, and our bare VM has only a pod IP. Use `confai launch` (it
   creates the LB service `VerifyLive` resolves) and allow the runner egress to
   that LB IP — or run the verify step from a `confai-images` Job.
3. **`--image-dir` / golden digest** — the base rootfs dir for `confai measure`
   (or the offline `--igvm` variant against `igvm-files`).

Decisions from below, now settled by this finding: **#1 (bm attester tooling)** —
already in the base image, don't bake our own. **#3 (verifier)** — use
`attestation-cli`/`confai verify` in-step (CDS later). **#2 (gcp)** still open (Phase 2).

---

> Historical scope (pre-finding) below — kept for the gcp/azure phases and the
> general RATS framing.

## The gap, precisely

Today both E2E paths assert the *platform*, not the *workload's TEE*:

- bm `baremetal/snp-e2e.yml`: greps the launcher's qemu cmdline for `sev-snp-guest`.
- gcp `e2e/run.sh`: confirms the node is a Confidential GKE node.

Neither proves the CI workload ran inside a **genuine, measured, non-debug** TEE
with a **known measurement**. That requires a hardware-rooted quote/report, bound
to a fresh nonce, and **verified** against reference values — the RATS loop
(Attester → Evidence → Verifier → Reference values). This is the capability that
makes confidential-ci more than "ARC on confidential nodes."

## Definition of done

Each backend's E2E:

1. issues a per-run **nonce**;
2. has the workload (inside the TEE) produce **evidence** — an SNP/TDX report with
   `report_data = H(nonce ‖ ephemeral_pubkey)`;
3. **verifies** that evidence with `attestation-go` (`teeverify.Verify`) /
   `attestation-rs`: signature → AMD/Intel root, measurement == reference value,
   `report_data` match, policy (debug off, TCB floor);
4. **fails closed** on any mismatch;
5. emits the **verified claims** as a run artifact + step summary.

## The flow (one shared module, per-backend evidence source)

```
CI step (verifier)               inside the TEE (attester)
  nonce ───────────────────────▶ get report, report_data = H(nonce‖pubkey)
        ◀─────────────────────── evidence (SNP/TDX report + cert chain)
  teeverify.Verify(evidence, {ExpectedReportData, refValues, policy})
        └─ sig→VCEK/PCS root · measurement==golden · report_data==H(nonce‖pk)
           · debug=0 · TCB≥floor
  pass → emit claims | fail → exit 1
```

The `report_data = H(nonce ‖ pubkey)` binding does double duty: nonce gives
**freshness** (anti-replay), and binding the **pubkey** proves "this fresh key
lives inside a genuine TEE measured as X" — which is what later lets CDS **release
a secret/registration token** to the attested guest (the on-ramp to the
attestable-runner north-star, see `../MULTI-BACKEND.md` / improvement #14).

## Evidence acquisition — the hard part, differs per backend

| Backend | How the report is produced | Reference value (golden measurement) | Difficulty |
|---|---|---|---|
| **confidential-bm** (KubeVirt SNP VM) | inside the guest: `configfs-tsm` (`/sys/kernel/config/tsm/report`) or `snpguest` / attestation-rs CLI, `report_data=nonce` | **we control the IGVM** → the launch `MEASUREMENT` is computable from `guest-smpN.igvm` (`sev-snp-measure`). Golden value is ours. | **lowest — do first** |
| **confidential-gcp** (Confidential GKE node) | privileged pod with `/dev/sev-guest` (or configfs-tsm host mount) → SNP/TDX report; verify with attestation-go | node launch measurement is **GCP-managed** — pin it, or policy-only (valid VCEK + debug off + TCB floor + our workload RTMR/PCR) | medium |
| **confidential-azure** (future) | `/dev/sev-guest` on the CVM, or Microsoft Azure Attestation (MAA) signed token | MAA reference values / pinned image measurement | design-only |

**Key scoping insight:** start with **bm** — it's the only backend where we own
the measured boot (the IGVM), so we have a true golden measurement and can do full
appraisal, not just policy.

## Critical-path dependency

The in-guest attester (the report tool) must live **inside the confidential image**:

- **bm:** the verity-immutable `confidential-dot-ai/base-cpu-image` must ship
  `configfs-tsm` / `snpguest` (or our attestation-rs CLI). Either coordinate with
  the bare-metal owners (Ameen) to add it, or we bake a minimal attester image.
  **This is the gating decision for Phase 1** — the rootfs is verity-immutable and
  has no cloud-init, so the tool has to be baked, not installed at boot.
- **gcp:** ship the attester as a privileged DaemonSet/pod — no base-image change.

## Verifier placement

- **Phase 1 (in-step):** the runner runs `teeverify` / attestation-rs on the
  evidence. Self-contained, fast to prove. (Verifier binary baked into the runner
  image — ties to improvement #7.)
- **Production (CDS):** verify via the company's **CDS** key-broker so policy is
  centralized and you get **key release on success**. `report_data`'s pubkey
  binding is exactly what lets CDS release a secret/registration token to the
  attested guest — and the on-ramp to the attestable runner (#14).

## Where it slots in

A shared `confidential-ci/attest/` (to be built — not present yet):

- `attest/verify.sh` — nonce → collect evidence (backend-pluggable) → `teeverify`
  → fail-closed → emit claims.
- `attest/refvals/{bm,gcp}.json` — per-backend reference values + appraisal policy
  (debug=false, TCB floor, expected measurement / allow-list, report_data freshness).
- bm `baremetal/snp-e2e.yml` calls it after `VMI Running`; gcp `e2e/run.sh` calls
  it after the probe pod is up. Same script, different `refvals` + evidence source.

## Fail-closed / edge cases

Default deny. Fail the run on: bad signature, measurement mismatch, stale/replayed
nonce, `debug=1`, TCB < floor, or missing evidence. Notes:

- Cert-chain fetch (AMD **KDS** / Intel **PCS**) needs egress — the #7
  NetworkPolicy must allowlist those hosts.
- Pin a TCB/SVN **floor** and plan for TCB-update bumps (rollback protection).
- Nonce is per-run, short-TTL.

## Phased plan (within #4)

| Phase | Scope | Notes / effort |
|---|---|---|
| **P1** | bm, in-step, **full appraisal** vs golden IGVM measurement | flagship slice; **gated on the base-image attester tool**; ~2-4 days |
| **P2** | gcp, in-step, **policy-based** (privileged attester pod) | ~3-5 days |
| **P3** | **CDS** verification + `report_data`→key release | sets up #14; larger |
| **P4** | azure | when the backend exists |

## Decisions needed before any build starts

1. **bm attester tooling:** add the SNP report tool to `base-cpu-image`
   (coordinate w/ Ameen) **or** bake our own minimal attester? (P1 is gated on this.)
2. **gcp model:** Confidential GKE **Nodes** (raw report — what we provision today)
   vs **Confidential Space** (signed JWT token — easier verify, different
   provisioning model)?
3. **Verifier:** in-step `teeverify` first (recommended) or go straight to **CDS**?

**Recommendation:** P1 on bm with in-step `attestation-rs` verify against the
golden IGVM measurement, baking the attester into our own image so we're not
blocked on the base-image change — then generalize to gcp, then CDS.
