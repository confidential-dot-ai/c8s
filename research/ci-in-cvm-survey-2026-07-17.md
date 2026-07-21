# Which org repos should get CI-in-CVM — survey (2026-07-17)

Classified 22 plausible-TEE repos (of ~55; docs/web/demos/ML-forks excluded up
front) by the only question that matters: **does its correctness need a real
TEE to prove — i.e. does hosted CI silently skip or fake a test the hardware
would run?** "Runs in a TEE in production" is NOT that.

## Headline: zero tier-1 left — and that's the right answer

The "lift an existing hardware-gated test" surface was **fully consumed by the
trio we already onboarded** — attestation-rs (`nextest --features attest` vs
/dev/sev-guest), kettle (vTPM `bin/test-integration`), c8s (install+attest+
enforce). No remaining repo has an `#[ignore]`/`--features attest` test binary
to merely un-skip. We didn't miss easy wins; we already took them.

## The real "do next": tier-2 measured-artifact boot-and-verify

Four repos each ship a **software-PREDICTED SNP launch digest that has never
been compared to what real silicon reports.** Same first-run-on-hardware ROI as
tier-1, but the lane must *boot the artifact and read its measurement*, not lift
a test. This is a NEW lane shape (`boot-and-verify`) — and it IS the
base-image→boot-c8s CD lane João asked for, now with concrete targets.

Ranked (all `snp-metal`, build→boot-under-SNP→assert hw-measurement == manifest):

1. **confidential-os-builder** — HIGHEST ROI: the measurement engine the other
   three inherit. `igvm-tools/measure_snp()` + `tdx-measure` reimplement SNP
   page-SHA384/VMSA and TDX MRTD/RTMR in software; tests only self-check.
   `pe.rs` documents an OVMF Authenticode-padding DEVIATION from the MS spec — a
   hand-coded silicon-vs-software mismatch a boot lane exists to catch. A bug
   here cascades to all of the below.
2. **base-images** — highest PRODUCT value: the shipping RKE2 L1 node image
   (disk.raw + guest-smp4.igvm + roothash + manifest digest), pushed to GHCR
   with NO boot step. Every downstream node attestation is anchored to that
   unverified digest. Boot also proves dm-verity root actually mounts.
3. **kata-containers** — fork's sole feature is IGVM measured-boot for QEMU SNP;
   the new `--cmdline`/UKI dm-verity-in-measured-cmdline logic is unproven on
   silicon; changed tests are host-only Go units.
4. **igvm-tools** — standalone SNP-measurement lib; README contract is
   "matches hardware attestation reports," unverifiable in hosted CI. Lower
   rank: substantially overlaps confidential-os-builder's vendored copy — only
   worth its own lane if the standalone repo diverges.

## Tier-3 (author a payload first; do after tier-2 is green)

- **containerd-conf-qemu** (`snp-metal`): confidential containerd+QEMU runtime;
  tests are deliberately hypervisor-free (MockVmm). Needs `steep` (private,
  STEEP_REPO_TOKEN) side-by-side to make a bootable image; the 16 REAL-QEMU
  properties are prose to encode. Anchor assertion = launch-measurement match.
- **confidential-cvm-cli** (`azure-cvm`, borderline): genuine in-TEE code
  (`tpm2_nvread 0x01400001` Azure HCL NV index — needs azure-cvm, KubeVirt lacks
  it) with two documented hardware-only bugs already caught. BUT crypto is
  delegated to attestation-cli (covered); distinctive value is only the full
  `ccvm verify` 5-check e2e, which needs a live inference gateway too. Medium
  confidence — could stay "none" if the gateway can't be stood up.

## none — 16 repos, do not revisit

attestation-go (verify-only offline fixtures; thin go-sev-guest shim + a
verifier-parity port of attestation-rs — RE-CONFIRMED 2026-07-21, see below),
TEErminator (client-side relying
party), rust-tss-esapi (upstream mirror, swtpm software TPM), confidential-metal
(control plane, digests computed outside the TEE), c8s-fleet (Flux YAML),
teefarm (orchestrator on a plain VM), kettle-orchestrator (untrusted host,
mocked launcher), c8s-operator (operator OUTSIDE the boundary, all mocks),
privateclaw + privateclaw-cli (SaaS/bash, crypto delegated), proxy-rs
(attestation is a TODO placeholder), confidential-agents (orchestrator),
tee-benchmarking (perf, disclaims security), c8s-verify-js (WASM client
verifier), denv (local docker), vllm-private (upstream mirror). Common thread:
control planes, client-side verifiers, mirrors, and orchestrators — all
correct-on-ubuntu-latest.

## RE-CONFIRMED NONE 2026-07-21 — attestation-go (raised again; settled)

Re-examined against the code, not just the classification, because it *looks*
like it might need a TEE: it has `GetReport` (SNP/TDX report generation) in
`attestation/snp/snp.go` + `attestation/tdx/tdx.go` and a `go-configfs-tsm` dep.
It does not need the rail:

- **Every test is offline fixture verification** (`//go:embed testdata/…` — reports
  captured once from real hardware, then verified in software). NO test calls
  `GetReport`, touches `/dev/sev-guest`, or is hardware-gated; CI is
  `runs-on: ubuntu-latest`, `go test ./...`.
- attestation-go is a **thin parameter-mapping shim over Google's
  `go-sev-guest`/`go-tdx-guest`** (snp.go header: *"delegated to go-sev-guest …
  mapping teetypes.VerifyParams onto go-sev-guest's verify/validate options"*)
  AND a **verifier-parity port of attestation-rs** (`PARITY.md`, "Go ↔ Rust
  **verifier** parity", audited check-by-check vs attestation-rs `e967531`). Both
  `Verify` and `GetReport` delegate down to the Google libs.
- So a CVM would re-test Google's (already-tested) library + a mapping shim that
  the offline fixtures already cover. Near-zero new signal. A port DOES need its
  own tests (the Rust tests execute Rust, never the Go shim; parity-by-audit
  drifts) — but it HAS them, offline, which is the right coverage for a verifier
  shim and needs no CVM.
- The attestation-rs tests that genuinely needed the rail (`attest_endpoint`,
  `attest_then_verify_roundtrip`, `az_*_live`) are **generation** tests (fetch a
  live report off the silicon) with **no attestation-go counterpart** — it's a
  verifier port. Do NOT port them here.

**Only flip:** an explicit *defense-in-depth-on-own-silicon* compliance
requirement (prove the whole Go generate→verify path on our hardware rather than
trusting go-sev-guest's tests transitively). That's a posture choice, not a
technical coverage gap — pursue only if stated as a requirement.

## Sequencing

Build the `snp-metal` **boot-and-verify** cell ONCE (same consumer shape for all
four): `build artifact → boot under SNP → read hw measurement in-guest →
assert == manifest digest`. Roll confidential-os-builder → base-images → kata →
igvm-tools through it. confidential-os-builder FIRST — a page-order/VMSA/padding
bug caught there fixes the whole inheritance chain. THEN the two tier-3 payloads.

Note vs the existing primitive: this needs a NEW adapter — boot a
caller-BUILT IGVM and check its measurement, vs today's primitive which boots
the pre-staged rke2 image. That's the one piece of net-new lane work.
