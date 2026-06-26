# Research: kettle, kettle-orchestrator, c8s

Read-only research pass over the three product repos now under `~/dev/conf/`,
and how they relate to the confidential-CI work in this repo. As of: kettle
`80e0358`, kettle-orchestrator `0fda2d0`, c8s `7df6f40` (≈2026-06-26).

## TL;DR — one trust spine, three products

All three sit on the same primitive: **TEE remote attestation** (AMD SEV-SNP /
Intel TDX) via the `attestation-rs` / `attestation-api` stack (the `/attest`
endpoint + `attestation-cli verify` we already use).

| Repo | Lang | Role |
|---|---|---|
| **kettle** | Rust (336 `.rs`) | Attested-build *tool* — builds + signs SLSA provenance inside a TEE |
| **kettle-orchestrator** | Rust + React | The *service* that drives CVMs to run kettle builds (build-as-a-service) |
| **c8s** | Go (200 `.go`) | Confidential **Kubernetes** — attested runtime: CDS, RA-TLS mesh, digest policy |

The hand-drawn architecture in the planning notes *is* c8s.

---

## kettle — attested builds (Rust)

**What:** builds + verifies "attested builds" — output packages carrying
cryptographically signed SLSA provenance that certifies the source, dependencies,
toolchain, and machine. The pitch vs GitHub artifact attestations: hardware-rooted,
so you trust the chip vendor + the physical custodian, not the CI provider's word.

**Build flow** (`docs/2-how-it-works.md`) — 3 phases, 2 environments:
1. **Dev machine — manifest creation.** Hash source + deps + toolchain → a
   **manifest → Merkle root**.
2. **TEE — build execution.** The manifest + source archive go into a TEE; the
   build runs there.
3. **TEE — provenance signing.** A hardware attestation signs the provenance
   (report_data binds the manifest/provenance hash). Verification re-derives the
   Merkle root and checks the signature against the manufacturer cert chain,
   closing source → binary.

**Interfaces (two):** the `kettle` CLI (`build` / `verify`) and `kettle-server`
(HTTP). Other bins: `remote-build`, `kettle-build-repo`, `image-build/push`,
`build-reproducible`. **Toolchains:** cargo / nix / pnpm.

**Attestation deps** are vendored as crates: `az-cvm-vtpm`, `tss-esapi(-sys)`,
`igvm-tools` — the same stack `attestation-cli` links (hence the `libtss2`
runtime dependency we hit). `--features attest` gates the in-TEE *signing* path;
*verify* is the default build. Docs: `1-attested-builds.md`, `2-how-it-works.md`,
`3-provenance-standards.md` (SLSA), `4-threat-model.md`.

## kettle-orchestrator — CVM build service (Rust + React)

**What:** manages Confidential VMs that run kettle attested builds. The SaaS form
of "spin a CVM → run a build → return signed output."

**Backend** (`src/`): `qemu.rs` + `bin/qemu-system-x86_64` (drives QEMU directly),
`slot.rs` (numbered **CVM slots**, `slot_index`), `job.rs` (build jobs scheduled
into slots), `driver.rs`, `proxy.rs`, `api.rs`, `manifest.rs`, `cleanup.rs`,
`image_config.rs`. **Frontend:** React (96 files) dashboard. This is the
concrete "kettle e2e roundtrip: run a build in a CVM, output of that build" loop
from the notes — the productized version of what our `snp-e2e` prototype does.

---

## c8s — confidential Kubernetes (Go) — the flagship

"Confidential computing infrastructure for Kubernetes: TEE attestation,
certificate management, RA-TLS mesh networking, and container image policy
enforcement." The planning-notes diagram maps 1:1 onto these components.

### Components (`cmd/`)
- **CDS** (`cmd/cds`) — **Certificate Distribution Service**, the trust root,
  itself a CVM. One **challenge → attest → certify** call
  (`pkg/attestclient`): verifies TEE evidence, issues **EAR** tokens (Entity
  Attestation Result, ES256 JWT — `internal/ear`, `pkg/earsigner` w/ JWKS +
  rotation), and **signs workload CSRs** with an in-process **mesh CA**
  (`internal/issuer`). `CertificateResult` = the PEM chain + the challenge /
  platform / evidence that authorized it. Callers MUST reach CDS over an
  RA-TLS-verified transport.
- **get-cert** (`cmd/get-cert`) — CLI + **init-container** injected into opted-in
  pods; generates an ECDSA P-256 key + CSR and runs the attest→cert flow so each
  workload gets a leaf cert via CDS.
- **ratls-mesh** (`cmd/ratls-mesh`) — node **DaemonSet**, a **transparent L4 TCP
  proxy** that wraps pod-to-pod traffic in **RA-TLS** (hardware-attested mTLS);
  apps need zero changes. Excludes `kube-system` + the release namespace as
  sources (one-sided — see operator.md for the pod-IP-bypass caveat).
- **nri-image-policy** (`cmd/nri-image-policy`) + **policy-monitor**
  (`cmd/policy-monitor`) — **digest-allowlist enforcement** (the "only allowed
  digests can run" scenario). kata-agent's OPA is permissive on
  CreateContainerRequest, so an **in-VM `policy-monitor`** watches kata-agent's
  container-bundle dir via inotify, reads each container's OCI image digest, and
  **SIGKILLs the init PID if the digest isn't allowlisted**. Allowlist =
  **baked seed** (`/etc/c8s/bootstrap-allowlist.json`, on the dm-verity root →
  part of the SNP launch measurement → enforces from t=0, no network) **+ CDS
  refresh** over RA-TLS (pinned to `cds.measurements`), **merge-only-grows** (a
  compromised/unreachable CDS degrades to "stale, never open").

### Operator + workloads
- `cmd/c8s operator` runs the controller-runtime manager, the
  **ConfidentialWorkload** (`api/v1alpha2`) status-mirror controller, and a
  **pod-injection admission webhook** (`internal/webhook`) that injects the
  get-cert init-container.
- `cmd/c8s install` extracts the embedded Helm chart (`internal/helmchart/c8s`)
  and `helm upgrade --install`s the operator, CRDs, RBAC, webhook,
  attestation-api DaemonSet, and CDS. Platform-admin op; workloads then opt in
  with the `confidential.ai/cw` annotation.
- **kata-guest-base** — the measured guest image: osbuilder dm-verity **erofs**,
  verity root hash in the kata kernel cmdline (no IGVM/UKI — a *different
  measurement model* than the bare-metal box we have, which is IGVM-measured).

### Allowlist + storage
`internal/allowlist` (handlers + SQLite store), `internal/cache` (NRI cache),
`internal/audit` (policy audit log), `internal/containerd` (tag→digest resolver).
Client libs: `pkg/allowlistclient`, `pkg/allowlist`.

### Known gaps (`docs/GAPS.md`) — useful for "what to test / where to help"
- CDS is a **singleton with the CA key in memory**; active/active handoff off by
  default; **not HA** by default (#18, #75).
- **Application-secret release not implemented** (#46) — the "release a secret to
  an attested workload" story isn't there yet.
- **Per-workload measurement allowlists not enforced at `/attest`** (#57) — a real
  testable edge.
- Leaf certs **don't embed a verified TEE measurement**; mesh **doesn't pin peer
  measurement**; no SPIFFE URI SANs; strict/permissive mTLS not configurable;
  per-workload `allowedPeers` not enforced (#47).
- NRI gates **image digest only** — not args/env/mounts/caps (#49).
- c8s infra images not pinned into NRI policy by default (#51).
- No multi-tenancy isolation design (#56).
- Browser/out-of-cluster verification exists behind a flag (`tlsLb.attest.enabled`):
  `/.well-known/c8s/attestation`, a post-quantum over-encryption channel
  (`pkg/overenc`), client `c8s-verify-js`.

Other docs: `THREAT_MODEL.md`, `QUICKSTART.md`, `DEMO.md`, `install-flows.md`,
`kata-image-policy.md`, `kata-guest-base.md`, `decisions/`, `pitfalls.md`.

---

## The shared trust spine
- **attestation-rs / attestation-api** — the `/attest` endpoint (in the guest)
  and `attestation-cli verify` (signature → vendor root + report_data) are the
  common primitive under all three. Releases (`confidential-dot-ai/attestation-rs`
  v0.4.0) ship a prebuilt `attestation-cli` (x86-64 linux, links `libtss2`).
- **CDS** is the production *centralization* of verification: instead of each
  client fetching the VCEK from AMD KDS (the per-IP **429** we hit), CDS verifies
  evidence server-side and hands back certs/EAR — one place to cache collateral.
- **EAR** (ES256 JWT) is the portable "this workload is attested as X" token.
- **RA-TLS** binds the attestation into the TLS handshake → attested mTLS without
  app changes.
- **Two measurement models** in play: c8s kata guests use **dm-verity erofs**
  (verity root in cmdline); our bare-metal box uses **IGVM** (`guest-smpN.igvm`).
  Same SNP report, different launch-measurement provenance.

## How it maps to our confidential-CI work
- Our **multi-CVM attest job** is the hand-rolled seed of c8s: c8s replaces our
  `curl /attest` + `attestation-cli verify` with **CDS** (challenge/attest/certify
  + EAR + mesh CA), and "is this a genuine CVM" becomes **per-pod cert issuance +
  digest-allowlist enforcement**.
- The **"only allowed digests can spin up"** integration test ≈ exercising
  **nri-image-policy / policy-monitor + the CDS allowlist** — and gap #57
  (measurement-allowlist-at-`/attest`) is a concrete thing to test.
- The **kettle e2e roundtrip** ≈ kettle-orchestrator spinning a CVM, running a
  kettle build, returning signed provenance — a natural CI E2E alongside a c8s
  cluster test.
- Our **KDS-429 / VCEK-cache** pain is exactly what routing verification through
  **CDS** solves.

## Candidate CI test scenarios (for when we build, not now)
1. **c8s cluster bring-up** on a runner: `c8s install` → assert CDS up, webhook
   injecting, attestation-api DaemonSet ready.
2. **Digest allowlist**: deploy an allowlisted ConfidentialWorkload (runs) + a
   non-allowlisted image (policy-monitor SIGKILLs it) — assert both outcomes.
3. **Multi-CVM cross-attest**: two ConfidentialWorkloads, RA-TLS mesh between
   them, assert attested mTLS (today our job attests both externally).
4. **kettle attested build** in a CVM via kettle-orchestrator → verify the signed
   provenance.

## Pointers
Repos: `~/dev/conf/{kettle,kettle-orchestrator,c8s}`. GitHub org:
`confidential-dot-ai`. Key c8s entry points: `cmd/cds`, `cmd/c8s`,
`cmd/get-cert`, `cmd/ratls-mesh`, `cmd/nri-image-policy`, `cmd/policy-monitor`,
`api/v1alpha2/confidentialworkload_types.go`, `docs/operator.md`,
`docs/kata-image-policy.md`, `docs/GAPS.md`, `docs/THREAT_MODEL.md`.
