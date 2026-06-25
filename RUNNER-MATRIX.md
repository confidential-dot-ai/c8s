# Runner coverage matrix

The confidential self-hosted runner (`confidential-e2e`) is **x86-64 Linux**.
attestation-rs CI has 8 jobs; here's what runs there today and what the rest
needs. The short version: the security-relevant **build + test of the Linux,
attest-capable binaries** runs on confidential now; the remaining jobs are
gaps in runner *type* (arm node, macOS, docker), not a redesign.

All jobs are **enabled** (no `if: false`) and routed to the right runner. Every
row below was proven green on a live push to `cifrai/attestation-rs-ci`:

| CI job | Platform / target | `runs-on` | Status (live) | Confidential relevant? |
|---|---|---|---|---|
| `check` (fmt/clippy) | x86-64 Linux | `confidential-e2e` (self-hosted) | ✅ green | yes — compiles the attest path |
| `test` (`cargo test --workspace`) | x86-64 Linux | `confidential-e2e` | ✅ green | yes* |
| `audit` (cargo-audit) | x86-64 Linux | `confidential-e2e` | ✅ green** | yes |
| `release-build` · `x86_64-unknown-linux-gnu` | x86-64 Linux | `confidential-e2e` | ✅ green | yes — `--features attest`, full generate+verify binary |
| `release-build` · `aarch64-unknown-linux-gnu` | arm64 Linux | `ubuntu-24.04-arm` (hosted) | ✅ green | builds attest; **GCP has no ARM confidential VM**, so a hosted ARM node is fine to *build* |
| `release-build` · `aarch64-apple-darwin` | macOS arm64 | `macos-14` (hosted) | ✅ green | **N/A — verify-only** (attest path compiles out on macOS) |
| `docker-build` | x86-64 Linux | `ubuntu-latest` (hosted) | ✅ green | not confidential per se (ARC has no Docker daemon → hosted, or dind) |
| `publish` / `release` | x86-64 Linux | `ubuntu-latest` (hosted) | guarded to source repo | — |

\*\* `audit` needs a toolchain: the self-hosted runner image bakes build deps but
not `rustup`, so the job installs the toolchain (`dtolnay/rust-toolchain`) like
`check`/`test` do — GitHub-hosted runners ship `cargo` pre-installed, self-hosted
don't. `publish`/`release` carry `&& github.repository == '<source>'` so copies
and forks never push images or cut releases.

\* `test` runs `cargo test --workspace`, i.e. the offline/verification tests
(against captured quotes in testdata). The tests that *generate* a hardware
quote are `#[ignore]`d and need a runner pod scheduled onto a real **TEE node**
(SEV-SNP/TDX) — that's the Model-A confidential-node-pool upgrade, separate from
the orchestrator we run today.

## macOS — verify-only, confidential compute does not apply

This is the subtle one. macOS has **no TEE** (no SEV-SNP/TDX), and attestation-rs's
evidence-*generation* code lives behind Linux-only deps (`az-cvm-vtpm` →
`tss-esapi`, which is `pkg-config`/`libtss2` on Linux). On macOS that path
**compiles out** — so even when you build `--features attest`, the macOS artifact
is a **verify-only client**: it can check a quote, never produce one. (attestation-rs's
own CI comment says exactly this: "macOS isn't Linux, so the attest path compiles
out there entirely.")

So macOS needs **no confidential runner and no TEE** — only a macOS *builder*:
- Simplest: leave it on GitHub-hosted `macos-14`.
- Or self-host an Apple Silicon runner (a Mac with the Actions runner) if you
  want it off GitHub-hosted. It still isn't confidential — there's nothing to
  attest on a Mac.

Bottom line: don't try to make the Mac job "confidential" — it's a verify-only
client build by design.

## arm64 Linux — full attest build, but no ARM confidential VM (yet)

`aarch64-unknown-linux-gnu` builds the full `--features attest` binary (libtss2
on arm). It needs an **arm64 Linux runner**. GCP confidential VMs are x86 only
(AMD SEV-SNP / Intel TDX); there is no ARM confidential VM, so the arm *build*
runs on a normal ARM node — you're compiling a binary, not attesting on it. The
binary itself runs confidentially wherever ARM TEEs exist (ARM CCA, bare metal).

- Add an ARM node pool to the host and a runner scale set pinned to it:
  ```bash
  gcloud container node-pools create arm --cluster arc-host --zone us-central1-a \
    --machine-type t2a-standard-2 --num-nodes 1 --enable-autoscaling --min-nodes 0 --max-nodes 2
  # then a 2nd scale set (e.g. confidential-e2e-arm) with a nodeSelector for the arm pool
  ```
- Or keep this target on GitHub-hosted `ubuntu-24.04-arm`.

## docker-build — needs a Docker daemon

ARC runners have no Docker. Either enable `containerMode: dind` (privileged) on a
dedicated scale set, or keep `docker-build` on GitHub-hosted. For confidential
parity you'd use dind; for now hosted is fine.

## Production split (shipped — all jobs enabled)

- **Confidential self-hosted (`confidential-e2e`):** `check`, `test`, `audit`,
  `release-build · x86_64-linux` — the attest-capable Linux build + test.
- **GitHub-hosted (correct, not a gap):** `release-build · aarch64-linux`
  (`ubuntu-24.04-arm` — no ARM confidential VM exists), `release-build ·
  aarch64-apple-darwin` (`macos-14` — verify-only), `docker-build`
  (`ubuntu-latest` — ARC has no Docker daemon).
- **Optional self-host upgrades:** ARM node pool for the arm leg, a dind scale
  set for `docker-build` — neither is confidential, so hosted is fine.

Nothing is `if: false`. The diff vs upstream is just per-job `runs-on` (plus a
toolchain step in `audit` and a `github.repository` guard on publish/release so
copies/forks don't ship). **Eligibility prerequisite:** the repo must be
**private/internal** — GitHub won't dispatch self-hosted runners on public repos
(see `MONITORING.md`).
