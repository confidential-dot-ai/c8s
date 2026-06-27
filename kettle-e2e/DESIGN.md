# Kettle e2e roundtrip in CI — design

> **Status: P1 BUILT & GREEN** (2026-06-26). [`kettle-e2e.yml`](kettle-e2e.yml)
> runs on `confidential-bm` in `cifrai/confidential-bm-smoke`: it submits a build
> to the orchestrator (`build.confidential.ai`), which launches a CVM, builds
> ripgrep (pinned commit `4649aa97`) + hardware-signs SLSA provenance, then
> `kettle verify --nonce` passes **signature + provenance + binary checksum +
> nonce/freshness**, fail-closed. One green run = a build ran in a real TEE and
> the artifact is cryptographically tied to its source, toolchain, and a fresh
> nonce. P2 (`--igvm` launch-measurement bind) is wired but **parked**: the image
> is now public (no cred needed), but the live orchestrator's attested launch
> measurement does not match the image its `/config` advertises — a server-side
> deployment mismatch, not a CI/kettle bug. See "P2 finding" below.

## Goal / definition of done

A CI job that submits a build to the kettle-orchestrator, which **launches a CVM,
runs the attested build, and returns the output**; the job then **verifies the
output is genuine** — hardware signature (vendor keys) + SLSA provenance + binary
checksum, and (P2) the launch measurement bound to the pinned VM image — and
**fails closed** on any mismatch. One green run proves: *a build ran in a real
TEE and the artifact is cryptographically tied to its source, toolchain, and that
exact VM.* This is the build-side complement to `snp-e2e` (runtime-side); both
rest on the same SNP attestation primitive, but here the **TEE is remote** (the
orchestrator's CVM), so the job itself needs no local TEE.

## The flow

```
CI job (client)                         build.confidential.ai (orchestrator, deployed)
  nonce (hex, ≤16B)
  POST /build {nonce, repo_url/ref} ───▶ launch CVM (qemu-igvm, pinned image) → `kettle attest`
       ← {job_id}                         build + record FW/OS measurement + HW-sign evidence
  GET /build/{id}/events  (SSE) ◀──────── progress … → "complete"
  GET /build/{id}/result  ◀────────────── build.tar.gz: evidence.json + provenance.json + binary
  kettle verify <dir> [--igvm <pinned>]    → sig valid · provenance valid · checksum matches
       fail-closed on mismatch             (P2: launch measure == pinned IGVM; nonce freshness)
```

## API contract (confirmed live)

- `GET /health` → `200 ok`. `GET /config` → the pinned CVM image, e.g.
  `{"image":{"reference":"ghcr.io/confidential-dot-ai/kettle-build@sha256:8c1a825…",
  "igvm":"guest-smp10.igvm","disk":"disk.raw"}}`.
- `POST /build` (`application/json`): **`nonce`** (hex, ≤16 bytes / 32 hex chars,
  *bound into the attestation* → freshness) + exactly one of **`repo_url`**
  (+`repo_ref`) or **`source_data`** (base64 archive). Auto-detects Cargo/Nix.
  Returns `{job_id}`.
- `GET /build/{id}/events` — SSE progress; wait for the `complete` event.
- `GET /build/{id}/result` — `application/gzip` tarball of outputs
  (`evidence.json`, `provenance.json`, binary, checksums). `404` until ready.

## kettle CLI (the verifier — prebuilt, no build)

- `kettle build <src>` — provenance + build, no TEE (local sanity only).
- `kettle attest <src>` — build + record VM FW/OS measurement + HW-sign →
  `evidence.json` (runs *inside* the TEE; this is what the orchestrator runs).
- `kettle verify <build-dir>` — verify `evidence.json` signature against hardware
  vendor keys, validate `provenance.json`, confirm the binary checksum.
  - `--igvm <FILE>` — assert the attested launch measurement == this IGVM's launch
    digest (binds the build to the exact confidential VM image).
  - `--image <FILE>` — assert the dm-verity roothash in the IGVM matches `disk.raw`.
- Download the prebuilt `kettle` from GitHub releases (same pattern as
  `attestation-cli`): `curl -LO .../confidential-dot-ai/kettle/releases/latest/download/kettle`.

## The CI job steps

1. `curl` the prebuilt `kettle` binary; `apt-get install -y libtss2-dev`
   (verify links it, like `attestation-cli`).
2. `NONCE=$(openssl rand -hex 16)`.
3. `POST https://build.confidential.ai/build` with `{nonce, repo_url, repo_ref}`
   (ripgrep, pinned commit) → capture `job_id`.
4. poll `GET /build/{job_id}/events` until `complete` (fail on error event).
5. `GET /build/{job_id}/result` → `build.tar.gz`; `tar xzf`.
6. `kettle verify <dir> --nonce <NONCE>` (P2 adds `--igvm <guest-smp10.igvm>`) —
   verifies signature + provenance predicate + provenance match + artifact
   checksums + nonce/freshness; **fail-closed**.
7. (optional) assert `provenance.json` lists the expected source/ref/toolchain.

## Where it runs / networking

- `runs-on: confidential-bm` for dogfooding/consistency — **but the TEE is remote**,
  so this job doesn't need a local confidential runner; it could run on any runner.
- **No new egress carve-out needed:** `build.confidential.ai` is public internet
  (the runner-egress policy already allows `world`), unlike the in-cluster `/attest`
  path which needed the `confai-images:8400` carve-out.

## Phasing

| Phase | Scope |
|---|---|
| **P1** | roundtrip + `kettle verify` (signature + provenance + checksum) + nonce freshness, fail-closed |
| **P2** | `--igvm` (and `--image` dm-verity) binding to the pinned VM image — the strongest form; get the IGVM via `oras pull` of the pinned digest (see resolved Q2) |
| **P3** | source matrix: Cargo + Nix fixtures (kettle supports both today) |

## Build gotchas (learned wiring P1 — both cost a red run)

1. **The source must be a git repo with a commit.** kettle records
   `git rev-parse HEAD` in the provenance, so a plain `source_data` tarball with
   no `.git` fails inside the CVM with
   `BuildFailed: git rev-parse HEAD failed: not a git repository`. P1 uses
   `repo_url` (cloned with `git clone --revision <ref>`, git ≥2.49, so a full
   commit SHA works). A `source_data` path would have to ship a real `.git`.
2. **`kettle verify` exits 0 even on a FAILED verdict.** `verify()` returns
   `Ok(())` unconditionally and only prints `Verification PASSED` / `FAILED` in
   the table. So the CI step must assert on the verdict **text** ("Verification
   PASSED", and no "Verification FAILED"), **not** `$?` — relying on the exit code
   alone would let a forged build pass silently. Set `NO_COLOR=1` so the grep is
   stable. (This is a fail-open footgun in the verifier; flagged upstream.)

## Resolved (pinned against the live service + kettle source)

1. **Auth on `POST /build`: none.** `POST /build {}` → `HTTP 422 "missing field
   nonce"` (not 401/403) — open endpoint, body-validated only. The job needs no
   token. (Rate-limiting unconfirmed, but it's not auth.)
2. **IGVM for `--igvm` (P2): `oras pull`.** The pinned image (`/config`'s
   `image.reference` = `ghcr.io/confidential-dot-ai/kettle-build@sha256:…`) is an
   **`oras`-pushed OCI artifact** of `target/image/` — i.e. the `.igvm` +
   `disk.raw` files. So P2 = `oras pull <that digest>` → `guest-smp10.igvm` (+
   `disk.raw` for `--image`).
3. **Nonce + verify: `kettle verify --nonce <hex>`** (confirmed in
   `src/commands/verify.rs`). Args: `--nonce` (≤16 bytes, "checked against the
   attestation"), `--igvm`, `--image` (requires `--igvm`). verify runs signature
   + provenance predicate + provenance match + artifact checksums, plus nonce /
   igvm / image when set. **Freshness is a first-class flag → P1 uses `--nonce`**;
   no manual report_data parsing.
4. **Source fixture:** a tiny self-contained **Cargo crate via `source_data`**
   (base64 ZIP/tarball) — deterministic, fast, no external repo dependency.
   Fallback: `repo_url=https://github.com/burntsushi/ripgrep` (kettle's own example).

### P2 finding — measurement mismatch in the deployed service (2026-06-26)
The image was made **public**, so `oras pull` needs no credential (the earlier
GHCR-cred blocker is gone). We wired P2 (oras pull + `kettle verify --igvm
--image`) and ran it — it **fails closed on the launch-measurement bind**, and the
cause is server-side, not ours:

| Value | Digest |
|---|---|
| Published golden — image's own `manifest.json` `snp_launch_digest` | `82e291e0…` |
| `kettle measure_snp` recomputed from the pulled `guest-smp10.igvm` | `82e291e0…` (**== golden**) |
| **Attested** launch digest from the CVM that ran our build | `1932a2f5…` (**differs**) |

- kettle's verifier is **correct** — it reproduces the image's published
  measurement *exactly* (both `82e291e0`). So this is **not** a kettle/measure_snp
  bug and **not** a CI bug.
- The build at `build.confidential.ai` therefore **did not run on the image its own
  `/config` advertises** (`8c1a825`, smp=10, golden `82e291e0`); the live CVM
  measured to `1932a2f5` — a different image/config. The published image was built
  **2026-06-22**; the deployed orchestrator predates it → most likely the live
  service boots an **older on-disk image than `/config` reports** (deployment drift).
- `--image` (dm-verity) ✅ is only a **self-consistency** check between the *pulled*
  IGVM and *pulled* disk — it never touches the attestation, so it can't catch
  this. Only `--igvm` binds to the report, and it correctly failed.

**Disposition:** CI reverted to the green P1 (the meaningful, passing check). P2 is
mechanically ready (pull is anonymous; flags confirmed) and re-enables the moment
the deployed orchestrator's attested measurement matches its advertised image.

**Decisive next check (to confirm H1 vs H2):**
- H1 (likely): live service runs a different/older image → a build on the *correct*
  image would verify. Confirm by asking what image/smp `build.confidential.ai`
  actually boots (its `/usr/share/kettle/image`), or by an independent
  `sev-snp-measure --igvm guest-smp10.igvm` (expect `82e291e0`).
- H2 (less likely): `measure_snp` + the producer `manifest.json` were both produced
  by the same code and neither matches real hardware (then `1932a2f5` is the true
  measurement). Same independent-tool check distinguishes it: if `sev-snp-measure`
  yields `1932a2f5`, it's H2.

`/build` rate-limiting (unconfirmed; not auth).

## Chase-down: is the orchestrator deployed? — YES

- **Not on the bare-metal cluster** (no kettle/orchestrator pods/svc/ns) and the
  deploy model is **systemd-on-a-host** (`bin/deploy-orchestrator` writes
  `/etc/systemd/system/kettle-orchestrator.service`, `ExecStart=…
  kettle-orchestrator /usr/share/kettle/image --qemu-binary …`), not Kubernetes.
- **A live instance is public:** `https://build.confidential.ai` answers
  `/health` (200 ok) and `/config` (pinned image above). So we **call it**, we
  don't deploy it — decision #1 from the scope is resolved.
