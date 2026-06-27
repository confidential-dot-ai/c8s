# Kettle e2e roundtrip in CI — design

> **Status: design (not built); ready to build P1.** Orchestrator confirmed LIVE
> at `https://build.confidential.ai` (CI job is a pure **client**; nothing to
> deploy), and all four open questions are **resolved** (see "Resolved" below).
> P1 has no blockers; P2 (`--igvm`) has one P2-only TBD (a GHCR pull cred).

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
   (a small fixture repo) → capture `job_id`.
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

### Remaining (P2-only, non-blocking for P1)
- Whether the `kettle-build` OCI image needs a **GHCR pull cred** for `oras pull`
  (private `confidential-dot-ai` org → probably yes). Only affects P2's `--igvm`.
- `/build` rate-limiting (unconfirmed; not auth).

## Chase-down: is the orchestrator deployed? — YES

- **Not on the bare-metal cluster** (no kettle/orchestrator pods/svc/ns) and the
  deploy model is **systemd-on-a-host** (`bin/deploy-orchestrator` writes
  `/etc/systemd/system/kettle-orchestrator.service`, `ExecStart=…
  kettle-orchestrator /usr/share/kettle/image --qemu-binary …`), not Kubernetes.
- **A live instance is public:** `https://build.confidential.ai` answers
  `/health` (200 ok) and `/config` (pinned image above). So we **call it**, we
  don't deploy it — decision #1 from the scope is resolved.
