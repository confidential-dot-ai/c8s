# Kettle e2e roundtrip in CI — design

> **Status: design (not built). Orchestrator confirmed LIVE** at
> `https://build.confidential.ai` — so the CI job is a pure **client**; nothing to
> deploy. Chase-down notes at the bottom.

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
6. `kettle verify <dir>` (P2: `--igvm <pinned guest-smp10.igvm>`) → **fail-closed**.
7. "check the output": assert the binary checksum + that `provenance.json` lists
   the expected source/ref/toolchain, and that `evidence.json`'s report_data
   carries our `nonce` (freshness).

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
| **P2** | `--igvm` (and `--image` dm-verity) binding to the pinned VM image — the strongest form; needs the IGVM file (see open Qs) |
| **P3** | source matrix: Cargo + Nix fixtures (kettle supports both today) |

## Open questions / details to confirm

1. **Auth on `POST /build`?** `/health` + `/config` are open; the docs show a plain
   `curl` to `/build`. Confirm whether builds need a token / are rate-limited.
2. **IGVM file for `--igvm` (P2).** `kettle verify --igvm` needs the pinned
   `guest-smp10.igvm`. Where to fetch it — from the `kettle-build` OCI image
   (`/config.image.reference`), or a release artifact? Until then P1 skips `--igvm`.
3. **Nonce check.** Does `kettle verify` expose an `--expected-nonce`, or do we
   assert the nonce against `evidence.json`'s report_data ourselves? (Confirm the
   field.)
4. **Source fixture.** A tiny Cargo fixture (fast, deterministic) vs the `ripgrep`
   example from kettle's docs. Recommend a small fixture for speed.

## Chase-down: is the orchestrator deployed? — YES

- **Not on the bare-metal cluster** (no kettle/orchestrator pods/svc/ns) and the
  deploy model is **systemd-on-a-host** (`bin/deploy-orchestrator` writes
  `/etc/systemd/system/kettle-orchestrator.service`, `ExecStart=…
  kettle-orchestrator /usr/share/kettle/image --qemu-binary …`), not Kubernetes.
- **A live instance is public:** `https://build.confidential.ai` answers
  `/health` (200 ok) and `/config` (pinned image above). So we **call it**, we
  don't deploy it — decision #1 from the scope is resolved.
