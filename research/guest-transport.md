# Guest transport: what kettle-orchestrator teaches us (2026-07-15)

We asked: can we learn from how `kettle-orchestrator` (build.confidential.ai)
launches CVMs? Answer: **yes — its guest TRANSPORT is the fix for our
primitive's worst part.** Its launch stack is qemu-direct (not KubeVirt), which
doesn't transplant; its communication pattern does, cleanly.

## What it does differently (verified in-repo)

| concern | our primitive (cvm-e2e.yml) | kettle-orchestrator |
|---|---|---|
| work IN | chunked base64 typed over the serial console via expect (~min/attempt, truncation retries) | **HTTP POST of a JSON job spec to an in-guest agent on :8080** (the kettle server, baked into disk.raw), reached via qemu user-net hostfwd |
| results OUT | poll `guest-console-log` for `@@markers@@` | **SSE event stream + `GET /result` gzipped tarball** (with `?from=N` replay) |
| console's job | the whole delivery channel | **boot logs only, one-way, cosmetic** |
| secrets | ghcr token base64'd over the console → guest-console-log + Actions log | ride the HTTP body; **never touch the console** |
| scratch space | tmpfs overlay on verity root | fresh per-job ext4 scratch disk (`LABEL=scratch`), deleted on teardown |
| image identity | refs CM + runtime configfs-tsm discovery | `GET /config` publishes pinned `{reference, igvm, disk}` so verifiers bind measurement↔image without trusting the host |
| lifecycle | VM per run, reap-by-run-status | VM per job (slot pool = concurrency cap, not reuse), SIGTERM→SIGKILL, stale reap on startup |

Decomposition worth copying if we ever build a service: `Launcher` trait
(qemu impl swappable for KubeVirt) / `SlotPool` / `Proxy` (POST spec, relay
SSE, fetch tarball) / `ProxyDriver`.

## Why this transplants to KubeVirt easily

The only qemu-specific bit is HOW the guest's :8080 becomes reachable
(SLIRP `hostfwd=tcp:127.0.0.1:{port}-:8080`). Under KubeVirt the VMI has a pod
IP on bridge networking — **we already talk HTTP to guests this way**:
`baremetal/snp-e2e.yml` curls the guest's attestation-api on `:8400` (with a
narrow egress carve-out `arc-runners → confai-images:8400`). The agent pattern
needs nothing we haven't already proven.

## What adopting it would kill

1. The expect/fold/`@@DLEN@@` delivery machinery — the flakiest, slowest part
   of the primitive (serial kubeconfig scrape called out as "flakiest link").
2. The secret-transit gap (Phase 4 T4.1) — job specs and any future credential
   ride an HTTP body over the pod network, never the console.
3. The 3000-char payload chunking ceiling — payloads/archives of any size.

## The gate: an agent must be IN the measured image

The rootfs is verity-immutable — the agent has to be baked at image build, not
installed at boot. Options, in order of preference:
1. **Reuse the kettle server contract** (`POST /build`, `GET /build/{id}/events`,
   `GET /build/{id}/result`) — the agent already exists, is maintained, and its
   API is exactly "run this job, stream progress, return artifacts". Ask
   base-images to bake kettle-server into rke2-node + base-cpu images (it's
   already in the kettle build image).
2. A minimal purpose-built agent (tiny static bin: POST script → run → SSE +
   tarball). Only if reusing kettle-server drags in unwanted server deps.
Either way `/attest` (:8400) stays separate — attestation-api already serves it.

## Sequencing (do NOT redo the primitive now)

Console delivery works and is green; the roadmap's critical path (consumers +
triggers) doesn't wait for this. Adopt the agent transport as the **primitive
v2 internal change** once base-images ships an agent-bearing image: same
payload contract (`payload_b64` in, markers/`PAYLOAD_OK` out — markers become
SSE events), zero consumer changes. Pair it with T4.1 since it IS the secret
fix. Bonus: on GKE/Azure lanes (no console at all!) the agent transport is the
ONLY option — building gke-e2e.yml against an agent contract first avoids
inventing a second transport there.
