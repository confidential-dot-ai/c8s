# P1 — c8s node-as-CVM on the conformance harness (scoping)

> **Status: SCOPING — not built.** Reuses the P0 harness (launch/attest/teardown).
> **Critical path = the node image: no confidential RKE2 node image exists in our
> hands yet** (bare-metal `images/` has only KubeVirt *infra* images; the "measured
> RKE2 CVM" is a planned platform follow-up for `dev-c8s-integration`, per
> `dev_ovh_2.yml`). Pin OQ1 (node image) + OQ2 (control channel) + OQ3 (NRI on k3s)
> before building. Same discipline as kettle/c8s-e2e: don't build until pinned.

## Goal / definition of done
Boot a **confidential VM that is a single-node k8s cluster** (node-as-CVM), install
**c8s with NO `--kata`**, and verify c8s's guarantees inside it — fail-closed — on the
P0 harness:
- **bring-up:** `c8s install` (no kata) → operator / CDS / attestation-api / webhook /
  `nri-image-policy` Ready inside the VM.
- **node attestation:** the VM's SNP report verified (reuse P0's attest).
- **CDS = genuine TEE:** `c8s cds verify` → exit 0.
- **workload identity:** an annotated pod attests → gets a CDS-issued leaf cert.
- **digest allowlist (host-side `nri-image-policy`, "host" = the confidential node):**
  an allowlisted image runs; a non-allowlisted image is **blocked**. Assert both.
- **teardown:** reuse P0 (delete the VM; clone GC'd).

One green run = *"this host runs c8s node-as-CVM and c8s enforces its guarantees inside
a real confidential node — no kata."* This is the cloud (Confidential GKE) model, so it
also pre-builds ~80% of the GCP backend.

## What reuses P0 (most of it)
`launch` a KubeVirt SNP VM (just a different IMAGE), **attest the VM = the node** via the
SNP report, serialize (concurrency group), guaranteed teardown. **New in P1:** the node
image, a control channel into the guest, the c8s install, and the c8s-specific assertions.

## The flow (sketch)
```
launch SNP VM (RKE2 node image)  → inner k3s/RKE2 Ready
  → c8s install   (no --kata)    → operator/CDS/attestation-api/webhook/nri Ready
  → c8s cds verify               → CDS is a genuine TEE
  → deploy allowlisted workload  → Running + attested + leaf cert
  → deploy non-allowlisted image → blocked (host-side nri-image-policy)
  → teardown (P0)
```

## Open questions to pin (before building)

**OQ1 — the node image (critical path).** No confidential RKE2 node image is in our
repos. Three options:
- **(a) consume the platform's "measured RKE2 CVM"** image (built for
  `dev-c8s-integration`) — a dependency on their pipeline; contradicts "build our own".
- **(b) build our own measured RKE2 node image** — heavy; needs the steep/base-image
  build pipeline (steep was inaccessible earlier).
- **(c) runtime-k3s on the existing base `cpu-image` CVM + a writable data disk** —
  *our own, lightest.* k3s/c8s are installed at boot onto a writable disk (rootfs is
  read-only verity). Trade-off: k3s/c8s are **not in the launch measurement** — which is
  **fine for a conformance test of c8s's *runtime* guarantees** (we're testing what c8s
  enforces, not the node image's supply chain). Feasibility depends on the base image
  having k3s's kernel prereqs (cgroups v2, overlay, br_netfilter, nft) and enough
  writable space. **RECOMMENDED as the prototype path** (proves node-as-CVM with zero
  platform dependency); swap to a measured image (a/b) later for production-grade
  measurement.

**OQ2 — control channel into the guest.** The CI job (outside the VM) must install c8s +
run checks inside it. The base image runs attestation-api on :8400 but likely no
sshd/guest-agent. Options: `virtctl` + `qemu-guest-agent`, an sshd in the guest, or
expose the inner k3s API on the guest pod-IP and pull a kubeconfig out. Pin the mechanism.

**OQ3 — NRI on the inner k3s/RKE2 containerd.** `nri-image-policy` needs NRI enabled +
the containerd drop-in import; c8s ships a `containerd-prep` for RKE2 — confirm it works
on the inner k3s/RKE2's containerd (this is what makes the allowlist enforcement real).

**OQ4 — c8s CLI + private images.** No c8s release → build the CLI from Go source
(`go build -tags c8s_node ./cmd/c8s`); needs `helm`/`kubectl`/`crane`. The c8s component
images are **private** (`cds`/`get-cert`/`kata-guest-base` → 403; `attestation-api`
public) → a GHCR `read:packages` cred (or they go public, which `pitfalls.md` says is
intended).

**OQ5 — TEE device passthrough inside the inner k3s.** attestation-api + CDS pods need
`/dev/sev-guest`. The guest *is* the SNP guest, so the device exists in the VM; pods get
it via `attestationApi.teeDevices` / a device plugin or hostPath. Confirm the wiring.

**OQ6 — golden measurement** for `c8s cds verify` / node attestation = the node image's
SNP launch measurement (the RKE2 node image's IGVM). Need the golden (same measurement
story as kettle P2; trivially we can pin the node VM's own attested measurement first and
tighten to a published golden later).

## What's already determined
- **Reuses the P0 harness** (launch/attest/teardown spine + concurrency + isolation).
- **No kata, no nested SNP, no nested KVM** — inner workloads are runc containers; the VM
  is the single confidential boundary.
- **CDS-as-runc works here** (the pitfall "cds needs an SNP guest" is satisfied — the
  *node* is the SNP guest).
- **Host-side `nri-image-policy` is the enforcement** in node-as-CVM (no in-guest
  policy-monitor; that's the kata/pod-as-CVM path, deferred to LAST).

## Recommendation
Prototype **OQ1(c) runtime-k3s on the base CVM** to prove node-as-CVM c8s end-to-end on
our own host with no platform dependency, accepting the unmeasured k3s/c8s layer. Pin
**OQ2 (control channel)**, **OQ3 (NRI on k3s)**, and **OQ5 (TEE device)** first — they're
the feasibility gates. Swap to a measured RKE2 node image (OQ1 a/b) once available.
**Don't build until OQ1–OQ3/OQ5 are pinned.**
