# P1 — c8s node-as-CVM on the conformance harness (scoping)

> **Status: SCOPING COMPLETE; node image BUILDABLE — route decision needed (2026-06-27).**
> Looking at kettle revealed the image pipeline (steep = mkosi + kettle's public
> `igvm-tools Build` + cloud-init), so P1 is no longer hard-blocked — see "Build status".
> Reuses the P0 harness (launch/attest/teardown).
> **Critical path = the node image: no confidential RKE2 node image exists in our
> hands yet** (bare-metal `images/` has only KubeVirt *infra* images; the "measured
> RKE2 CVM" is a planned platform follow-up for `dev-c8s-integration`, per
> `dev_ovh_2.yml`). **`c8s install` itself handles the components, image pull+pin,
> TEE-device wiring, and NRI/containerd setup** — so our real job is just: give it a
> **confidential RKE2 cluster** to install into (OQ1) + a **control channel** to drive
> it (OQ2) + a pull secret. Pin OQ1 + OQ2 first. Don't build until pinned.

## Build status — node image BUILDABLE; route decision needed (updated 2026-06-27)
First pass concluded "blocked" (no RKE2 node image; `base_cpu_image` is a ~3 GiB
attestation *appliance*, not a node; SNP VMs boot a verity rootfs + matched
`guest-smpN.igvm`, so you can't drop in an arbitrary RKE2 image). **Then we looked at
kettle-orchestrator/kettle — which revealed the image pipeline, and it's replicable:**

- **steep (the confidential-image builder) = `mkosi` (upstream, open) + kettle's
  `igvm-tools Build` + a baked `--cloud-init`.** kettle's `bin/image-build` runs
  `steep build target/image --smp --memory --extra <files> --cloud-init <user-data> --package …`.
- **kettle's `igvm-tools` is PUBLIC and has a `Build` subcommand** ("Build an IGVM file
  from firmware, kernel, and optional components" — `crates/igvm-tools/src/builder.rs`).
  So the IGVM-packaging half is in our hands.
- **The `--cloud-init` is the control channel (OQ2 solved by the build).** steep bakes a
  `#cloud-config` (users, `write_files` for systemd units, `runcmd`, udev for
  `/dev/sev-guest`). So we bake an sshd / kubeconfig-export / agent into the node image.

So a confidential **RKE2 node image is buildable**: mkosi verity rootfs + RKE2
(`--package`/`--extra`) + a cloud-init that installs/enables RKE2 and exposes a control
channel, packaged into an IGVM by `igvm-tools Build`.

**Two routes (pick one):**
1. **Get it from the platform (cheapest).** The "measured RKE2 CVM" (steep-built; the
   `dev-c8s-integration` workload they're already building) or steep itself. These are
   **private** (anon GHCR → 403, like `base-cpu-image`), so this needs a pull cred / the
   platform sharing — a small ask, and the image is already on their roadmap.
2. **Replicate steep ourselves (our own, harder).** `mkosi` (open) + kettle's
   `igvm-tools Build` (public) + an RKE2 cloud-init spec. Fully in our control but a
   multi-day build (privileged mkosi builder, OVMF/kernel sourcing, verity + IGVM, RKE2's
   kernel prereqs: cgroups v2 / overlay / br_netfilter / nft).

**Net: P1 is no longer hard-blocked** — it's a route choice. **OQ2 (control channel) is
solved** by the build's cloud-init; **OQ1 (node image)** is route 1 (ask) or route 2
(build). (Secondary: host SSH `ubuntu@100.65.229.52` is intermittently timing out;
cluster still reachable via the Rancher kubeconfig.)

**Decision (open):** route 1 (get the platform's RKE2 CVM image / steep + a pull cred) is
the cheapest unblock and should be tried first — it's a small ask and the image is already
on their roadmap. Route 2 (replicate steep with mkosi + igvm-tools) is the autonomous
fallback but a multi-day build, so don't start it speculatively before choosing. P0 stands
green; the per-component version-conformance model + the launch seam are ready for either
route's image.

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

## What a green run proves — per-component, per-version conformance

Because c8s evolves, the harness is **parameterized by component image digest**: every
new build flows through and is proven to run + function + attest inside a CVM. The crux:
**the SNP launch measurement attests the *environment* (the node/guest base); a
component's *version* is governed by the digest allowlist + its SLSA provenance — never
by the launch measurement.** So "component version X attested in a CVM" decomposes into
three independently-checked facts:

1. **Environment is a genuine CVM** — the node SNP report verifies against the expected
   base measurement.
2. **Version X is the governed one** — its digest is allowlisted → it runs; a
   non-allowlisted digest → **blocked**. (The marquee allowlist test, applied *per
   component*.)
3. **It did its job** — the component's observable (below), plus (if it
   produces/consumes attestation) its attestation verifies.

### Per-component observables
| Component | "worked" observable | attestation shows up as |
|---|---|---|
| `attestation-api` | serves a report we can verify | it *is* the report source (bound to the base measurement) |
| `cds` | `c8s cds verify` → exit 0 | RA-TLS serving cert is SNP-bound (base measurement) |
| `get-cert` | a workload gets a CDS-issued leaf cert | issuance *required* a successful attest→CDS challenge |
| `ratls-mesh` | attested mTLS between 2 pods; **wrong-measurement peer rejected** | the mTLS handshake is RA-TLS (attestation-bound) |
| `nri-image-policy` / `policy-monitor` | allowlisted digest runs; non-allowlisted **SIGKILLed/denied** | its *effect* is the version governance (fact #2) |
| operator / webhook | injects runtimeClass / get-cert correctly | functional (runs in the attested node) |

### Version-conformance flow (digest-parameterized; re-run per build)
```
input: component=cds, digest=sha256:NEW
 → allowlist sha256:NEW  → deploy cds@NEW into the confidential node
 → c8s cds verify → exit 0                  (ran + attested inside the attested CVM)
 → (negative) deploy cds@NEW NOT allowlisted → blocked   (version governance works)
```
Same shape for every component — swap the digest, re-run. CI thus continuously proves
*each new version* runs + functions + attests in a CVM, and that the allowlist correctly
admits/denies it by digest.

### Boundaries (honest)
- **node-as-CVM (P1): all components share the *one* node launch measurement** —
  they're runtime containers in the single node CVM, so there's no distinct
  per-component measurement.
- **Per-component, per-pod CVMs** (each in its own memory-encrypted VM with its own base
  measurement) come only with **kata / pod-as-CVM** (deferred last); even there the
  component *version* is allowlist-governed, not in the launch measurement.
- **Supply chain** (is digest X built from the expected source?) = **SLSA provenance**
  (kettle's job), not attestation. Attestation = *where it ran*; provenance = *what it's
  built from*; allowlist = *which digest is allowed*. All three = "this version, from
  this source, ran in a real CVM."

## What `c8s install` handles for us (NOT our open questions)

Given a running cluster + a pull secret, `c8s install` (its embedded Helm chart) does
the heavy lifting — so several things are c8s's job, not ours:
- **Deploys all components** (operator, CRDs, RBAC, webhook, CDS, attestation-api,
  `nri-image-policy`, ratls-mesh).
- **Pulls + digest-pins the component images** (via `crane`); for the private ones we
  just supply `--image-pull-secret <name>` and it wires that into every component.
- **Wires the TEE device** into the attestation-api/CDS pods (`attestationApi.teeDevices`)
  — and the device exists because the node *is* the SNP guest. *(was OQ5 — handled.)*
- **Sets up NRI/containerd** for `nri-image-policy` via its `containerd-prep` initContainer
  — tested on **RKE2** (k3s is "likely but untested"). *(was OQ3 — handled, on RKE2.)*
- **cds reaches Ready** as a runc pod because the node is an SNP guest (`/dev/sev-guest`)
  — the default (non-kata) install shape on a confidential node *is* node-as-CVM.
- *(was OQ6)* `c8s cds verify` does node/CDS attestation; pin the node's own attested
  measurement first, tighten to a golden later.

## Our genuine prerequisites (what c8s does NOT do)

**OQ1 — provide the cluster (critical path).** `c8s install` runs *onto an existing
cluster*; it does not create one. So we must boot a **confidential RKE2 node** (the
VM-as-node) for c8s to install into. No such image is in our repos. Three options:
- **(a) the platform's "measured RKE2 CVM"** (built for `dev-c8s-integration`) —
  dependency on their pipeline; contradicts "build our own".
- **(b) build our own measured RKE2 node image** — heavy (steep/base-image pipeline).
- **(c) runtime-RKE2 on the base `cpu-image` CVM + a writable data disk** — *our own,
  lightest, RECOMMENDED prototype.* RKE2 installed at boot onto a writable disk (rootfs
  is read-only verity). Trade-off: RKE2/c8s aren't in the launch measurement — fine for
  testing c8s's *runtime* guarantees. Feasibility depends on the base image having RKE2's
  kernel prereqs (cgroups v2, overlay, br_netfilter, nft) + writable space. Use **RKE2**
  (c8s's tested distro), not k3s.

**OQ2 — control channel into the guest.** The CI job must run `c8s install` + the
checks against the inner cluster. The base image has attestation-api on :8400 but likely
no sshd/guest-agent → need `virtctl`+`qemu-guest-agent`, sshd, or expose the inner RKE2
API on the guest pod-IP and pull its kubeconfig out. Pin the mechanism.

**OQ3 (small) — the install-host bits we supply:** the c8s CLI (build from Go,
`go build -tags c8s_node ./cmd/c8s` — no release) + `helm`/`kubectl`/`crane`; a GHCR
**pull secret** for the private images (`cds`/`get-cert` are 403; create the secret, c8s
wires it) — unless they go public; and a `role=cds` node label (trivial).

## What's already determined
- **Reuses the P0 harness** (launch/attest/teardown spine + concurrency + isolation).
- **No kata, no nested SNP, no nested KVM** — inner workloads are runc containers; the VM
  is the single confidential boundary.
- **CDS-as-runc works here** (the pitfall "cds needs an SNP guest" is satisfied — the
  *node* is the SNP guest).
- **Host-side `nri-image-policy` is the enforcement** in node-as-CVM (no in-guest
  policy-monitor; that's the kata/pod-as-CVM path, deferred to LAST).

## Recommendation
Prototype **OQ1(c) runtime-RKE2 on the base CVM** to prove node-as-CVM c8s end-to-end on
our own host with no platform dependency, accepting the unmeasured RKE2/c8s layer. The
feasibility gates that are genuinely ours are just **OQ1 (a confidential RKE2 cluster)**
and **OQ2 (control channel)** — `c8s install` handles the components, images, TEE-device
wiring, and NRI itself. Swap to a measured RKE2 node image (OQ1 a/b) once available.
**Don't build until OQ1 + OQ2 are pinned.**
