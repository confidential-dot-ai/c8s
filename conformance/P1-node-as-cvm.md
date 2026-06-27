# P1 — c8s node-as-CVM on the conformance harness (scoping)

> **Status: SCOPING — not built.** Reuses the P0 harness (launch/attest/teardown).
> **Critical path = the node image: no confidential RKE2 node image exists in our
> hands yet** (bare-metal `images/` has only KubeVirt *infra* images; the "measured
> RKE2 CVM" is a planned platform follow-up for `dev-c8s-integration`, per
> `dev_ovh_2.yml`). **`c8s install` itself handles the components, image pull+pin,
> TEE-device wiring, and NRI/containerd setup** — so our real job is just: give it a
> **confidential RKE2 cluster** to install into (OQ1) + a **control channel** to drive
> it (OQ2) + a pull secret. Pin OQ1 + OQ2 first. Don't build until pinned.

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
