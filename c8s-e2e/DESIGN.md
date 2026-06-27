# c8s e2e in CI — design (scoping)

> **SUPERSEDED-IN-PART by [`../conformance/DESIGN.md`](../conformance/DESIGN.md).**
> The approach is now: prove the host we have today (`sev-snp-gh-runner`) can test
> all of c8s **via KubeVirt SNP VMs, deferring kata to the very last test.** c8s has
> two deployment shapes — **node-as-CVM** (the node is a confidential VM; runc pods;
> host-side `nri-image-policy`; **no kata**) and **pod-as-CVM** (kata). We test
> ~all of c8s in node-as-CVM mode on a KubeVirt SNP VM; **kata only covers the final
> per-pod-as-CVM enforcement test.** This dissolves the old blast-radius worry (OQ1)
> for everything but that last step, and removes the dependency on `dev-c8s-integration`.
> The detail below (bring-up, allowlist, mesh) still applies — just read it as
> running on a node-as-CVM KubeVirt node first, kata last.
>
> **Original scoping (kata-first framing) kept for reference:** SCOPING — not built;
> the headline risk was **blast radius** (OQ1) of `c8s install --kata` on the shared
> runner node, and the private-image cred (OQ3).

## Goal / definition of done

A CI test that **installs c8s on a real SEV-SNP cluster and proves the flagship
security property end-to-end, fail-closed**:

1. **Bring-up** — `c8s install --kata` → operator + CDS + attestation-api + webhook,
   plus kata-deploy and the `kata-qemu-snp` RuntimeClass, all Ready.
2. **CDS is a genuine TEE** — `c8s cds verify https://<cds-ip>:8443 --measurements
   <golden>` returns exit `0` (its exit codes are a documented CI contract:
   `0` verified / `2` policy fail / `3` evidence unavailable — `operator.md`).
3. **Digest allowlist (the marquee)** — an **allowlisted** confidential workload
   runs (boots as `kata-qemu-snp`, attests, gets a leaf cert at `/etc/c8s/certs`);
   a **non-allowlisted** image is **blocked** (in-guest `policy-monitor` SIGKILLs
   the init PID under `--kata`; host-side `nri-image-policy` denies otherwise).
   Assert **both** outcomes.
4. **Teardown** — `c8s uninstall` (sweeps kata host artifacts; refuses while kata
   pods are still scheduled).

One green run = *c8s actually enforces "only allowlisted digests run inside attested
CVMs" on real hardware.*

## Why this is the highest-value c8s CI

- It's the product's **core claim** — the digest-allowlist + attested-runtime story
  the whole stack builds toward (see `research/kettle-orchestrator-c8s.md`).
- **c8s has no hardware e2e today.** Its CI is unit/chart/build only:
  `ci.yml` (`go test` + `helm template`), `chart.yml` / `docker.yml` (publish),
  `kata-guest-base.yml` + `kernel-snapshot.yml` (image builds). Nothing installs
  c8s on a live SNP cluster or exercises enforcement. This fills that gap.

## The flow (sketch)

```
c8s install --kata --image-pull-secret ghcr-secret
    → kata-deploy + RuntimeClasses + operator + CDS(kata-qemu-snp) + webhook + nri/policy-monitor
c8s cds verify https://<cds-ip>:8443 --measurements <cds-golden>        → exit 0 (genuine TEE)

# positive: allowlisted confidential workload
kubectl apply <allowlisted pod, annotated confidential.ai/cw>          → Running; cert in /etc/c8s/certs
# negative: a digest NOT in the allowlist
kubectl apply <non-allowlisted image pod, annotated>                   → killed; assert never Ready

c8s uninstall
```

## Where it runs — **the #1 open question (OQ1)**

`c8s install --kata` is a **cluster-wide platform mutation** (`operator.md`):
- kata-deploy installs QEMU + the kata runtime + `containerd-shim-kata-v2` on
  **every node** and **restarts containerd** (the RKE2 vs k8s config path is
  auto-detected — c8s supports RKE2, which is what we run);
- a `ValidatingAdmissionPolicy` **rejects non-kata workload pods** (system &
  host-namespace pods exempt) and the webhook injects `runtimeClassName`;
- cluster-scoped CRDs / RBAC / webhook / a host-side NRI image policy.

Our bare-metal is a **single node** (`sev-snp-gh-runner`) that **also hosts the ARC
runners** (`arc-runners` ns). Risks: the containerd restart disrupts running pods;
`arc-runners` is **not** a system namespace, so the VAP/webhook may capture the
runner pods; the NRI image policy could gate the runners' own images. → Almost
certainly needs a **dedicated SNP node/cluster** for the c8s e2e, or confirmed
exemptions + a tolerance for runner churn. **Pin this before anything else.**

## Phasing

| Phase | Scope |
|---|---|
| **P1** | Bring-up + `c8s cds verify` (CDS is a genuine TEE running expected code). |
| **P2** | Digest-allowlist enforcement — allowlisted runs, non-allowlisted blocked. The marquee. |
| **P3** | RA-TLS mesh: two confidential workloads, attested mTLS between them (extends `multi-cvm-attest`). |

## Open questions to pin (before building)

1. **Blast radius / cluster (OQ1, the big one).** Dedicated SNP node/cluster vs the
   shared runner node. See above. Likely needs a second SNP node or an ephemeral
   kata-capable cluster; on a single shared node the install will probably disturb
   the runners.
2. **kata-qemu-snp actually works via `c8s install --kata` on our EPYC/RKE2 node.**
   `pitfalls.md`: the kata-image-puller reconcile loop must hold
   `experimental_force_guest_pull` or sandboxes die with `rootfs ENOENT`; host-side
   image pull is still needed (no nydus-snapshotter). Validate a `kata-qemu-snp` pod
   boots after install.
3. **Private-image credential (OQ3).** c8s images are **private** today —
   `cds` / `c8s` / `get-cert` / `kata-guest-base` → `HTTP 403` anon; only
   `attestation-api` is public. Need a GHCR `read:packages` cred wired three ways
   (`--image-pull-secret` for kubelet; `kata.guestImage.pullerAuthSecret` for the
   in-pod `oras pull`; the baked `ghcr-auth.json` via `READ_PRIVATE_GHCR_TOKEN` for
   guest-pull). Same situation `kettle-build` was in before it went public, and
   `pitfalls.md` says to *"remove this once the artifacts go public"* — so this may
   resolve itself. Pin: obtain the cred, or wait for the images to go public.
4. **c8s CLI provenance (OQ4).** No release → build from source
   (`make` / `go build -tags c8s_node ./cmd/c8s`, needs Go). Runner also needs
   `helm`, `kubectl`, and `crane` (for `c8s install`'s default digest resolution).
5. **Allowlist fixtures + assertions (OQ5).** Positive = an allowlisted image;
   negative = a digest not in the allowlist. How the allowlist is seeded (baked
   `bootstrap-allowlist.json` on the dm-verity rootfs + runtime growth via CDS
   `POST /allowlist`, EAR-authorized and gated by `cds.allowlistWriteMeasurements`)
   and how to **observe the deny** (policy-monitor SIGKILLs the init PID in-guest →
   pod never Ready). Pin the exact images + `kubectl wait`/phase/event assertions.
6. **CDS golden measurement (OQ6)** for `c8s cds verify --measurements`. The
   kata-guest-base launch digest (via `sev-snp-measure`, per `operator.md`) — same
   measurement story as kettle P2. Pin where it comes from (published vs computed).

## What's already determined

- **c8s supports RKE2** (our cluster) — operator auto-detects the containerd path.
- **`c8s cds verify`** gives a clean CI assertion (exit `0/2/3`, JSON output).
- **`c8s uninstall`** handles teardown (sweeps kata artifacts; refuses while kata
  pods are scheduled → delete workloads first or `--force`).
- **Two enforcement flavors:** `--kata` (in-guest `policy-monitor`, the real
  confidential story) vs plain install (host-side `nri-image-policy`). The real
  test is `--kata`; cds also **can't reach Ready without `--kata`** (needs
  `/dev/sev-guest`, only inside an SNP guest — `pitfalls.md`).
- **No c8s release** → build the CLI from source.
- **No hardware e2e exists in c8s today** → this is net-new coverage.

## If/when it lands
Like kettle's, the e2e is a **client of a confidential platform** but here it also
*installs* that platform, so it must run on (or against) a real SNP cluster — it
can't be a stock `ubuntu-latest` job. Natural home once proven: a workflow in
`confidential-dot-ai/c8s` (gated to a self-hosted SNP runner) + a mirror here.
