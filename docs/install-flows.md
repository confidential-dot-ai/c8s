# c8s install flows and features (node shapes vs pod)

How `c8s install` assembles the platform, and how the runtime behaviour
differs across the install shapes. This is the overview that ties the
deeper docs together:

- [`kata.md`](kata.md) — the kata runtime install + enforcement, in depth.
- [`kata-guest-base.md`](kata-guest-base.md) — the confidential guest
  image design: how it boots, how a pod reaches end-to-end attestation,
  and why it lives here. (The recipe and what's baked in live in
  [`kata-guest-base/README.md`](../kata-guest-base/README.md).)
- [`kata-image-policy.md`](kata-image-policy.md) — in-guest per-image
  enforcement (`policy-monitor`).
- [`operator.md`](operator.md) — the operator, webhook, and controllers.

**Reading order (start here).** This doc is the map; read it first, then
[`kata-guest-base.md`](kata-guest-base.md) (the guest-image concept) →
[`kata-image-policy.md`](kata-image-policy.md) (in-guest enforcement) →
[`kata.md`](kata.md) (install/ops reference).

The source of truth is one chart per shape: `internal/helmchart/` holds
four installable shape charts — `pod` (c8s-pod), `node-cloud`
(c8s-node-cloud), `node-metal` (c8s-node-metal), `node-image`
(c8s-node-image) — built on a shared library chart (`lib/`, c8s-lib). The
CLI picks the chart from `--cvm-mode` (`resolveShape` in
`cmd/c8s/install.go`); component enablement is the chart choice.

---

## The shapes

`c8s install` runs `helm upgrade --install` against one of the four embedded
shape charts. The required `--cvm-mode` flag selects the chart. `pod` is the
kata shape; the others are node-as-CVM shapes, differing in where the node's
TEE evidence comes from and what the node image already bakes.

| Chart | Flag | One-liner |
|---|---|---|
| **c8s-node-image** | `--cvm-mode=node-image` (alias `node`) | Nodes booted from the c8s node-guest-image: the attestation-api and the NRI image-policy plugin are baked, and the chart's pins installer carries the release's CDS pins to the baked plugin. Normal Kubernetes pods on CVM nodes — **single-tenant**, the node is one trust domain. The dev/baseline shape. |
| **c8s-node-metal** | `--cvm-mode=node-metal` | Self-managed bare-metal CVM nodes (SEV-SNP or TDX) without the c8s node image: the chart installs the attestation-api DaemonSet and the full NRI installer. |
| **c8s-node-cloud** | `--cvm-mode=node-cloud` (aliases `gke`, `aks`; `aks` pins `--evidence=vtpm`) | Cloud-managed confidential VM nodes (GKE, AKS): native TEE evidence, or the Azure vTPM. |
| **c8s-pod** | `--cvm-mode=pod` | Installs the kata runtime + RuntimeClasses **and enforces them**: the webhook *injects* a kata RuntimeClass into every in-scope workload pod, a ValidatingAdmissionPolicy *rejects* non-kata pods, and the host-side mesh/attestation/image-policy move into the guest image. The production "pod-as-CVM" shape — kata is enforcing, there is no kata-without-enforcement mode. |

```mermaid
flowchart LR
    A["c8s install"] --> B{--cvm-mode}
    B -->|"node-image / node-metal / node-cloud"| NODE["node-as-CVM<br/>host-side everything<br/>no per-pod confidentiality"]
    B -->|"--cvm-mode=pod"| KATA["kata (enforcing)<br/>all workloads forced<br/>into kata VMs"]
```

There is no distro flag: the host distro (`k8s` vs `rke2`), which picks the
containerd config paths for kata-deploy and nri-image-policy, is detected
from the cluster's kubelet versions (`+rke2` build suffix → rke2) — skipped
under `node-image`, whose nodes are always RKE2. An install with `-f` values
owns the distro instead: set the top-level `distro` value there (every chart
but node-image carries it) if the chart default doesn't fit — a mixed
cluster cannot be detected and always needs that, plus nodeSelectors to
partition the install.

The kata-image-puller is on by default under `--cvm-mode=pod`, and the install
pins `kata.guestImage.tag` to the tag it resolves the component images at — the
guest's baked allowlist seed admits only the components of the commit the guest
was built from. A `-f` values file can switch the puller off or own the tag
itself (`kata.guestImage.enabled=false` / `kata.guestImage.tag=<tag>`); a file
that sets the tag wins. There is no dedicated CLI flag for these.

`--cvm-mode=pod --debug` points the puller at the `<tag>-debug` guest image —
identical except the baked guest policy allows host log/exec streams, so
`kubectl logs` / `kubectl exec` work against kata pods. Container I/O becomes
host-readable and the launch measurement differs from the locked image; dev
only (see [`kata.md`](kata.md)).

---

## What runs where (feature matrix)

✓ = present, ✗ = not rendered. "host" = ordinary container on the node;
"CVM" = `kata-qemu-snp` confidential VM; "in-VM" = baked into the guest image,
not a cluster resource.

| Component | node shapes | `--cvm-mode=pod` | Runs on |
|---|:--:|:--:|---|
| c8s operator (webhook + controllers) | ✓ | ✓ | host (runc; always webhook-exempt) |
| MWC `pod-injector` | ✓ | ✓ | cluster (release-tracked resource) |
| **CDS** (Certificate Distribution Service: verify + EAR + mesh-CA + leaf signing) | ✓ host | ✓ **CVM** | runc on the node shapes, `kata-qemu-snp` under kata |
| attestation-service | ✓ host | ✗ (in-VM) | chart DaemonSet on node-cloud/node-metal, baked into the node image on node-image; baked into the kata guest image under pod |
| ratls-mesh | ✓ host | ✗ (in-VM) | host DaemonSet on the node shapes; in-VM routing under kata |
| nri-image-policy | ✓ host | ✗ (in-VM) | host NRI plugin (chart installer on node-cloud/node-metal, baked plugin + pins installer on node-image); in-guest `policy-monitor` under kata (fed from CDS's served allowlist) |
| kata-deploy DaemonSet | ✗ | ✓ | host (privileged, hostPID/hostNetwork) |
| kata RuntimeClasses | ✗ | ✓ | cluster |
| kata-image-puller | ✗ | ✓¹ | host (privileged) |
| kata-enforcement VAP | ✗ | ✓ | cluster |
| RuntimeClass injection (workloads) | ✗ | ✓ | webhook (admission time) |
| get-cert injection (`confidential.ai/cw` pods) | ✓ | ✓ | webhook (admission time) |
| tls-lb (bundled workload) | ✓ | ✓ CVM | runc on the node shapes; `kata-qemu-snp` CVM under kata (pinned by the chart) |

¹ on by default; disable via `-f` values (`kata.guestImage.enabled=false`)

Under kata, **every host-side security component (attestation-service,
ratls-mesh, nri-image-policy) moves *inside* the confidential guest**, where
the host (adversarial) cannot tamper with it. The pod chart has no values
for them and renders none of them — component presence is the chart, so the
host versions cannot be left behind as a second, unattested enforcement
path.

---

## Trust boundary by shape

**node shapes** — there is no per-pod confidentiality. Everything runs in
ordinary containers the host kernel can read. The mesh/attestation
components operate at the node level; they do not hide pod memory from the
host. The node is a single trust domain, so these shapes are
**single-tenant**: every pod on it can reach what any other pod on it can
reach. Multi-tenant isolation requires `--cvm-mode=pod`.

```
 HOST (trusted on these shapes)
 ┌─────────┐ ┌────────┐ ┌────────────┐ ┌───────────────────┐
 │operator │ │  CDS   │ │ratls-mesh  │ │attestation-service│
 │+webhook │ │ (runc) │ │nri-img-pol │ │   (host DaemonSet) │
 └─────────┘ └────────┘ └────────────┘ └───────────────────┘
```

**kata** — the host is adversarial. Workloads and the c8s CDS run
inside `kata-qemu-snp` CVMs whose memory is SEV-SNP-encrypted; the security
services they rely on are *baked into the guest image* (part of the launch
measurement), not provided by the host.

```
 ══════════════ TEE boundary — SEV-SNP encrypted, host cannot read ══════════════
  ┌──────── kata-qemu-snp CVM ────────┐ ┌──── kata-qemu-snp CVM ────┐
  │ CDS                               │ │ workload                  │
  │  RA-TLS serving cert              │ │  + get-cert sidecar       │
  │  (snp evidence)                   │ │  (leaf from CDS)          │
  │ baked-in: attestation-service · ratls-mesh · policy-monitor (all in-VM) │
  └───────────────────────────────────┘ └───────────────────────────┘
 ════════════════════════════════════════════════════════════════════════════════
  HOST (adversarial)
  ┌─────────────┐ ┌──────────────┐ ┌───────────────────┐ ┌────────────────────┐
  │ c8s operator│ │ kata-deploy  │ │ kata-image-puller │ │ containerd         │
  │ + webhook   │ │ installs the │ │ stages the guest  │ │ + containerd-shim- │
  │ (runc)      │ │ kata runtime │ │ image + config    │ │   kata-v2          │
  └─────────────┘ └──────────────┘ └───────────────────┘ └────────────────────┘
```

The host-side pods that remain under kata — operator, kata-deploy,
kata-image-puller — are **infrastructure that cannot itself
run inside a CVM** (they install/serve the very thing CVMs depend on). They are
explicitly outside the trust boundary and are exempt from kata injection (see
[Admission flow](#admission-flow)).

---

## Install flow (ordering)

The MWC `pod-injector` is an **ordinary release-tracked resource**: Helm's
kind-order applies it *after* the Deployments, with an empty `caBundle` and
`failurePolicy: Fail`. The chart's own pods never depend on it — the MWC's
namespaceSelector excludes the release namespace — and workload pods are
annotated only after `helm --wait` reports the release ready.

```mermaid
sequenceDiagram
    participant CLI as c8s install
    participant K as kube-apiserver
    participant Helm as helm
    participant Op as operator pod
    participant Pods as workloads

    CLI->>K: kubectl apply Namespace (labelled pod-security=privileged in every mode)
    CLI->>Helm: helm upgrade --install --wait
    Note over Helm: normal resources (kind-order)
    Helm->>K: create operator Deployment, kata-deploy, CDS, ...
    Helm->>K: create MWC pod-injector (failurePolicy=Fail, empty caBundle)
    Op->>Op: bootstrapWebhookPKI: mint ephemeral CA + serving cert
    Op->>K: patch MWC caBundle (every operator start)
    Op->>K: reinject sweep: delete controller-owned cw pods admitted uninjected
    Note over Pods,K: in-scope pod created before the caBundle patch →<br/>webhook call fails → Fail rejects → ReplicaSet retries
    Pods->>K: (retry) admitted + mutated correctly
    Helm-->>CLI: --wait: all Ready
```

Key properties (see `templates/webhook.yaml`, `controller/runner.go`):

- **`failurePolicy: Fail`** means the window where the MWC exists but the
  operator hasn't patched the caBundle yet *fails closed* — pod creation is
  rejected and retried, never admitted as an unmutated runc pod.
- The **chart's own components are exempt** via the MWC's namespaceSelector,
  which excludes the release namespace (plus `kube-system`, `kube-public`,
  `kube-node-lease`, and `webhook.extraExcluded`), so the operator can always
  boot to patch the caBundle — no deadlock.
- The webhook CA is **ephemeral**: `bootstrapWebhookPKI` re-mints it and
  re-patches the caBundle on every operator start. The chart renders the
  `caBundle` field only when `webhook.caBundle` is set, so a `helm upgrade`
  leaves the operator-patched bundle in place and MWC spec changes roll out
  like any other resource.
- A `cw` pod admitted while the webhook was unavailable (e.g. before the MWC
  existed on first install) cannot self-heal — admission fires only on CREATE
  — so the operator runs a **one-shot reinject sweep** at startup that deletes
  controller-owned `cw` pods missing injection; their controllers recreate
  them through the webhook.
- CDS comes up during the main install and, living in the excluded release
  namespace, is never gated on the webhook — bootstrap services must not be
  gated behind the workloads that depend on them.

---

## Admission flow

Every CREATE of a pod in an in-scope namespace hits the `pod-injector` MWC. The
operator's handler (`internal/webhook/pod_mutator.go`) decides:

```mermaid
flowchart TD
    P["Pod CREATE"] --> EX{"namespace excluded?<br/>(release ns, kube-system, ...)"}
    EX -->|yes| PASS["webhook not called (runc)<br/>— host infrastructure"]
    EX -->|no| CW{"has confidential.ai/cw?"}
    CW -->|yes| GC["inject get-cert<br/>(c8s-cert sidecar)"]
    CW -->|no| RC
    GC --> RC{"--cvm-mode=pod<br/>AND no runtimeClass<br/>AND not hostNet/PID/IPC?"}
    RC -->|no| DONE["admit"]
    RC -->|yes| INJ["set runtimeClassName<br/>(kata-qemu-snp if cw, else kata-qemu)<br/>+ kata nodeSelector + toleration"]
    INJ --> DONE
    DONE --> VAP{"enforce VAP"}
    VAP -->|"kata class OR host-ns"| OK["allowed"]
    VAP -->|otherwise| REJ["rejected (fail-closed)"]
```

Two independent injections, both keyed off the pod (not a CR):

1. **get-cert** — driven by the `confidential.ai/cw=<id>` annotation, in
   **any** mode. Injects a `c8s-cert` native sidecar that fetches the
   leaf cert from CDS on startup and renews it on a ticker, plus a
   `c8s-cert-wait` run-once init container (`/c8s probe-file --wait`) that
   blocks until the initial cert is written so downstream containers wait for
   it before launching. (An exec startupProbe cannot gate here: the locked
   kata guest denies `ExecProcessRequest`.)
2. **runtimeClass** — only under `--cvm-mode=pod` (which is enforcing).
   `kata-qemu-snp` for `cw`-annotated pods (confidential), `kata-qemu`
   otherwise.

**Exemptions** (the `webhook.yaml` MWC and the `kata-enforcement.yaml` VAP
binding render the same namespaceSelector exclusion list and must stay in
sync):

- **excluded namespaces** — the release namespace (operator, CDS,
  kata-image-puller: host infrastructure that installs/serves what CVMs
  depend on — the puller cannot run as a kata VM, its `/host` bind-mount
  would map into the guest) plus `kube-system`, `kube-public`,
  `kube-node-lease`, and `webhook.extraExcluded`.
- **host-namespace pods** (`hostNetwork`/`hostPID`/`hostIPC`) — a VM cannot
  share the host's namespaces. This is how `kata-deploy` (which sets
  `hostPID`+`hostNetwork`) is left as runc.

> **Why CDS doesn't use `cw` for its runtimeClass.** It must be a
> CVM, but it must *not* get a get-cert sidecar: that sidecar dials CDS,
> and CDS dialing itself from its own init container is a bootstrap deadlock.
> So the pod chart pins `runtimeClassName: kata-qemu-snp` **directly** in
> CDS's pod template and carries no `cw` annotation. It self-provisions its
> serving cert via RA-TLS bound to the SNP measurement.

---

## Certificate and attestation flows

**Node shapes (host attestation).** Workloads annotated `cw` get a get-cert sidecar
that dials CDS over the cluster Service (`--cds-url`); CDS verifies the request
against the **host** attestation-service DaemonSet and signs the CSR with its
in-memory mesh CA — verify and sign happen in one process.

```mermaid
sequenceDiagram
    participant W as workload (get-cert)
    participant A as CDS (host)
    participant AS as attestation-service (host DaemonSet)
    W->>A: request leaf cert (workload id)
    A->>AS: verify evidence
    Note over A: signs the CSR in-process (in-memory mesh CA)
    A-->>W: leaf cert + key
```

**kata (in-VM attestation + RA-TLS).** The pod chart renders no host
attestation-service; consumers dial `http://127.0.0.1:8400`, the in-VM
service baked into the guest. CDS self-provisions its own *serving* cert via RA-TLS using SNP
evidence from its own CVM before it serves. Workloads still get-cert from CDS,
but CDS now runs inside its CVM.

```mermaid
sequenceDiagram
    participant G as in-VM attestation-service (127.0.0.1:8400)
    participant A as CDS (CVM)
    participant W as workload (CVM, get-cert)
    Note over A,G: CDS mints RA-TLS serving cert from SNP evidence
    A->>G: attest (snp)
    W->>A: request leaf cert (over RA-TLS)
    Note over A: verifies evidence and signs the CSR in one process
    A-->>W: leaf cert + key
```

In kata mode the trust anchor is the **launch measurement**: CDS,
attestation-service, ratls-mesh, and policy-monitor are all part
of the guest image whose SNP digest a client verifies — see
[`kata-guest-base.md`](kata-guest-base.md) and
[`kata-image-policy.md`](kata-image-policy.md).

---

## Uninstall flow

The MWC is release-tracked, so `helm uninstall` deletes it along with every
other release resource — a `failurePolicy: Fail` webhook pointing at a deleted
operator Service cannot leak and block pod creation cluster-wide. The only
`pre-delete` hook in the charts is the nri-image-policy uninstall DaemonSet
(node-cloud and node-metal only — node-image's plugin is baked into the node
image), which unwinds the host-side NRI plugin install before the release
goes.

```mermaid
sequenceDiagram
    participant Helm as helm uninstall
    participant DS as nri uninstall DaemonSet
    participant K as kube-apiserver
    Helm->>DS: pre-delete hook (node-cloud/node-metal: unwind the host NRI plugin)
    Helm->>K: delete release resources (operator, MWC pod-injector, CDS, VAP, ...)
    Note over K: MWC removed with the release → no orphaned Fail webhook
```

kata-deploy separately runs `kata-deploy cleanup` on `preStop` to unwind the
host runtime install.

**`c8s uninstall`** wraps the helm step and adds the host sweep the preStop
hook cannot guarantee: after the release is gone, a short-lived privileged
DaemonSet removes whatever survived on each node, on every release shape
(leftovers may come from a previous install of a different shape). It refuses
to run under live kata pods (`--force` overrides), reads the release values
before deletion so install-time `-f` overrides are honored, and
`--host-sweep-only` recovers a cluster whose release a bare `helm uninstall`
already deleted. Full sweep inventory: [`kata.md`](kata.md#uninstalling).

---

## Quick reference

```bash
# Every flow below also requires --hardware-platform (the nodes' CPU TEE:
# sev-snp or tdx). --operator-keys authorizes `c8s allowlist` writes; a -f
# values file may carry the keys instead, and --force installs without.
# --upstream (with the port on its --workload-ref) points tls-lb at an adopted
# workload's mesh-wrapped headless Service (see operator.md, "tls-lb upstream").

# Node-image — nodes booted from the c8s node-guest-image, host-side
# components, no per-pod confidentiality.
c8s install --cvm-mode=node-image --hardware-platform=sev-snp --operator-keys operator-pub.pem \
  --workload-ref vllm=vllm/deployment/serving:8000 --upstream vllm

# Kata (enforcing): every workload pod becomes a kata VM, non-kata pods
# rejected, host-side mesh/attestation/image-policy replaced by their
# in-guest counterparts. --measurements pins the kata guest launch digest
# (from `c8s kata measure`); without it no cw workload can start.
c8s install --cvm-mode=pod --hardware-platform=sev-snp --operator-keys operator-pub.pem \
  --measurements <kata-guest-digest> \
  --workload-ref vllm=vllm/deployment/serving:8000 --upstream vllm

# RKE2 host — the distro is detected from the cluster, no extra flag.
c8s install --cvm-mode=pod --hardware-platform=sev-snp --operator-keys operator-pub.pem \
  --measurements <kata-guest-digest> \
  --workload-ref vllm=vllm/deployment/serving:8000 --upstream vllm

# Single-node / local build (no registry artifact, don't starve the one node).
# The puller is on by default; switch it off via a values file:
#   kata: {guestImage: {enabled: false}}
c8s install --cvm-mode=pod --hardware-platform=sev-snp -f single-node.values.yaml \
  --workload-ref vllm=vllm/deployment/serving:8000 --upstream vllm

# Uninstall: helm uninstall + sweep the kata artifacts off every node.
c8s uninstall
```

For the deeper "why" behind any of the kata pieces, follow the cross-links at
the top of this document.
