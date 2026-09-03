# c8s operator and Helm chart

The c8s operator installs the Kubernetes-facing c8s components. It hosts
status-mirror controllers, serves the pod-injection admission webhook, and
ships an embedded Helm chart for installing the operator, CRDs, RBAC, webhook
resources, attestation-api DaemonSet, and CDS (the Certificate
Distribution Service trust root).

## Overview

The operator tree is built around these pieces:

- `cmd/c8s operator` runs the controller-runtime manager, the
  `ConfidentialWorkload` status-mirror controller, and the pod-injection
  admission webhook.
- `cmd/c8s install` extracts the embedded chart from `internal/helmchart`
  and shells out to `helm upgrade --install`.
- `internal/helmchart/c8s` installs the operator Deployment and Service, the
  CRDs, RBAC, webhook configuration, attestation-api DaemonSet, and CDS.
- `internal/webhook` injects get-cert containers into opted-in pods so each
  workload can fetch and renew a leaf certificate through CDS.

The operator does not inject the RA-TLS mesh sidecar. Pod-to-pod mTLS remains
the responsibility of the node-level `ratls-mesh` DaemonSet. The chart-managed
mesh excludes `kube-system` and its own release namespace as local traffic
sources, so c8s control-plane agents (and, on kind/kubeadm-style clusters where
the API server runs as a `kube-system` pod, in-cluster webhook callers) do not
get captured by the pod-to-pod mesh path. The exclusion is one-sided: it
removes those pods as PREROUTING sources but keeps their IPs in the destination
ipset, so a workload that connects to a `kube-system` or release-namespace pod
by pod IP — bypassing the Service VIP — will still be DNATed into the mesh and
fail mTLS against a peer with no ratls sidecar. In-cluster Service-VIP traffic
to those namespaces is unaffected because kube-proxy DNATs the VIP before the
mesh chain matches.

Confidential-workload pods (label `confidential.ai/cw`) get a stricter
inbound posture from the always-on cw guard: the mesh drops FORWARD-path
traffic to their pod IPs, so Service-VIP dials and excluded-namespace sources
are blocked instead of reaching the workload in plaintext.
`ratlsMesh.cwInboundEnforcement.passthrough` (default `udp:53,tcp:53`) is the
reply allowlist that keeps DNS working; an empty list is strict drop-all. It
admits replies only on the stock ephemeral window (32768-60999), which costs a
cw pod its DNS if the pod moves `net.ipv4.ip_local_port_range` *and* the
dataplane breaks the reply's conntrack tuple — see the
`RATLSMeshCWInboundDrops` alert description for the triage path.
Only mesh-delivered traffic and node-local host processes
(kubelet probes) reach cw pods.

## Ownership model

Installing the c8s chart is a platform-admin operation, not a fully
self-service application-team workflow.

The install creates or updates cluster-scoped resources such as CRDs, RBAC,
the operator Deployment, the webhook Service and configuration, and the
attestation-api DaemonSet. Enabling injection also requires platform-owned
prerequisites:

- the chart-managed CDS Service reachable from workload pods;
- allowlist storage and a measurement allowlist for any workload allowed to
  mutate the allowlist;
- a CDS public-bundle PVC for CA continuity;
- nodes with the expected TEE device access for attestation-api;

After the platform installs those pieces, workload opt-in is self-service:
application teams annotate their pod templates with `confidential.ai/cw`.

## Code layout

The main source directories are:

| Path | Purpose |
|---|---|
| `cmd/c8s/` | User-facing operator and install CLI commands. |
| `internal/controller/` | controller-runtime manager, webhook bootstrap, and status mirror setup. |
| `internal/webhook/` | Pod mutation logic, get-cert args, cert volume permissions, and unit tests. |
| `internal/helmchart/c8s/` | Embedded Helm chart templates and defaults. |
| `internal/helmchart/chart_test.go` | Helm render tests for the supported chart-managed CVM-only shape. |
| `cmd/get-cert/` | Certificate bootstrap and renewal helper, including private-key file mode handling. |

## Default install behavior

The supported chart shape is chart-managed and CVM-only. The chart does not
support a non-CVM install shape or a bring-your-own CDS endpoint shape.

- The chart renders webhook, attestation-api, and CDS together.
- The webhook is wired to the chart-managed CDS Service.
- CDS verifies evidence, issues EAR tokens, and signs workload CSRs in one
  process; EAR validation and signing share that process, so there is no
  internal Service hop or JWKS fetch between them.
- allowlist admin is EAR-authorized through CDS; the chart does not render a
  CDS allowlist password or attestation-api API key into Kubernetes
  Secrets.
- Sandbox identity needs the node addresses CDS may dial for a pod's admission
  inventory. CDS derives them **live from the cluster's node objects** — one
  host route per node InternalIP, kept current as nodes are added, replaced,
  or removed — over read-only node access the chart grants its ServiceAccount.
  A host route per node rather than a covering range, because on a CNI that
  assigns pod IPs from the node subnet (AWS VPC CNI, Azure CNI) any range
  covering the nodes covers the pods too, and the bound would be absent while
  looking configured. `c8s install` preflights the same derivation and fails
  rather than proceeding if it cannot determine them or a node address sits
  inside a pod range; such an address is excluded from the bound at runtime
  too, and CDS logs it.

  On a cluster whose node network is separate from the pod network, pass
  `--node-cidr <range>` instead: CDS then uses the static range and the chart
  grants no node access. (docs/ratls.md, "Sandbox identity".)

  **Under `--cvm-mode=pod` the inventory is inside each kata guest** and answers
  on the guest's pod IP, so `c8s install` pins `cds.sandboxInventoryCIDRs` to the
  cluster's **pod range(s)** (read from `spec.podCIDRs`) instead of leaving CDS
  to derive node host routes. The address bound is not what separates a
  workload from its guest's inventory there — both share the guest's IP; the
  RA-TLS handshake CDS runs against the inventory endpoint is, since only the
  guest's own attested mesh identity can present that leaf. A CNI that runs its
  own IPAM leaves `spec.podCIDR` empty; the install then fails and asks for
  `--node-cidr <pod-cidr>` explicitly.
- `image.tag` or `image.digest`, `attestationApi.image.tag` or
  `attestationApi.image.digest`, and `cds.image.tag` or
  `cds.image.digest` are required; the CLI passes its build version when
  running `c8s install`. Unstamped local builds report version `dev`, and the
  install CLI maps that to the `main` branch tag because CI does not publish
  `dev` (CI publishes `main` and `latest` for every image on the default
  branch).

This means a default platform install creates the operator, CRDs, RBAC,
webhook, attestation-api, and CDS. It does not mutate
application workloads until those workloads opt in with
`confidential.ai/cw`.

Install with the CLI. Adopt a running workload as a CW and front it behind
tls-lb with `--upstream` (see [Existing workload adoption](#existing-workload-adoption)
and [tls-lb upstream](#tls-lb-upstream)):

```bash
c8s install \
  --workload-ref vllm=vllm/deployment/serving:8000 \
  --upstream vllm
```

### Existing workload adoption

If vLLM is already deployed, `install` can adopt the router as one CW and the
serving engine as another, giving each its own confidential workload identity
without any GitOps overlay wiring:

```bash
c8s install \
  --workload-ref vllm-router=vllm/deployment/vllm-deployment-router:8000 \
  --workload-ref vllm-engine=vllm/deployment/<serving-engine-deployment> \
  --upstream vllm-router
```

The ref syntax is `<cw-id>=<namespace>/<kind>/<name>[:<port>]`, where kind is any
resource exposing a pod template at `spec.template` (`deployment`,
`statefulset`, `daemonset`, or an operator CRD such as `<kind>.<group>`); the
optional `:<port>` is the tls-lb upstream port, needed on the ref `--upstream`
selects. After Helm reports the c8s release ready, the CLI patches each workload
pod template with `confidential.ai/cw: <id>`. Those rollouts go through the
webhook, and the workload-service reconciler creates the `c8s-<id>` headless
Services. `--upstream vllm-router` points tls-lb at
`c8s-vllm-router.vllm.svc.cluster.local:8000` (its `<cw-id>` must be one of the
adopted refs, carrying a `:<port>`). With `--resolve-digests=true`, install resolves adopted workload
images into `nriImagePolicy.bootstrapAllowlist.digests` so image admission (the
host NRI plugin, or the in-guest policy-monitor under `--cvm-mode=pod`) allows those
rollouts.

`c8s install --install-crds=false` passes Helm's `--skip-crds`; CRDs are
advisory and not required for pod injection. That path also disables the
CRD-backed status mirror controller; if CRDs are absent at runtime, the
operator skips that controller rather than failing startup.

## Kata runtime installation and enforcement

`c8s install --cvm-mode=pod` additionally installs the Kata Containers runtime onto
the cluster: the embedded chart renders the upstream `kata-deploy` DaemonSet
(which installs QEMU, the kata runtime, and the `containerd-shim-kata-v2`
shim onto every node) and the `kata-qemu` / `kata-clh` / `kata-qemu-snp` /
`kata-qemu-tdx` RuntimeClass objects. The host containerd config path (`k8s` vs `rke2`
layout) is detected from the cluster's kubelet versions.

`--cvm-mode=pod` is **enforcing** — there is no kata-without-enforcement shape:

- the operator's pod webhook injects a `runtimeClassName` into workload pods
  that don't request one — `kata-qemu`, or `kata-qemu-snp` for pods annotated
  `confidential.ai/cw`;
- a `ValidatingAdmissionPolicy` rejects workload pods that request a non-kata
  `runtimeClassName`;
- the host-side ratls-mesh, attestation-api, and nri-image-policy are
  disabled — their function runs inside the kata-guest-base VM image.

Host-namespace pods and system namespaces are exempt. The Kata stack is off
by default — a plain `c8s install` is unchanged.

See [`docs/kata.md`](kata.md) for the design (why it wraps upstream
kata-deploy), the threat model, distro support, the one-shot bootstrap-window
caveat, and the SEV-SNP-host / GPU constraints.

## Uninstall

`c8s uninstall` reverses `c8s install`. It runs `helm uninstall` to remove the
release (operator, CDS, attestation-api, ratls-mesh, tls-lb, the
webhook configuration, RuntimeClasses, and the enforcement policy). The
`MutatingWebhookConfiguration` is release-tracked, so it is deleted with the
release — a `failurePolicy: Fail` webhook cannot outlive the operator Service
and block pod creation cluster-wide.

It then **sweeps the host-side artifacts** that the chart's hooks and the
`kata-deploy` preStop cleanup cannot guarantee — on every release shape, since
leftovers may come from a previous install of a different shape. The swept set
(NRI image-policy plugin, ratls-mesh netfilter state, nydus unit, kata payload
and guest images, RKE2 containerd-prep template, node labels) is in
[`docs/kata.md`](kata.md#uninstalling). The host paths are read from the
release's computed values *before* deletion, so install-time `-f` overrides are
honored.

Guardrails:

- Uninstall **refuses to run while pods with a kata RuntimeClass are still
  scheduled** — pulling the runtime out from under a confidential workload kills
  it without cleanup. Delete those workloads first, or pass `--force` (the kata
  VMs keep running unmanaged but cannot restart). The release's own
  chart-managed pods (CDS and tls-lb pin a kata RuntimeClass) are excluded by
  release namespace + `app.kubernetes.io/instance`, and the refusal reports how
  many it skipped; see [`docs/kata.md`](kata.md#uninstalling).
- `--host-sweep-only` runs only the host sweep, for a cluster whose release a
  bare `helm uninstall` already removed but whose nodes still carry artifacts;
  it uses the chart defaults and the distro detected from the cluster.
- `--delete-crds` and `--delete-namespace` are **off by default** and
  destructive: the former deletes the `ConfidentialWorkload` CRD and every
  `ConfidentialWorkload` object with it; the latter deletes the release
  namespace and everything left in it.

Requires the `helm` and `kubectl` CLIs on `PATH`. See
[`docs/install-flows.md`](install-flows.md#uninstall-flow) for the uninstall
sequence and [`docs/kata.md`](kata.md#uninstalling) for the host sweep in
full.

## Chart-managed CDS

The supported deployment is chart-managed CDS running inside the intended CVM
trust boundary.

The chart installs a CDS Deployment, Service, ServiceAccount, and either an
`emptyDir` allowlist DB or a PVC when `cds.persistence.enabled=true`. The
operator injects pods with the chart-managed CDS Service URL. Allowlist
writes (`POST`, `PUT`, `DELETE /allowlist`) are authorized by an operator key:
the caller presents a short-lived token signed by an operator EC private key
whose public half is pinned in `cds.operatorKeys`. The `c8s allowlist` CLI mints
that token (see the README, "Managing the image allowlist"). Without
`cds.operatorKeys` set, allowlist writes are rejected while reads keep serving.

CA-bundle refresh traffic uses the chart-managed cluster Service. Trust for
those flows comes from EAR validation, measurement allowlists, and CA
continuity checks rather than WebPKI on the Service hop.

CDS verifies EAR JWTs against its own in-process signer; there is no JWKS
fetch to a separate component. The chart does not render a CA private key into
a Kubernetes Secret. CDS generates its mesh CA key inside the process, keeps it
in memory, and persists only the public CA bundle in the configured
public-bundle PVC.

Minimal allowlist-write values (pin operator public keys):

```yaml
cds:
  operatorKeys: |
    -----BEGIN PUBLIC KEY-----
    ...operator EC public key...
    -----END PUBLIC KEY-----
```

Prefer `c8s install --operator-keys operator.pub`, which reads the file and
sets this value for you. In a GitOps flow, `c8s render-values --operator-keys
operator.pub` embeds the content into the emitted values.

The value is the PEM **content**, never a file path — a path from the machine
that rendered the values is meaningless in-cluster, and the chart fails the
render when the value doesn't look like PEM.

### Operational warning: CDS is a singleton

CDS runs as a single replica with the in-memory mesh CA key, and **any
restart is a full re-bootstrap event**: the replacement pod generates a
fresh CA whose public key is not signed by anything ratls-mesh already
trusts. `pkg/ratls/cdsclient`'s continuity check then refuses the new CA on
the next `/ca` poll, CDS keeps signing leaves with the new key, no workload
trusts them, and the mesh degrades as old leaves expire. Recovery is to
restart every workload so its get-cert init container re-runs the CDS
provisioning flow.

The tls-lb discovery endpoints (`/.well-known/mesh-ca.pem`,
`/.well-known/cds-cert.pem`, `/v1/discovery`) track the new CA without a
tls-lb restart: the c8s-cert sidecar polls CDS's `/ca` every
`tlsLb.certProvisioning.caWatchInterval` (default 1m) over the same
RA-TLS-verified channel it obtains certificates on, and re-issues its leaf —
rewriting the served CA bundle and discovery document — as soon as CDS holds
a CA the served bundle is missing. External clients that pinned the old CA
must still re-fetch it from the discovery endpoint.

There is **no scheduled in-process CA rotation today** — no cds flag or
loop drives it, so every CA fingerprint change is a restart-shaped
re-bootstrap. (An unwired rotator exists at `internal/issuer.CARotator`:
it signs a successor CA with the still-live current CA's key, so the
continuity check would accept it and workloads would pick it up on their
next `/ca` refresh, without re-bootstrap. Wiring it into `c8s cds` is
future work.)

With CDS a singleton:

- run CDS with `replicas: 1` and `strategy: Recreate` (default in
  this chart);
- guard the CDS Deployment with a PodDisruptionBudget that blocks
  voluntary disruptions;
- treat any CDS restart as a planned maintenance event with workload
  churn;
- watch CDS startup logs for the active CA fingerprint — any fingerprint
  change means a restart happened and workload re-provisioning is needed.

### Operator-added allowlist entries across restarts

The same restart that re-bootstraps the mesh CA also resets the **served
allowlist**. CDS seeds its store from the install seed at startup, then serves
whatever an operator adds with `c8s allowlist add`. With
`cds.persistence.enabled=false` (the default) that store is an `emptyDir`, so a
restart (OOM, drain, upgrade, scale) drops every operator-added digest back to
the install seed — workloads pulling those images are denied roughly one worker
poll interval (~5s) later. CDS logs a warning at startup when persistence is
off. To keep dynamic entries across restarts set `cds.persistence.enabled=true`
(an RWO PVC); otherwise re-run `c8s allowlist add` after any CDS restart.
Component/floor digests are unaffected — they are re-seeded and, unlike dynamic
entries, are also enforced from the baked floor.

### Static allowlist

Under `staticAllowlist.enabled=true` (set by `c8s install --static-allowlist`,
see [`static-allowlist.md`](static-allowlist.md)) CDS serves the bundle the
node measured into RTMR[3] and nothing else. The chart renders CDS with
`--static-allowlist --policy-dir /run/confai/policy --allowlist-seed
/run/confai/policy/static-allowlist.json` and
`--attestation-api-url unix:///run/confai/attestation-api.sock`, mounts the
policy directory and the socket directory read-only as `hostPath` volumes of
type `Directory`, and gives the pod supplementary group 65532 so it can
connect to the root-owned socket. There is no `cds.operatorKeys`, no
persistence, and no seed ConfigMap: every start reseeds from the measured
member, so a restart cannot add entries and allowlist writes do not exist.
`cds.measurementsConfig` carries one entry, `{MRTD, RTMR[1], RTMR[2],
RTMR[3] = ForStaticAllowlist(index)}`, which `/attest` requires of every
requester and CDS requires of its own evidence at start. The render fails
(`VALIDATION_ERROR kind=static_allowlist_*`) on `cds.operatorKeys`,
`cds.persistence.enabled`, `kata.enabled`, `attestationApi.enabled`,
`nriImagePolicy.enabled`, a `cvmMode` other than `node`, a platform other than
TDX, or an empty `cds.measurementsConfig`.

## Attestation-api

The attestation-api DaemonSet binds pod loopback and is served to on-node
consumers by its attest-proxy sidecar over a Unix socket in
`nriImagePolicy.hostPaths.runtimeDir`; no Service renders.

The c8s node image serves the same API itself: `c8s-attest-socket.service`
runs `c8s attest-proxy` in front of the baked attestation-api on the
root-owned `unix:///run/confai/attestation-api.sock` (mode 0660, group
65532). The baked NRI plugin config dials that path, and under
`staticAllowlist.enabled` so do CDS, tls-lb, ratls-mesh, the operator, and
every injected sidecar (`staticAllowlist.attestationSocketDir`, default
`/run/confai`). A path in a measured config, unlike an address, is one the
control plane cannot repoint; the verdict stays unsigned, the socket is what
makes it immutable. The chart refuses `attestationApi.enabled` beside
`staticAllowlist.enabled` because nothing would dial the DaemonSet.

Two operational notes:

- **Upgrading from a release that rendered the attestation-api Service
  deletes it.** Already-running cw pods keep their old
  `--attestation-api-url`, and their get-cert renewals fail once the Service
  is gone — roll cw-annotated workload pods after the upgrade so the webhook
  re-injects the socket URL. New pods are unaffected.
- **A wedged attestation-api does not self-restart.** Its health signal is
  the attest-proxy's exec probe, so a hung (not crashed) API process shows as
  a NotReady `c8s-attestation-api` pod with a crash-looping attest-proxy
  container; delete the pod to restart the pair.

## Verifying attestation after install

`c8s verify` (and `c8s cds verify`, shorthand for `c8s verify --kind cds`) fetches
a component's TEE attestation evidence — AMD SEV-SNP or Intel TDX — and verifies it
against the hardware signature chain plus a pinned launch measurement. Use it to
confirm CDS — or the load balancer — is a genuine TEE running the expected code
after install.

It verifies **in-process** with `attestation-go` — the Go port of the same
attestation-rs engine the cluster runs. That engine auto-detects the platform and
AMD product, including Zen4c (Siena/Bergamo) which stock `go-sev-guest` cannot
classify. The only requirement on the machine running `c8s verify` is outbound
HTTPS to AMD KDS (`kdsintf.amd.com`), which it uses to fetch the VCEK for a bare
report; no container runtime is needed.

```bash
# CDS's RA-TLS endpoint answers unattested clients. Under kata the baked guest
# env exempts the front-door port from the in-guest mesh redirect
# (C8S_MESH_INBOUND_PASSTHROUGH=tcp:8443 — see docs/kata.md), so a plain
# port-forward reaches it:
kubectl port-forward -n c8s-system svc/c8s-cds 8443:8443 &

c8s cds verify https://localhost:8443 --measurements <sha384-launch-digest>

# JSON + exit codes for CI:
c8s cds verify https://localhost:8443 --measurements-file digests.txt -o json
```

PKI/SAN mismatch when dialing localhost or a pod IP is fine — `verify` trusts
the attestation embedded in the serving cert, not the certificate chain.

The launch digest(s) to pin are the same values discussed under measurement
pinning (kata guest digest via `sev-snp-measure`, or the node CVM digest). They
are enforced client-side against the report's launch measurement; with no
`--measurements` the command still runs but prints an UNSAFE warning — any
genuine TEE is accepted.

`--init-data <sha256-hex>` pins the guest's init-data document: the kata shim
commits `sha256(document)` at launch, and a verdict pinned this way fails
unless the evidence commits exactly that digest. The document renders
deterministically from the pod's role and CDS measurement set (`pkg/initdata`),
so the digest comes from the same pipeline that chose those measurements. With
no `--init-data` the committed digest is still shown on SNP/TDX, labelled as
compared against nothing.

On TDX, `--measurements` pins MRTD, which covers only the TDVF firmware: the
guest kernel and rootfs live in RTMR[1] and RTMR[2], and a verdict pinned on
MRTD alone warns that they are unmeasured by that policy. To pin the whole
image, pass `--image-manifest <file>` — a build-artifact manifest published
with the guest image build, carrying `mrtd`, `rtmr1` and `rtmr2` (96
lowercase hex chars each, each named once) under its `tdx` object, as a
confos manifest publishes them; a flat top-level tuple is also accepted.
The manifest ships as a `manifest.json` layer in the image's oras artifact
(the tag the CDI ref carries without its `-cdi` suffix), so it can be
fetched with `crane blob` for the exact build a node booted. The
three registers are loaded atomically from that one provenanced manifest and
all three are compared exactly, the same rule `c8s get-kubeconfig` applies to
the same manifest — MRTD is deliberately not merged into the `--measurements`
allowlist, since an allowlist is satisfied by any member and a launch digest
from a different build would then pass alongside this manifest's
RTMR[1]/RTMR[2].

For that reason `--image-manifest` **replaces** the allowlist rather than
combining with it: passing it together with `--measurements` or
`--measurements-file` is a usage error (exit 1). The manifest already pins
MRTD to exactly one value, so an allowlist beside it can only restate that
digest or contradict it — and a contradiction builds a policy no guest can
ever satisfy, failing every run with an `MRTD mismatch` that reads like an
attestation failure rather than the typo it is. Pin this image and drop
`--measurements`/`--measurements-file`; or, to accept several firmware
images, drop `--image-manifest` and give up its RTMR[1]/RTMR[2] kernel and
rootfs pins with it.

`--rtmr 3=<sha384-hex>` can additionally pin the runtime register — the ordered
operator-key/workload extend chain (`pkg/runtimemeasure`) — which is a
deployment property, not a cluster identity, and therefore requires
`--image-manifest`: the untrusted host picks the guest image, so it can boot
anything and reproduce that chain. (`--expected-rtmr3` is the former spelling of
the same pin and still works, but `--rtmr` now covers every register: 1 and 2
conflict with `--image-manifest` because they *are* the image, while 3
requires it.) `--operator-pkey <file>` is the same pin
without the arithmetic: point it at the operator **public** key PEM (the
verbatim bytes the guest initrd hashed, as written by `openssl ec -pubout`)
and `verify` derives the dynamic-mode register of an operator-key boot
itself: the seed `SHA-384(0x00*48 ‖ SHA-384(pubkey))` extended by the mode
event `SHA-384("c8s/rtmr3/mode/dynamic/v1")` that the node image extends
before containerd starts. The two are mutually exclusive — one register, one
expected value — and `--operator-pkey` carries the same `--image-manifest`
requirement. Note its scope: it pins the seed-plus-mode register, i.e. a node
with no per-workload RTMR[3] extends on top. That is what every node reports
today, because the workload measurer ships only inside the kata guest image;
`c8s get-kubeconfig` is the command that also folds `--workload-image`
extends into the expected register. Supplying any of these
flags against SEV-SNP evidence is a policy error, not an ignored option: SNP
has no runtime measurement registers.

`--static-allowlist <bundle>` is the static-mode sibling of
`--operator-pkey` ([`static-allowlist.md`](static-allowlist.md)). The bundle
is a directory of members or the `static-allowlist.json` alone (an `.iso` is
refused). `verify` lints the member as sealed, derives the static register
`Extend(Extend(Zero, SHA-384("c8s/rtmr3/mode/static/v1")),
SHA-384("c8s/rtmr3/policy/v1:" ‖ index))` from it, and holds the leaf's
matched-workload stamp to the member's own bytes. It requires
`--image-manifest`, `--workload`, and `--mesh-ca` (the stamp is CA-vouched,
and the mesh CA carries no evidence of its own yet), and conflicts with
`--operator-pkey`, `--expected-rtmr3`, `--rtmr 3=`, and `--allowlist`. A
verified verdict reports `static_policy_digest`, the index digest the
register was derived from.

A TDX verdict pinned on MRTD alone is **rejected**, not warned about, when no
operator-pinned CA anchor (`--mesh-ca`) stands beside the measurements: the
measurement pins are then the entire trust anchor, so an incomplete image
policy leaves nothing behind the verdict. A chain checked against a CA the
responder committed into its own transcript (attest-pq) does not downgrade
this — that anchor is responder-chosen.

Certificate-sourced evidence must also carry an authenticated certificate
body. A self-signed leaf authenticates its own body under the attested key; a
CA-issued one does not, and `x509` parsing verifies no signature — so a
CA-issued leaf is accepted only when its chain verifies against `--mesh-ca`,
or when a live TLS handshake proves the peer holds the attested key. For
`--mode discovery` on an https target that handshake doubles as the front-door
check below: a CA-issued discovery certificate the live door presents
byte-identically is authenticated by possession. A door serving some other
certificate — or a fetch with no handshake to observe (a non-https target) —
still requires `--mesh-ca` (the document publishes `cds_tls.mesh_ca_url`).

Exit codes are a CI contract: `0` verified, `1` usage error, `2`
verification/policy failed (e.g. wrong measurement), `3` evidence unavailable
(unreachable/unparseable), `4` partially verified — the evidence verified, but
a property it presents is not proven. The three partial cases today: the
front door's live TLS handshake presenting a serving certificate the discovery
evidence does not attest (a WebPKI front door, whatever the document's
`public_tls.mode` declares — the verdict keys on the handshake observed on the
verifier's own connection at verify time, not the host-served declaration;
what is proven is the tls-lb pod's TEE residency and measurement, not the TLS
endpoint clients reach), a discovery target fetched over a non-TLS connection
(no live handshake observed — the declared `public_tls.mode` is then the only
mode signal, a host-served claim nothing authenticates), and attest-pq or
saved-bundle evidence without `--mesh-ca` (the mesh chain anchors to a CA the
responder committed into its own transcript, so which deployment the endpoint
belongs to is not proven). JSON renders these as
`verified: false, partial: true` with a `not_proven` list, so a gate checking
`verified` fails closed while scripts can still tell partial from failure.

Caveats the output surfaces:

- **Freshness.** Verifying an RA-TLS serving cert binds REPORTDATA to the
  certificate key, not a per-request nonce, so it proves "this key was born in a
  TEE with this measurement" but not "freshly now" (`fresh: false`).
- **Reachability under kata.** Reach each component on its public/host address,
  not the in-cluster ClusterIP — the ClusterIP path goes through the mesh and
  demands an attested client cert (`tls: certificate required`). CDS's RA-TLS
  endpoint and the tls-lb's nginx serving port both answer unattested clients on
  their public address (the tls-lb serves `/v1/discovery` there with no client
  cert), so `c8s cds verify` and `c8s verify <lb>` work without any mesh changes.

### Trust gate: `c8s get-kubeconfig`

`c8s get-kubeconfig` obtains an admin kubeconfig from a measured node CVM.
Before any credential flows it enforces the node's **full measured identity**,
and it enforces the identical policy twice — on the initial attestation gate
and again on the RA-TLS credential-release connection:

- **platform** — the `--image-manifest` shape selects it (a TDX tuple or SNP
  `snp_variants`); a node of any other platform is refused up front;
- **guest image (TDX)** — MRTD, RTMR[1] and RTMR[2] must match the tuple from
  `--image-manifest` (required), an explicitly selected, provenanced
  build-artifact manifest carrying all three fields under its `tdx` object. A
  generic artifact-hash `manifest.json` is not an image pin and is rejected;
- **RTMR[3] chain (TDX)** — the register must equal the operator-key seed
  (`pkg/runtimemeasure.ForOperatorKey` over the exact pubkey PEM bytes)
  extended by the dynamic mode event (`runtimemeasure.ForDynamic`), then, in
  order, by each digest-pinned `--workload-image` ref (tags are rejected).
  With no `--workload-image` the register must equal `ForDynamic(seed)`; the
  bare seed is rejected. With `--static-allowlist <bundle>` in place of
  `--operator-key` the register must instead equal
  `runtimemeasure.ForStaticAllowlist` over the bundle's index, the static
  mode event followed by the policy event ([`static-allowlist.md`](static-allowlist.md));
  `--workload-image` is then a usage error, and the credential is fetched
  without an operator token;
- **guest image + operator key (SEV-SNP)** — the report's MEASUREMENT must be
  one of the per-SMP launch digests pinned by `snp_variants` (one image has
  one digest per vCPU count), and HOSTDATA must equal `SHA-256(operator
  pubkey)`. SNP has no runtime-extend register, so `--workload-image` is a
  usage error there rather than a silently ignored flag;
- **certificate body** — the credential-release serving cert must sit inside
  its validity window (NotBefore with a bounded 5-minute skew, NotAfter with
  none) and, being self-signed, verify its own signature with its attested
  key.

The released kubeconfig's client certificate is
`CN=operator, O=c8s:node-operators`, with a one-hour default (and baked
node-image) TTL. The node image's baked `cred-release-rbac` RKE2 AddOn binds
that group to the built-in `cluster-admin` ClusterRole through ordinary RBAC,
and `cred-release.service` does not start serving until that binding exists,
so a released credential is authorized the moment it is issued.
`system:masters` is deliberately avoided because it bypasses authorization
and admission webhooks and cannot be revoked through RBAC. The default group
is only meaningful where such a binding exists: on a cluster that is not the
c8s node image, create an equivalent `ClusterRoleBinding` or pass `--cert-org`
for a group that cluster already authorizes.

Do not read the binding as a privilege boundary. On this single-node cluster
`cluster-admin` is root-equivalent on the guest: `kube-system` is exempt from
PodSecurity admission, so a privileged pod with a hostPath mount of `/` is one
`kubectl` away. RBAC is used for revocability and policy, not containment; the
credential's blast radius is bounded by who can obtain it (the attestation gate
above), by the one-hour TTL, and by the verity root and per-boot ephemeral
writable state of the guest.

Revocation is a launch-time decision. Deleting or editing the live
ClusterRoleBinding cuts access immediately, but only until the next boot: the
manifest is baked into the read-only root and everything RKE2 writes, the
cluster state included, lives on the scratch disk, which is re-encrypted with
a fresh random key every boot. `.skip` markers and `config.yaml.d` drop-ins
are lost with it, so there is no in-guest switch that survives a restart, by
design. To revoke durably, relaunch without `opkeydata`, or with a rotated
operator key, so the old key can no longer obtain a certificate. A certificate
already issued stays usable for the remainder of its one-hour TTL.

A static node has no operator key and nothing to revoke: `cred-release`
serves any caller once the node's RTMR[3] matches the bundle, because the
static design already treats `cluster-admin` as the adversary. Relaunching
with another bundle changes the register, and clients pinned to the old
bundle refuse the node.

What the gate proves: a genuine guest of the manifest's platform booted
exactly the pinned image, was launched to trust exactly this operator key,
and (on TDX) ran exactly the expected measured workloads. Under
`--static-allowlist` it proves instead that the node measured exactly the
reviewed bundle, so its sealed plugin admits only that bundle's entries.
What it does not prove: anything about images or keys the manifest and
flags do not name, or the provenance of the manifest file itself — select
it deliberately from the trusted image build. An RTMR[3]-only gate would
prove much less: the untrusted host stages the operator public key, so it
can boot **any** image and reproduce the operator-key/mode register — the
image tuple is the identity anchor, and RTMR[3] then binds the key and
workload set to it.

## Injection contract

The webhook only reads pod metadata. A `ConfidentialWorkload` CR is not
required for injection. The single webhook entry (`pods.c8s.confidential.ai`)
excludes the release namespace via its namespaceSelector, so the chart's own
pods never hit the webhook during bootstrap; tls-lb's get-cert containers are
rendered directly into its pod template by the chart instead of injected.

Opt a pod template in with:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api
```

`confidential.ai/cw` is required. The certificate SAN is derived from it: an
id that names the operator-managed headless Service gets that Service's
in-cluster DNS name (`c8s-<id>.<namespace>.svc`, which CDS's default
`--dns-san-pattern` signs); an id that cannot name a Service (dots, length
over 59) is used as the SAN verbatim and must match a CDS pattern itself.
A workload adopted into c8s whose clients already dial an existing Service
name can set `confidential.ai/c8s-san` to that name instead; the annotation
value is used as the requested SAN verbatim and must match a CDS pattern.
Injection does not require a CR lookup.

For opted-in pods, the webhook:

- adds an in-memory `emptyDir` volume named `c8s-certs`;
- mounts that volume read-only into application containers at
  `/etc/c8s/certs`;
- prepends a `c8s-cert` native sidecar (init container with
  `restartPolicy: Always`) that fetches the first cert before application
  containers start and then renews `tls.crt` every
  `webhook.getCert.renewInterval`;
- prepends a `c8s-cert-wait` run-once init container after it that gates the
  application containers on the initial cert (see below);
- stamps `confidential.ai/c8s-injected=true` to make reinvocation a no-op.

The sidecar runs:

```bash
get-cert \
  --cds-url=https://<release>-cds.<namespace>.svc:8443 \
  --attestation-api-url=<release-attestation-api-url> \
  --san=<derived from confidential.ai/cw, e.g. c8s-api.default.svc> \
  --out=/etc/c8s/certs/tls.crt \
  --key-out=/etc/c8s/certs/tls.key \
  --ca-out=/etc/c8s/certs/ca.crt \
  --key-mode=<webhook.certVolume.keyMode> \
  --renew-interval=<webhook.getCert.renewInterval> \
  --reload-nginx=<from annotation> \
  --continue-on-initial-error
```

`--key-out` is idempotent: on a kubelet restart of the sidecar it reuses the
key that's already on disk, so the previously-issued cert chain stays valid.
`tls.crt` is the full chain (leaf first, mesh CA after); `ca.crt` is the mesh
CA alone, world-readable, for applications that take the trust anchor as a
separate file (`mysqld --ssl-ca`, clients doing `VERIFY_CA` against peers on
the mesh). File names are overridable per pod with `confidential.ai/c8s-cert-file`,
`confidential.ai/c8s-key-file`, and `confidential.ai/c8s-ca-file`.

`tls.key` is written `0640` owned by the get-cert user (UID/GID 65532, the pod's
`fsGroup`). An image whose entrypoint starts as root and then drops to a
service user (`gosu`, `su`) loses supplementary groups and can no longer read
it; either run the container as UID 65532, or have the entrypoint copy the
key into a directory the service user owns before dropping privileges.
The `c8s-cert-wait` init container (`/c8s probe-file --wait /etc/c8s/certs/tls.crt`)
gates the application containers on the initial cert being written: it blocks
until the cert exists, then exits, and normal init-completion ordering holds the
workload until then — fail-closed. It is a plain init container rather than a
`startupProbe` on the sidecar because the locked `kata-qemu-snp` guest denies
`ExecProcessRequest` by design, so an exec probe could never pass there and the
workload would hang in `Init`; a container blocking on its own is a
`CreateContainerRequest` the guest allows. Renewals rewrite the file on disk;
application-level TLS reload remains the workload's responsibility unless the
pod opts into one of the c8s reload annotations.

The sidecar is long-lived rather than a run-once init container because under
kata it doubles as the pidns anchor for `shareProcessNamespace` — see
`docs/kata.md` for the underlying constraint.

Platform-owned workloads can specialize the same webhook behavior with typed
c8s annotations for the cert volume, cert/key filenames, renewal interval,
nginx reload, Secret watch paths, discovery output, and get-cert UID/GID.
(tls-lb, living in the webhook-excluded release namespace, renders equivalent
get-cert containers directly from the chart's templates instead.) The
webhook rejects incomplete reload-watch or discovery annotation sets during pod
admission instead of admitting a pod that cannot serve its configured
certificate/discovery path.

## tls-lb upstream

### Built-in allowlist route

The chart publishes CDS's complete `/allowlist` API through tls-lb by default.
It renders exact `/allowlist` and `/allowlist/` prefix locations backed by the
release's chart-managed CDS Service, so lookalike paths such as `/allowlisted`
are not exposed. The tls-lb-to-CDS hop verifies CDS's RA-TLS attestation using
`cds.measurements`; `c8s install --measurements` populates that pin in node-CVM
mode. An empty pin still verifies that the peer is a TEE but accepts any launch
measurement, which is unsafe outside development.

Before nginx collapses requests onto the loopback proxy connection, it
rate-limits the route while it still has the public client address. Mutation
methods are limited per client (`tlsLb.allowlist.rateLimit.requestsPerSecond`/
`burst`, default 1 r/s, burst 5) and in aggregate across all clients
(`totalRequestsPerSecond`/`totalBurst`, default 8 r/s, burst 15). The
aggregate bound matters because CDS rate-limits per source IP and sees every
front-door request as the one tls-lb pod IP: without it, many distinct public
clients each inside their per-client budget could drain the single CDS bucket
that signed operator writes share. The chart requires the per-client values
not to exceed the totals and the totals to stay below `cds.rateLimit`/
`rateBurst`. Reads (GET/HEAD) are limited per client under
`tlsLb.allowlist.readRateLimit` (default 20 r/s, burst 40) so unauthenticated
read pressure on CDS — which also serves attestation issuance and node
allowlist fetches — stays bounded; CORS preflights are exempt. If a flood
saturates the front-door buckets, signed writes still work over a direct CDS
URL or port-forward, which CDS accounts under the caller's own source IP.
LoadBalancer and NodePort Services default to `externalTrafficPolicy: Local`
while this route or the attestation sidecar (`tlsLb.attest.enabled`) renders,
so nginx receives the public source address their per-client keys need;
`tlsLb.service.externalTrafficPolicy` overrides (Local delivers traffic only
through nodes that run the tls-lb pod).

The attestation sidecar bounds what one client may hold as well as how fast it
may ask: 512 concurrent sessions per client address (an IPv6 client is one
/64), inside a pool of 8192. A pool that is full gives up the idlest session,
and only from a client above the share the pool divides between its holders
and the caller, never below 8 entries, so a client holding a handful is not
drained by one holding thousands. Once every holder is down to that floor —
which takes 1024 client addresses holding sessions — a new session is refused
with 503 until one expires.

The proxy preserves the request method, original URI and query, body, and
`Authorization` header. Reads remain unauthenticated at CDS. Writes still
require the short-lived, body-bound operator token generated by
`c8s allowlist --operator-key`; the operator private key is never mounted in
tls-lb or CDS.
Use the tls-lb URL with `c8s allowlist --url` and pin tls-lb's launch digest
with `--measurements` only when `tlsLb.publicTLS.secretName` is empty
(`public_tls.mode=cds`). With a configured WebPKI secret, the public certificate
is not yet bound to the discovery attestation and the CLI refuses that front
door. Use a direct CDS RA-TLS URL (or a CDS port-forward) and pin the CDS launch
digest instead.

Set `tlsLb.allowlist.enabled=false` to remove this route. For compatibility,
an explicit `tlsLb.routes` entry whose path is `/allowlist` or `/allowlist/`
takes precedence and suppresses the built-in route.

tls-lb proxies its catch-all route to one upstream, `tlsLb.upstream.address`,
an opaque `host:port` the chart never interprets. For a workload run as the
operator-managed headless Service (annotated `confidential.ai/cw`, see
[Injection contract](#injection-contract)), that upstream must be the headless
Service's own DNS name and container port,
`c8s-<id>.<namespace>.svc.cluster.local:<port>`. Headless DNS resolves
to pod IPs, which the node mesh intercepts to wrap the hop in attested mTLS; a
regular Service VIP it cannot intercept, so dialing one leaves the hop in
plaintext. Dialing the pod IP also bypasses the Service's port remapping, which
is why the explicit container port is required.

`c8s install --upstream <cw-id>` builds that string for you from an adopted
workload: `<cw-id>` must be one of your `--workload-ref` ids and that ref must
carry a `:<port>`, and install sets `tlsLb.upstream.address` to
`c8s-<id>.<ns>.svc.cluster.local:<port>` (the ref's namespace and port). The
chart recognizes that headless-Service address shape as mesh-wrapped and admits
the plaintext http hop; any other address must be app-TLS (see below):

```bash
c8s install --namespace c8s-system \
  --workload-ref infer=vllm/deployment/serving:8000 --wait \
  --upstream infer
# tlsLb.upstream.address = c8s-infer.vllm.svc.cluster.local:8000
```

Without `--upstream`, `tlsLb.upstream.address` is used as-is: an upstream that
is not a c8s-managed workload (an existing Service, an external address). The
chart cannot verify a manual address resolves to pod IPs the mesh intercepts,
so it must be `protocol: https` with `tls.verify: true`: an upstream that
terminates and authenticates TLS itself (app-TLS). There is no
plaintext-to-unattested escape hatch and no default upstream.

Leaving the upstream unset is legal: tls-lb installs and serves its cert,
discovery, and any explicit routes with **no catch-all** `location /` until one
is wired. This is the install-then-attach flow: `c8s install` stands up the
front door, and the operator attaches the workload later (`--upstream`, or a
verified-https `tlsLb.upstream.address` via `-f`). An unmatched request gets
nginx's default 404 until then.

The chart rejects, at render time, with stable `kind=` markers (the same the
chart tests assert on):

- `tlslb_unsecured_upstream`: a `tlsLb.upstream.address` that is not a
  `c8s-<id>.<ns>.svc.cluster.local` headless-Service address is a plaintext http
  backend, or https without `tls.verify=true`. Only a verified-https (app-TLS)
  manual address is admitted; there is no acknowledgment to override this. To
  reach a confidential workload, adopt it with `--workload-ref` and pass
  `--upstream`: pointing a manual address at a Service VIP fronting cw pods is
  unmeshed, and the always-on cw guard drops it, so the hop fails closed rather
  than running plaintext.
- `workload_https_upstream`: the address is a `c8s-<id>` headless Service (a
  mesh-wrapped upstream) with `tlsLb.upstream.protocol=https`. That hop is
  plaintext at the app layer (the mesh wraps it in attested mTLS), so an https
  protocol could only fail at runtime; use http for a mesh-wrapped upstream.

The same secured-backend rule applies to every `tlsLb.routes[].backend`: it
must use `protocol: https` with `tls.verify: true` (app-TLS). A plaintext http
or unverified-https route backend fails the render (`tlslb_unsecured_route`);
there is no acknowledgment to override it. Routes have no default backend, so
this only affects routes you configure. A confidential workload is reached via
`tlsLb.upstream` (the `--upstream` flow), not a route.

The mesh guarantee holds only when `--upstream` names a real cw workload: the
CLI checks the id is one of the adopted refs, but cannot confirm `c8s-<id>`
fronts attested cw pods. A wrong id derives a headless Service that resolves to
nothing (tls-lb has no backend) rather than a plaintext leak; the runtime
boundary that a peer is a genuine cw pod is the mesh's always-on cw inbound
guard, not this render guard.

## Certificate file permissions

`get-cert` writes the private key with the mode passed by `--key-mode`. The
webhook default is `0640`, and it sets `fsGroup: 65532` on injected pods that
do not already define an `fsGroup`. This lets application containers running
as a different non-root UID read `tls.key` through the shared group.

Relevant values:

```yaml
webhook:
  certVolume:
    fsGroup: 65532
    keyMode: "0640"
  getCert:
    renewInterval: 2h
    runAsUser: 65532
    runAsGroup: 65532
    runAsNonRoot: true
```

Set `webhook.certVolume.fsGroup` to `-1` to disable pod `fsGroup` mutation.
The webhook preserves an existing pod `fsGroup`.

For Kata deployments that require UID 0 inside the guest, set
`webhook.getCert.runAsUser=0`, `webhook.getCert.runAsGroup=0`, and
`webhook.getCert.runAsNonRoot=false`. The install CLI exposes those as
`--webhook-get-cert-run-as-user`, `--webhook-get-cert-run-as-group`, and
`--webhook-get-cert-run-as-non-root=false`. The renewal interval is exposed as
`--webhook-get-cert-renew-interval`.

The injected get-cert containers also use a locked-down security context:

- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `runAsNonRoot: true` by default
- drops all Linux capabilities
- `seccompProfile: RuntimeDefault`

## Network policies

The chart ships default-deny ingress for every component it runs. Each pod
accepts only the ports it declares and nothing else on the pod network reaches
it:

| Policy | Selects | Accepts |
|---|---|---|
| `c8s-attestation-api` | attestation-api | nothing (it binds pod loopback) |
| `c8s-cds-ingress` | cds | `cds.port` (RA-TLS; also the NodePort route) |
| `c8s-operator-ingress` | operator | 9443 webhook, 8081 probes, 8080 metrics |
| `c8s-volumed-ingress` | volumed | nothing (it serves a node-local Unix socket) |
| `c8s-tls-lb-ingress` | tls-lb | `tlsLb.nginx.httpsPort` |

They are ingress-only. `ratls-mesh-tcp-only-egress` already selects every pod in
the namespace and allows all TCP, and NetworkPolicies union, so an egress rule
on one component would be allowed by that policy regardless.

**None of them restricts the source of a connection** — no rule carries a
`from`, so each one narrows which port answers, not who may connect. tls-lb is
the public front door and stays reachable from off-cluster; the API server that
dials the admission webhook has no address a selector could name; get-cert runs
beside every adopted workload in every namespace; and the CDS NodePort route
arrives off-cluster too. `c8s-volumed-ingress`, which has no `ingress:` rules at
all, is the only one that refuses everything.

**Opening another port.** Policies are additive, so apply your own
`NetworkPolicy` selecting the same pods — there is nothing to disable first:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cds-extra-port
  namespace: c8s-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: c8s-operator
      app.kubernetes.io/instance: c8s
      app.kubernetes.io/component: cds
  policyTypes: [Ingress]
  ingress:
    - ports:
        - protocol: TCP
          port: 9000
```

These are inert on a cluster whose CNI does not enforce NetworkPolicy.

## Validation

Run the full Go suite:

```bash
go test ./...
```

Run the chart tests only:

```bash
go test ./internal/helmchart
```

Validate the chart with `helm template` (use it, not `helm lint`: lint's
standalone YAML parse chokes on the nri-image-policy installer's embedded
host-config heredoc, while `helm template` — the path CI and the chart tests
use — renders it correctly).

The chart ships no default image tag, so a bare `helm template` must set one.
`c8s install` injects this for you; `main` here is the same fallback tag it
uses for a non-release build. The simplest validation disables the image-policy
component, so only image tags are required (no digests). Disabling it renders
only because the chart's default `attestationApi.cvmMode=node` bakes its own
policy plugin and so is exempt from the `require_host_image_policy` guard; other
modes (gke/aks) must keep nri-image-policy enabled and digest-pinned, as in the
full-shape render below.

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set cds.image.tag=main \
  --set ratlsMesh.image.tag=main \
  --set nriImagePolicy.enabled=false >/dev/null && echo OK
```

To render the full default shape (image policy enabled), the chart requires the
nri-image-policy installer image and the CDS image to be digest-pinned. The CDS
node selector defaults to `role: cds`; override it if your CDS node uses a
different label. `c8s install` fills these digests from the registry by default
(via `crane`); for a manual render the values below are placeholders:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set cds.image.tag=main \
  --set ratlsMesh.image.tag=main \
  --set nriImagePolicy.image.tag=main \
  --set nriImagePolicy.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  --set cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 >/dev/null && echo OK
```

Append `--set-file cds.operatorKeys=operator.pub` to either command to render
the operator-keys ConfigMap and the CDS `--operator-keys` flag that gate
allowlist writes.

The rendered manifests should include:

- a CDS Deployment, Service, and ServiceAccount;
- the operator arg `--cds-url=https://c8s-cds.c8s-system.svc:8443`;
- no CDS admin-password Secret and no attestation-api API-key Secret;
- `confidential.ai/trust-root-mode: inMemory` annotations on the chart-managed
  CDS resources.
