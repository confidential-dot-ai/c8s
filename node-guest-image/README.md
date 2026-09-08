# node-guest-image

The c8s node image (`node-guest-base`, `rke2[-cdi]-*` tags), defined in THIS repo
and built by [confidential-os-builder] acting purely as a builder — the same
ownership split `kata-guest-base/` already has with confos as a pinned tool.
Tracking issue: [#264].

Layout:

- `c8s/` — the mkosi profile (config, `mkosi.extra/`, `mkosi.sync`).
  Staged into the confos build via
  `confos build --profile-dir` (confos ≥ the release carrying
  confidential-os-builder#81); the dir basename **is** the profile name, so
  it must stay `c8s`.
- Platform: the profile is platform-neutral; `build` requires
  `C8S_PLATFORM` (`tdx`|`snp`, no default) and `c8s/mkosi.sync` renders the
  **entire** tdx/snp divergence — three files — from it: cred-release's
  `Environment=CRED_PLATFORM` drop-in, the node's self-label
  (`confidential.ai/tdx` / `confidential.ai/sev-snp`, the k8s vocabulary
  `c8s install --hardware-platform` selects on), and the NRI floor's
  `platform:`. The sync refuses to render a missing/invalid value, so the
  fail-closed gate is at **build** time; `--platform=${CRED_PLATFORM}` in
  the unit is boot-time defense in depth (cred-release opens no quote
  device — quotes come from attestation-api over HTTP, the operator-key
  RTMR read is sysfs). The guest kernel carries both TEEs' symbols via
  confos `kernel/required.config`, so the images differ only by those
  three rendered files — which keeps a one-image-serves-both design
  (boot-time platform probe, confos `--platform both`) evaluable later.
  NOTE: the operator credential-release flow itself is TDX-only today
  (RTMR[3] binding; SNP has no runtime-extend equivalent) — an SNP image
  boots and attests, but operator flows fail closed pending an SNP
  binding design.
- `kernel/` — the guest-kernel config fragments (`c8s.config`,
  `c8s-dev.config`), passed via `--kernel-config-fragment` exactly like
  kata-guest-base's `container.config`. confos's `required`/`hardening`
  baselines stay in confos: a fragment request that conflicts with them
  fails the build (see the balloon catch in #263).
- `build` — drop-in replacement for confos's `bin/build-c8s`: same env
  contract (`C8S_PLATFORM`, `C8S_REF`, `C8S_REGISTRY`, `C8S_DEV`, `C8S_NAME`, `C8S_MEMORY`) and the same profile stack
  and order; only the c8s profile content and kernel fragments come from
  here. Point `CONFOS_DIR` at a confos checkout (default: a sibling dir).
  The locked image runs the kubelet with `enable-debugging-handlers=false`,
  so `kubectl exec`, `attach`, `port-forward`, and `logs` fail for every
  kubeconfig holder; `C8S_DEV=1` turns them back on (with the serial
  autologin), at a different measurement.

## Launch requirements

Every node VM needs a write-storage disk with virtio-blk serial
`confai-scratch`, at least 64G. The serial is what matters: the confos
initrd scans `/dev/vd{b,c,d}` for it and ignores labels. In KubeVirt that's
`disk: {bus: virtio}` plus `serial: confai-scratch` (see the vendored
`tdx-metal-e2e.yml`); confidential-metal attaches one by default
(`--datadisk-gi`, 0 opts out).

The initrd encrypts the disk and mounts it as the rootfs upper, via a dm
mapping named `scratch`. Without the disk it falls back to a 2G RAM tmpfs:
the guest comes up Ready, then wedges once RKE2 fills it — a flapping
node, not a boot error. `scratch-enforce.service` closes that hole by
checking for the dm mapping and powering the VM off before rke2 starts.

The other disks are optional; each is owned by one unit under
`c8s/mkosi.extra`, whose header carries the full contract:

- serial `confai-containerd` (or label `containerd`) — recommended:
  backs containerd's image cache, which otherwise lives in a RAM tmpfs
  (`containerd-data-disk.service`).
- serial `confai-models` — a pre-populated, read-only weights disk
  mounted at `/var/lib/models` so a large cache survives relaunch. It is
  unencrypted and host-writable: attach it only for public weights whose
  digests the workload verifies itself (`models-disk.service`).
- label `joindata` — an ISO that picks server vs agent and joins the
  cluster; absent means single-node server (`rke2-role.service`).
- label `opkeydata` — an ISO carrying, at its root:
  - `pubkey` — the operator public key. Its presence turns on attested
    credential release (`cred-release.service`, see [operator.md]). The
    measured initrd is the one reader of the disk for this file: it stages
    the bytes to `/etc/confai/operator-pubkey` and extends RTMR[3] (TDX) with
    their digest before `switch_root`, and every later consumer
    (`cred-release.service`, `c8s-chart-values.service`) reads that staged
    file rather than mounting the ISO itself. The baked `cred-release-rbac`
    RKE2 AddOn binds the issued certificate's group to `cluster-admin`
    through ordinary RBAC; identity, TTL and revocation are documented in
    [operator.md].
  - `values.yaml` (optional) — a signed launch-time values fragment (see
    "Chart install" below): deployment configuration that used to need a
    `c8s install --values` on a live cluster. Present without a matching
    `values.yaml.sig` next to it, boot fails closed. Unlike `pubkey`, the
    initrd does not stage this file yet, so `c8s-chart-values.sh` mounts
    the ISO itself at boot to read it — an interim step until it is staged
    next to the pubkey the same way.
  - `values.yaml.sig` (required with `values.yaml`) — its detached
    signature: ECDSA (P-256) over SHA-256 of the file's exact bytes, ASN.1
    DER, base64, one line. Produced with:
    ```
    c8s keys sign-values --key operator.key values.yaml
    ```

## Chart install

The image installs the c8s chart itself at boot — no `c8s install` step is
needed (and `c8s install` refuses to run against a cluster that already
carries the baked release). `c8s/mkosi.sync` fetches `internal/helmchart/c8s`
from the c8s source tree at `C8S_REF`, packs it into
`server/static/charts/c8s.tgz`, and renders the platform's
`c8s/c8s-chart.<platform>.yaml.in` into a `HelmChart c8s` AddOn
(`server/manifests/c8s-chart.yaml`) that points `spec.chart` at that static
tarball, with the node-mode component digests resolved at the same `C8S_REF`
as the rest of the build. `c8s-chart-values.service` runs once at boot, before
`rke2-server`, and writes the two inputs only a running boot knows into a
`HelmChartConfig` RKE2 merges into that release:

- `cds.operatorKeys`, from the initrd-staged operator pubkey — present only
  on an operator boot (see `opkeydata` above); its absence is not an error,
  it just leaves allowlist writes disabled until a later boot supplies one.
- `cds.measurements`/`rtmrs` and `ratlsMesh.measurements`/`rtmrs`, this
  node's own launch measurement (TDX: the `tdx_guest` sysfs; SNP: a
  self-attestation against the local attestation-api) — pinning the mesh to
  the exact image that is running, the way an operator's `c8s install
  --measurements` would on a chart-managed cluster.

When opkeydata carries a `values.yaml` fragment, `c8s-chart-values.sh` mounts
the disk (the same locked-down way `rke2-role.sh` mounts `joindata`) and
hands the fragment, its signature, and this boot's own inputs to
`c8s launch-values render` (`internal/cmds/launchvalues`), which owns
`spec.valuesContent` from there: it verifies the signature under the
measured operator key, checks the fragment's `measurement` names this exact
boot, validates every leaf of its `values` subtree against an explicit
allowlist, and deep-merges it underneath the boot-derived keys above so a
fragment can never override them. See docs/operator.md, "Launch-time
values", for the allowlist and the fragment shape.

## Workload isolation

Tenant pods run on the node's own kernel under runc, so what a pod may ask
for is what stands between it and the measured host. The image enforces the
restricted PodSecurity standard by default
(`etc/rancher/rke2/psa-config.yaml`): no privileged pods, no host
namespaces, no root user, no added capabilities, no unconfined seccomp or
AppArmor. Only `kube-system` and `local-path-storage` are exempt; `default`
is not.

A namespace label can normally lower that level. The baked
`psa-level-policy.yaml` AddOn denies an `enforce` label other than
`restricted`, or an `enforce-version` other than `latest`, unless the
caller is authorized to grant `podsecurityexemptions.confidential.ai` (verb
`grant`), a virtual resource no default role includes. cluster-admin and
system:masters pass; a tenant holding `admin` or `edit` in its own
namespaces does not. The invariant therefore rests on tenancy: hand tenants
namespace-scoped credentials, never cluster-admin, and the launch
measurement vouches for the floor their pods run under. cluster-admin can
delete the policy, and RKE2 does not recreate deleted AddOn objects.

The floor covers namespaces without confidential workloads. In node mode
the webhook mounts the node's inventory socket into every
`confidential.ai/cw` pod as a read-only hostPath, which restricted (and
baseline) forbids, so a namespace hosting confidential workloads is opened
by the operator with the privileged label, as `c8s install` does for its
release namespace. Inside such a namespace the chart's own admission
policies (host namespaces, hostPort, the mesh UID) are the controls, and the
sample workload in `samples/` is restricted-compliant on its own so it can
move back under the floor when the socket no longer needs a hostPath.

## Module loading

`kernel/c8s.config` sets `CONFIG_MODULES=y`, which the confos base kernel
compiles out. It is on for exactly two out-of-tree modules, `nvidia.ko` and
`nvidia-uvm.ko` (see [MODULE-SIGNING.md](MODULE-SIGNING.md)); every symbol
kubelet, containerd and Cilium need is `=y`, so nothing modprobes at runtime.

Because the key exists on this kernel, the runtime lock has to be set here:
confos's `99-kspp-hardening.conf` omits `kernel.modules_disabled` on the
grounds that the base kernel has no such key. `c8s-modules-latch.service`
sets it to 1 once boot-time loading is done, ordered after the gpu profile's
`nvidia-modules-latch.service` and before the rke2 pair, which it is
`RequiredBy`. The latch is one-way for the rest of the boot.

The gpu profile ships a latch of its own, so on the canonical GPU build both
run and the second rewrites a 1. This one also covers the GPU-less
composition (`attest` + `c8s`, no `gpu`), where that unit is absent. The same
split applies to `99-c8s-bpf.conf`: the c8s profile owns the runtime locks its
own kernel fragment makes necessary.

Migration state (see [#264] for the full plan):

1. This directory is the canonical definition: `c8s-image.yml` builds via
   `node-guest-image/build`, which stages `c8s/` into a confos checkout
   with `--profile-dir` and passes the kernel fragment and
   `c8s-ref`/`c8s-registry` sync inputs explicitly. The
   `node-guest-image lint` workflow is permanent: it carries the
   invariants that moved here from confos `bin/lint` (fragment supersets
   vs confos's gpu/dev fragments at the `node-image` confos pin in
   `.github/build-pins.json`, the NRI
   floor template's no-hardcoded-digest rule, and the nested RKE2/Cilium
   pod-CIDR match), plus the cloud-init disable gate.
2. The switch was gated on building the same c8s ref both ways (confos
   in-tree vs staged from here) with identical `manifest.json`
   measurements; `c8s-image.yml`'s `gate=true` dispatch input reruns that
   A/B check against any confos ref.
3. Remaining cleanup, so the inherited interface doesn't become canonical
   selector.

[confidential-os-builder]: https://github.com/confidential-dot-ai/confidential-os-builder
[#264]: https://github.com/confidential-dot-ai/c8s/issues/264
[operator.md]: ../docs/operator.md
