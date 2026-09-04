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
- label `opkeydata` — an ISO carrying the operator public key; its
  presence turns on attested credential release (`cred-release.service`,
  see [operator.md]). The baked `cred-release-rbac` RKE2 AddOn binds the
  issued certificate's group to `cluster-admin` through ordinary RBAC;
  identity, TTL and revocation are documented in [operator.md].

## Workload isolation

Tenant pods run on the node's own kernel under runc, so what a pod may ask
for is what stands between it and the measured host. The image enforces the
restricted PodSecurity standard by default
(`etc/rancher/rke2/psa-config.yaml`): no privileged pods, no host
namespaces, no root user, no added capabilities, no unconfined seccomp or
AppArmor. Only `kube-system` and `local-path-storage` are exempt. `default`
is not: the sample workload in `samples/` is restricted-compliant, and so is
the sidecar the webhook injects.

A namespace label can normally lower that level. The baked
`psa-level-policy.yaml` AddOn denies an `enforce` label other than
`restricted` unless the caller is authorized to grant
`podsecurityexemptions.confidential.ai` (verb `grant`), a virtual resource
no default role includes. cluster-admin and system:masters pass, which is
how `c8s install` labels its release namespace privileged for the
node-level components; a tenant holding `admin` or `edit` in its own
namespaces does not. The invariant therefore rests on tenancy: hand tenants
namespace-scoped credentials, never cluster-admin, and the launch
measurement vouches for the floor their pods run under. cluster-admin can
delete the policy, and RKE2 does not recreate deleted AddOn objects.

Below admission sits AppArmor. The kernel fragment builds it as the
exclusive LSM (SELinux, a defconfig default in the confos base, is turned
off to make room), and containerd applies its default profile
(`cri-containerd.apparmor.d`) to every non-privileged container: no
mounts, no writes under `/proc/sys` or `/sys`, no ptrace across containers.
Restricted PodSecurity refuses `Unconfined`, so a tenant cannot opt out,
and a pod that somehow gains `CAP_SYS_ADMIN` still meets a mandatory policy
before the read-only root. The `apparmor` package is on the image only for
`apparmor_parser`; its unit is disabled so the package's stock host
profiles are never loaded.

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
