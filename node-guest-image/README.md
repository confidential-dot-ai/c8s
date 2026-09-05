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

Below admission sits AppArmor, the only enabled major LSM. Both kernel
fragments pin the complete `CONFIG_LSM` order; the invariant gate checks
them and the committed snapshot, and `build` checks the actual resolved
kernel `.config`, including cache hits. Before either RKE2 role starts,
`apparmor-enforce.service` requires an active AppArmor LSM, an executable
parser, and a disabled, inactive `apparmor.service`. It loads a temporary
profile, verifies its enforce-mode label and a denied read against a
successful unconfined control, then removes the profile. Failure blocks
RKE2. The package's stock host profiles are not loaded.

Containerd selects `cri-containerd.apparmor.d` for non-privileged containers
with omitted or explicit RuntimeDefault AppArmor settings. It denies mounts
and selected `/proc` and `/sys` writes, but permits shared-memory sysctls
under `/proc/sys/kernel/shm*` and access to `/sys/fs/cgroup/**`. It also
permits ptrace between processes using the same profile, which all
RuntimeDefault containers share. PID namespaces, capabilities, DAC, Yama,
seccomp and read-only mounts remain necessary isolation layers. Restricted
PodSecurity rejects `Unconfined` but allows `Localhost`, which names an
already loaded profile; no stock host profiles or boot probe profile remain
available for tenants to select.

From the repository root, run the configuration and boot regression tests
with Docker available, then the real parser/kernel probe on a Docker host
with AppArmor. Set `CONFOS_RELEASE` to the pinned confos base release
(currently Resolute); CI reads it from that checkout:

```sh
CONFOS_RELEASE=resolute make test-node-guest-image-apparmor
CONFOS_RELEASE=resolute bash node-guest-image/tests/apparmor-kernel-test.sh
```

The fault-injection harness copies the production script and `/bin/sh`
byte-for-byte into a private chroot, placing fixtures at their actual
absolute paths. It does not rewrite the script or mount host filesystems.
The separate real-kernel probe uses Resolute userspace and the Docker host's
kernel; neither test boots the node image. To verify containerd labels, mount
denial/control and Unconfined admission rejection on the actual image,
point `KUBECONFIG` at the operator credentials for a disposable single-node
c8s cluster and run `make test-node-guest-image-apparmor-runtime` (requires
`kubectl` and `jq`). This creates and cleans up a test namespace and a
`kube-system` pod with `SYS_ADMIN`.

Automatic main-push image publication runs a separate `verify-tdx-image`
job after the build finishes. It consumes the same run and attempt's
immutable evidence: the source SHA, CDI and ORAS digests, and the published
manifest. Disk and UKI hashes plus MRTD/RTMR1/RTMR2 must match the fresh
build; a differing nonmeasured build timestamp is not a mismatch. The
published manifest is passed unchanged to `get-kubeconfig` for attestation.
Tests are checked out at the build SHA.

That job imports the digest-pinned disk into its own 80Gi `local-path` PVC.
A restricted scheduling pod selects a TDX node before CDI import starts;
the pod has no service-account token or disk mount. Import has a 20-minute
deadline, and cleanup checks ownership of the temporary pod and PVC. This
requires working CDI, enough local disk space, and the launcher's existing
namespace-scoped Pod/PVC permissions; no shared image ConfigMap, root PVC,
or cluster-wide RBAC is changed. The hardware path must still be exercised
on the TDX runner; the local evidence/lifecycle fixtures are run with:

```sh
bash .github/scripts/tests/test-tdx-image-acceptance.sh
```

The ordinary `confidential-e2e` TDX lane continues testing the pre-staged
stack; it does not claim to validate the newly built image and does not run
the new-image AppArmor gate. Exact-image acceptance is post-publication
validation, not a gate on stable-alias promotion. Manual, development and
PR reproducibility builds do not invoke it. Attempt-bound evidence means
rerunning the full publication workflow, including the builder, if the
current attempt has no artifact; there is no fallback to older evidence.

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
