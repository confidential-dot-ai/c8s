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
- Platform: `build` requires `C8S_PLATFORM=tdx|snp`. Both roles share the
  same image for the selected platform and VM shape. Platform-specific
  service settings, node labels, measurement policy and image artifacts are
  generated at build time; TDX and SNP do not share a measurement or image
  digest. SNP also has one launch digest per supported vCPU count. Both
  platforms support operator-key-bound launch configuration and credential
  release: TDX binds the public key in RTMR[3], SNP in HOST_DATA.
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

The initrd encrypts the disk and, via a dm mapping named `scratch`, places a
writable overlay above the read-only dm-verity root. The currently pinned
confos version overlays the whole root; all changes disappear on reboot.
This profile also declares `/etc/rancher`, `/etc/cni`, `/opt/cni` and
`/etc/nri` in `/usr/lib/confai/state.d/60-c8s.conf` for confos versions with
selective writable directories. That declaration is inactive at the current
pin. Without the disk
the initrd falls back to a 2G RAM tmpfs: the guest comes up Ready, then
wedges once RKE2 fills it — a flapping node, not a boot error.
`scratch-enforce.service` closes that hole by checking for the dm mapping
and powering the VM off before rke2 starts.

Every boot also requires an ISO labelled `opkeydata` with these three files
at its root:

- `pubkey`: the launch public key for this cluster and role. The measured
  initrd stages the exact PEM bytes to `/etc/confai/operator-pubkey` and binds
  them into TDX RTMR[3]. An SNP launcher must set HOST_DATA to the SHA-256 of
  those same bytes.
- `launch.yaml`: the strict `c8s-launch/v1` document selecting `leader` or
  `follower`, the image measurements, cluster/node identity, join tokens,
  trusted role keys and TLS SAN.
- `launch.yaml.sig`: the detached signature produced by
  `c8s keys sign-launch --key <role-private-key> launch.yaml`.

Use distinct leader and follower keys and generate fresh keys for each
cluster. The private keys stay with the operator. Followers receive only the
RKE2 agent token; their documents must omit the server token entirely.
There is no diskless/default-leader boot. Missing or invalid signed input
fails the role gate before RKE2 or core services can start.

See [Authenticated launch configuration](../docs/operator.md#authenticated-launch-configuration)
for complete leader/follower bundle creation, image-manifest extraction,
ISO and KubeVirt attachment examples, and the exact schema. A leader may
omit its address to use `node.ip` or primary-interface IPv4 autodetection;
a follower must specify the leader's reachable IPv4 address. Switching roles
requires relaunching with the new role's authorized bundle and launch key.

Additional optional disks:

- serial `confai-containerd` (or label `containerd`): backs containerd's
  image cache (`containerd-data-disk.service`).
- serial `confai-models`: a pre-populated, read-only weights disk mounted at
  `/var/lib/models`. It is unencrypted and host-writable; attach public
  weights whose digests the workload verifies (`models-disk.service`).

## Measured services and Kubernetes integration

One image contains all service binaries and role conditions:

| Service | Leader | Follower |
|---|---|---|
| Local attestation API and Unix-socket proxy | Run | Run |
| NRI image admission | Run under containerd | Run under containerd |
| RA-TLS mesh and iptables reconciliation | Run | Run |
| RKE2 | Server | Agent |
| CDS, certificate renewal, TLS front door and attestation routes | Run | Disabled |
| Attested operator credential release | Run | Disabled |

`rke2-role.service` verifies and stages the launch configuration once.
Every dependent service requires that gate. The host attester listens only
on `127.0.0.1:8400`; workload helpers use its Unix socket in the existing
admission-inventory directory. CDS listens on the leader's port `30808`;
RKE2 followers join at `9345`; nginx serves the front door on `443`.

`c8s/mkosi.sync` resolves the shared c8s binary and operator container digest
from `C8S_REF`, then runs the binary's `c8s node-image render` command in the
build tools tree with a checksum-pinned Helm binary downloaded from the
official Helm release. Rendering uses the pinned RKE2 Kubernetes version,
so chart capabilities match the guest. Helm stays outside the guest image.
The command
renders the embedded chart once, preserving
its Kubernetes operator, CRDs, RBAC, webhook and admission policies while
extracting nginx configuration and the CDS component seed for the host.
There is no c8s chart archive, Helm installation job or runtime values merge.
The image needs a published `C8S_REF` containing the new commands;
`v0.1.0-rc2` is incompatible and fails the build with an explicit error.

The build stages measured templates at `/usr/lib/c8s/` and Kubernetes
integration at `server/manifests/c8s-integration.yaml`. At boot, verified
launch settings produce root-only `/run/confos/launch` files and the public
`c8s-node-runtime` ConfigMap in `c8s-system`. Its `cds-url` and `cds.json`
fields contain only the leader endpoint and full software/launch-key policy.
The operator passes that policy into workload helpers. Host services use the
same staged policy; peer connections accept authorized roles, while every
CDS client requires the leader's key. The shared image measurement alone
does not distinguish the two roles.

`c8s install` refuses this image's cluster: `c8s-system` carries the baked
ownership label. Workload deployment still uses the Kubernetes API; admission
protections remain generated from the existing chart. The launch schema has
no arbitrary Helm values, service arguments or optional component switches.
It can carry an initial workload allowlist and a DNS SAN, but volume support
and arbitrary front-door routes are not enabled by launch settings.

CDS keeps its database at `/run/c8s-cds/allowlist.db`; the directory survives
a service restart, but every VM reboot resets the database and the cluster's
ephemeral state. The baked component seed and signed initial workload entries
are reapplied on the next boot. The mesh CA key lives only in CDS process
memory, so a CDS process restart also requires certificate re-bootstrap.
Public certificates and discovery files live at `/run/c8s-tls`; launch
credentials remain in the separate root-only staging directory.

The local unit and rendering checks validate these contracts. They do not
replace booting the resulting image on the target TEE hardware.

The metal CI lanes require compatible image metadata in their respective
ConfigMaps; both must set `launchConfigVersion=c8s-launch/v1`:

| ConfigMap | Additional required fields |
|---|---|
| `tdx-rke2-image-refs` | `image`, `rootPvc`, `mrtd`, `rtmr1`, `rtmr2`, `c8sRef` |
| `snp-rke2-image-refs` | `image`, `rootPvc`, `manifestRef`, `igvmFile`, `igvmHookImage`, `smp`, `snpLaunchDigest`, `c8sRef` |

The SNP lane requires digest-pinned OCI references for `image`, `manifestRef`
and `igvmHookImage`, and a hook that sets HOST_DATA from the launch public key.
Its `smp` is currently `4`; `snpLaunchDigest` must match that variant in the
published `manifest.json`. The paired `c8sRef` identifies the image build.
Changing the attester requires a new measured image.

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

## Troubleshooting

**`Read-only file system` inside a service** — check that unit's systemd
sandbox first (`ProtectSystem` and `ReadWritePaths`). The current confos pin
uses a writable whole-root overlay, while newer confos versions limit writes
to `/usr/lib/confai/state.d/*.conf` paths. This profile declares its required
writable directories and the image invariant checks that each exists.

Changes to service binaries or persistent configuration belong in the measured
image build. Changes made on the running guest are outside the image's
measurement and disappear on reboot. Deploy workloads through Kubernetes and
use the signed launch document for the supported per-boot settings.

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
