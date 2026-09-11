# node-guest-image

The c8s node image (`node-guest-base`, `rke2[-cdi]-*` tags), defined in THIS repo
and built by [confidential-os-builder] acting purely as a builder.
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
  `c8s-dev.config`), passed via `--kernel-config-fragment`.
  confos's `required`/`hardening`
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

The initrd encrypts the disk and, via a dm mapping named `scratch`, backs the
writable state overlays with it; the root itself is the read-only verity
image. Which directories get an overlay is declared in
`/usr/lib/confai/state.d/`: confos's base covers `/var`, `/home`, `/root`,
`/tmp`, and this profile adds `/etc/rancher`, `/etc/cni`, `/opt/cni` and
`/etc/nri` (`60-c8s.conf` says why each). Without the disk
the initrd falls back to a 2G RAM tmpfs: the guest comes up Ready, then
wedges once RKE2 fills it — a flapping node, not a boot error.
`scratch-enforce.service` closes that hole by checking for the dm mapping
and powering the VM off before rke2 starts.

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

"Tenant" in these docs names the workload side of the trust boundary: pods,
and the namespaced credentials that create them, as opposed to the platform
components in the release namespace and `kube-system`. A node CVM serves one
tenant; the word says which side of the boundary a pod is on, not that
several share a node.

Tenant pods run on the node's own kernel under runc, so what a pod may ask
for is what stands between it and the measured host. The image enforces the
restricted PodSecurity standard by default
(`etc/rancher/rke2/psa-config.yaml`): no privileged pods, no host
namespaces, no root user, dropped ALL capabilities (only `NET_BIND_SERVICE`
may be added back), and no unconfined seccomp or AppArmor. Only `kube-system`
and `local-path-storage` are exempt; `default` is not.

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

RKE2 reconciles AddOns after kube-apiserver starts. The attested credential
endpoint therefore remains closed until `psa-ready.sh` sees the policy and
binding and proves, through server-side dry-runs as a synthetic non-granter,
that a restricted namespace is admitted and a privileged one is denied by
`confos-psa-level`. No externally released operator credential can enter the
first-boot reconciliation window.

The floor also covers namespaces hosting confidential workloads. In node mode,
`nri-image-policy` mounts the inventory socket directory read-only into credential
sidecars through NRI, below the Pod spec. Tenant namespaces keep Restricted
enforcement, warning, and audit. `c8s install` labels its release namespace
privileged for trusted platform components, including node DaemonSets.

The chart's fail-closed `deny-host-namespaces` policies enforce Restricted
controls and deny every tenant `hostPath` volume on Pod CREATE/UPDATE and
`pods/ephemeralcontainers` updates. Existing Pods that still declare the old
claims hostPath must be recreated to pick up NRI wiring; an unchanged prior
sidecar or chart image never exempts the volume. Admission does not evict
already-running Pods. The ephemeral policy also preserves the host-namespace
and host-port checks over the full Pod.

Ephemeral containers may inherit safe pod-level `runAsNonRoot` and seccomp
settings when their own settings are absent. Explicit unsafe Pod settings,
including root UID, Unconfined seccomp or AppArmor, disallowed SELinux settings,
and unsafe sysctls, are rejected even when the debugger specifies safe
container settings. Explicit `runAsNonRoot: false` and legacy Unconfined
AppArmor annotations are rejected too. The same Pod-level guards apply to
ordinary Pod admission.

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

Automatic main-push publication in `c8s-image-publish.yml` calls the separate
`tdx-image-acceptance.yml` workflow after the build finishes. Only this
automatic publisher can call exact-image acceptance; neither workflow has a
manual-dispatch trigger. It consumes the same run and attempt's
immutable evidence: the source SHA, CDI and ORAS digests, and the published
manifest. Disk and UKI hashes plus MRTD/RTMR1/RTMR2 must match the fresh
build; a differing nonmeasured build timestamp is not a mismatch. The
published manifest is passed unchanged to `get-kubeconfig` for attestation.
Tests are checked out at the build SHA. Before allocating the launcher,
the reusable workflow independently requires a successful same-repository
`main` push and exposes no c8s-ref override in exact-image mode. A read-only
hosted preflight fetches trusted `main` history and verifies that the full
build SHA is an ancestor before handing it to the launcher. It executes no
code from the requested build. On the launcher, the action checks that the
workspace HEAD equals that full SHA, then reuses the verified workspace for
the CLI build and every E2E script. The seven-character ref selects only OCI
image tags in exact mode.

The staged `tdx-metal-e2e.yml` wrapper checks out its workflow revision
independently and builds the CLI from the image's paired ref or the explicit
`c8s_ref` override. The optional `imageTag` in `tdx-rke2-image-refs` supplies
the staged image's manifest tag when digest-to-tag discovery cannot find it.
Both wrappers share the lifecycle in `.github/actions/tdx-metal-e2e/action.yml`
and the same concurrency group; checkout and evidence acquisition stay
outside that shared action. Run the real-Git provenance, matching-prefix tag,
source rejection, E2E routing and caller-isolation tests with
`go test ./test/workflows`. These local tests do not boot a node image.

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
For manual image builds, dispatch `c8s-image-manual.yml` (Actions name:
`c8s-image manual`), with the existing `dev`, `c8s_ref`, `confos_ref` and
`gate` inputs. It builds through the same reusable builder but cannot call
exact acceptance or promote stable aliases. `tdx-metal-e2e.yml` remains
manually dispatchable for staged-stack regression and `keep_cvm` debugging.

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

## Component pins

Every external input is pinned by immutable reference. Moving any pin
moves `root_hash` and the launch measurement — bump deliberately, in a
reviewed commit.

`.github/build-pins.json` is the canonical source for the measured workflows'
confos, attestation-rs, and mkosi pins. They validate and export the selected
domain through `.github/scripts/pin-manifest.sh`; automated pin-watch PRs
therefore change the manifest rather than workflow files.

`mkosi.sync` resolves the NRI floor from the mutable registry tag `C8S_REF`
at build time. The floor digests are recorded in the rendered
`image-policy.yaml`, so a mismatch is diagnosable, but a rebuild after those
tags move will not match.

## Physical host prerequisites

### TDX

- `qgsd` running on the host — the Intel DCAP Quote Generation Service
  that signs the TDREPORT into a full TDX quote. Talks over vsock.
- Intel PCS API key in `/etc/sgx_default_qcnl.conf` — DCAP fetches
  TCB collateral from Intel PCS during verify.
- **The platform registered with Intel**, so PCS can serve its PCK
  certificate. A CPU whose platform manifest was never uploaded gets no
  PCK cert, and every quote then fails inside qgsd with
  `[QPL] No certificate data for this platform` (`0xe011`). Cloud TDX hosts
  arrive registered; bare metal often
  does not, and the MPA agent (`sgx-ra-service`) only registers when
  the BIOS has "SGX Auto MP Registration" enabled. Without touching the
  BIOS, register indirectly once (`sgx-pck-id-retrieval-tool`):

  ```
  PCKIDRetrievalTool -f pckid.csv
  awk -F, '{print $6}' pckid.csv | tr -d '\r\n' | xxd -r -p > manifest.bin
  curl -sS -X POST https://api.trustedservices.intel.com/sgx/registration/v1/platform \
    -H 'Content-Type: application/octet-stream' --data-binary @manifest.bin
  # HTTP 201 = registered; restart qgsd afterwards
  ```

  Registration is permanent for the platform (survives reinstalls).

Two host-kernel gotchas seen on bare metal: if `dmesg` shows
`virt/tdx: initialization failed: Hibernation support is enabled`, add
`nohibernate` to the kernel command line (TDX and S3/hibernation are
mutually exclusive), and make sure `kvm_intel.tdx=1` is set (module
option or command line) — `cat /sys/module/kvm_intel/parameters/tdx`
must print `Y`, or QEMU refuses to launch TDs.

### GPU passthrough

Per the install constraints, the GPU **host** setup is not done by c8s.
Provision it with your host-provisioning system before installing c8s:

- **vfio-pci binding** of the GPUs (`vfio-pci.ids=10de:...` on the host cmdline,
  nvidia/nouveau blacklisted).
- **GPU confidential-compute (CC) mode** set in GPU firmware (`nvidia_gpu_tools.py
  --set-cc-mode=on`). A CC-mode/runtime mismatch panics the in-guest driver
  (`conf_compute.c:162` — "CPU does not support confidential compute").
- **BAR resize** on Blackwell (default → 8 GiB), before kubelet. Two mechanisms
  exist and each fails on one Blackwell part: prefer the kernel sysfs path
  (unbind → `echo 13 > resource2_resize` → rebind — the one that works on
  B200), fall back to `setpci` + remove/rescan (needed on `preserve_config`
  hosts like RTX PRO 6000, but a **silent no-op on B200**: the control
  register accepts the write while the device keeps decoding the old window —
  always verify with `lspci`).
- **Runtime PM pinned off** for every passthrough GPU
  (`echo on > /sys/bus/pci/devices/<bdf>/power/control`). An idle vfio-bound
  B200 gets runtime-PM autosuspended into D3cold and does not survive the
  resume (observed on kernel 7.0.9): BAR0 reads `0xFF`, the guest driver
  reports "GPU has fallen off the bus". Note
  `nvidia_gpu_tools.py` resets `power/control` to `auto` on every run, so
  host provisioning must re-apply the pin after any gpu-admin-tools
  invocation. Recovery for a bricked GPU: force D0 →
  `--reset-with-sbr` → D3→D0 power-control cycle; FLR alone is insufficient.
- On SEV-SNP hosts, `kvm_amd.sev_snp=1` and an IOMMU on the host cmdline.

## Troubleshooting

**`Read-only file system` under `/usr`, `/etc` or `/opt`** — from a unit log
(`mkdir: cannot create directory '/etc/foo': Read-only file system`), a
pod stuck in ContainerCreating with a FailedMount event for a hostPath
there, or a tool you installed on the host by hand. The root is the
read-only verity image; only `/var`, `/home`, `/root`, `/tmp` and the
directories listed in `/usr/lib/confai/state.d/*.conf` on the node are
writable, and nothing installed after boot is covered by the measurement.
If the writer is part of the image, declare its directory in
`c8s/mkosi.extra/usr/lib/confai/state.d/60-c8s.conf` (it must be baked; the
lint checks) or point it at `/var`. If it is something an operator installs
on the host afterwards, it does not belong on a measured node — run it as a
pod. `cat /usr/lib/confai/state.d/*.conf` on the node shows the live list;
a login shell prints it too.

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
   measurements; `c8s-image-manual.yml`'s `gate=true` dispatch input reruns that
   A/B check against any confos ref.
3. Remaining cleanup, so the inherited interface doesn't become canonical
   selector.

[confidential-os-builder]: https://github.com/confidential-dot-ai/confidential-os-builder
[#264]: https://github.com/confidential-dot-ai/c8s/issues/264
[operator.md]: ../docs/operator.md
