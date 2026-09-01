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

## Launch requirements

Every node VM needs a write-storage disk with virtio-blk serial
`confai-scratch`, at least 64G. The serial is what matters: labels don't
work, and the disk must be one of `/dev/vdb`–`vdd`. In KubeVirt that's
`disk: {bus: virtio}` plus `serial: confai-scratch` (see the vendored
`tdx-metal-e2e.yml`); confidential-metal attaches one by default
(`--datadisk-gi`, 0 opts out).

The initrd encrypts the disk and mounts it as the rootfs upper, via a dm
mapping named `scratch`. Without the disk it falls back to a 2G RAM tmpfs:
the guest comes up Ready, then wedges once RKE2 fills it — a flapping
node, not a boot error. `scratch-enforce.service` closes that hole by
checking for the dm mapping and powering the VM off before rke2 starts.

A second disk with serial `confai-containerd` is recommended so the image
cache stays off guest RAM. `confai-models`, `opkeydata`, and `joindata`
are optional; missing ones are a clean no-op.

Migration state (see [#264] for the full plan):

1. This directory is the canonical definition: `c8s-image.yml` builds via
   `node-guest-image/build`, which stages `c8s/` into a confos checkout
   with `--profile-dir` and passes the kernel fragment and
   `c8s-ref`/`c8s-registry` sync inputs explicitly. The
   `node-guest-image lint` workflow is permanent: it carries the
   invariants that moved here from confos `bin/lint` (fragment supersets
   vs confos's gpu/dev fragments at the pinned `CONFOS_REF`, the NRI
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
