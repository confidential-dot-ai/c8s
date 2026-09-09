# Kata runtime and scheduling helpers

Source: [templates/_kata.tpl](../../templates/_kata.tpl).
[All helpers](../README.md).

`attestationApi.teeDevices.tdxGuest` selects the cluster's CPU TEE: true selects
TDX; otherwise helpers select SEV-SNP.

| Helper output | TDX | SEV-SNP |
| --- | --- | --- |
| Hardware platform | `tdx` | `sev-snp` |
| CPU RuntimeClass | `kata-qemu-tdx` | `kata-qemu-snp` |
| CPU shim | `qemu-tdx` | `qemu-snp` |
| GPU RuntimeClass | `kata-qemu-tdx-nvidia` | `kata-qemu-snp-nvidia` |
| GPU shim | `qemu-nvidia-gpu-tdx` | `qemu-nvidia-gpu-snp` |

`c8s.kataConfidentialShims` supplies both selected shim names to kata-deploy's
`SHIMS_X86_64`. `c8s.kataAllowedRuntimeClasses` returns a quoted CEL list body
containing `kata-qemu`, `kata-clh`, and the selected confidential CPU/GPU pair.
Keep these outputs aligned with [kata.yaml](../../templates/kata.yaml) and
[kata-enforcement.yaml](../../templates/kata-enforcement.yaml). The image pullers
use the shim names to select their guest configuration files.

`c8s.kataContainerdConfigDir` honors an explicit `kata.containerdConfigDir`;
otherwise it resolves `rke2` to `/var/lib/rancher/rke2/agent/etc/containerd` and
`k8s` to `/etc/containerd`. Other distro values fail rendering. Kata-deploy sees
this host directory mounted at `/etc/containerd`.

`c8s.kataGuestReadyGate` is true when Kata and its guest-image puller are enabled.
`c8s.kataGuestReadyAffinity` then requires the node label
`confidential.ai/kata-guest-ready=true` for chart-managed pods that set their own
RuntimeClass. The puller's readiness supplies that label.
