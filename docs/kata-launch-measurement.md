# Predicting a kata guest's launch measurement

`c8s kata measure` computes a kata confidential guest's launch measurement
offline, from the guest artifacts — no pod has to boot first. `--platform`
selects which value:

| `--platform` | computes | inputs | one value per |
|---|---|---|---|
| `snp` (default) | SEV-SNP launch digest | firmware + guest artifacts + pod vCPU count | **pod shape** |
| `tdx` | Intel TDX **MRTD** | TDVF firmware only | **fleet** |

```console
$ c8s kata measure --vcpus 1
e246273c1efee7dab0f623ffc04c33315fd37925cd9300fdb39d0a19f1b8e38edb95844464577ee89453e4b1eb46f0fb

$ c8s kata measure --platform tdx
c78e2b8b2f66207f3807d8d999f51e04f5eab8f7aa02614a86ddd81b61f4e79c5d7616664fcb190b8eaae2e26d60b12a
```

Output is the bare hex digest, one per line, so it pipes straight into
`c8s verify --measurements-file`. `--json` emits the digest plus every input
that produced it; `-v` prints the same inputs to stderr.

The rest of this document is the SNP path; [Intel TDX](#intel-tdx-mrtd) is at
the end.

## Why this exists

Under `c8s install --cvm-mode=pod` every pod is its own SEV-SNP CVM, so every
pod has its **own** launch measurement. Two pods on the same node, booting the
same `kata-guest-base` artifact, measure differently if their resource shapes
differ. Measured on a live SNP cluster:

| pod | vCPUs | launch measurement |
|---|---|---|
| every default-resource pod (tls-lb, workloads) | 1 | `e246273c…46f0fb` |
| CDS (`limits.cpu: 500m`) | 2 | `ff0bfd88…dba9a` |

`cds.measurements` is a single fleet-wide list, and CDS only serves `/secrets`
when it is set (see [`secrets.md`](secrets.md), "When it is served"). So pod
mode needs the *set* of per-shape digests, and until now the only way to learn
one was to boot a pod, let attestation fail, and read the
`measurement not in allowlist` warning out of the CDS log. `c8s install
--cvm-mode=pod --measurements` takes the digests this tool produces
(`cmd/c8s/install.go`); under `--cvm-mode=node/gke/aks` the same flag takes the
node image's `manifest.json` value instead.

## What goes into the digest

The digest is an iterative SHA-384 over one `PAGE_INFO` structure per measured
guest page (SEV-SNP ABI §8.17.2, Table 67), in the order the VMM presents them:

1. **The OVMF image** (`/opt/kata/share/ovmf/AMDSEV.fd`) as NORMAL pages, mapped
   so that it ends at 4 GiB.
2. **The pages named by OVMF's SEV metadata table** — zeroed memory, the secrets
   page, the CPUID page, and the kernel-hashes page.
3. **One VMSA page per vCPU**, carrying the vCPU model signature in RDX and
   `SEV_FEATURES`. vCPU 0 starts at the reset vector; the rest start at OVMF's
   SEV-ES reset EIP.

kata boots these guests by **direct kernel boot** — no IGVM, no UKI (see
[`kata-guest-base.md`](kata-guest-base.md)). QEMU runs with
`-object sev-snp-guest,…,kernel-hashes=on`, which makes it build a table of
SHA-256 hashes of the kernel, the initrd and the kernel command line and place
it in the measured kernel-hashes page. That is how `vmlinuz` and the dm-verity
`root_hash` reach the measurement: the root hash rides in the command line.

So the digest changes when **any** of these change:

| input | where it comes from | notes |
|---|---|---|
| OVMF build | `firmware` in `configuration-qemu-snp.toml` | moves with the kata-static payload |
| `vmlinuz` | the pulled guest artifact | `manifest.json` records its sha256 |
| dm-verity `root_hash` / `salt` | `kernel_verity_params` in `manifest.json` | any rootfs change moves it |
| rest of the kernel command line | kata's assembly, see below | includes `nr_cpus=N` |
| **vCPU count** | the pod's CPU limit, see below | changes both `nr_cpus` and the VMSA page count |
| vCPU model | QEMU `-cpu` (`EPYC-v4` on this fleet) | wrong model silently changes the digest |
| `SEV_FEATURES` | `0x1` (SNPActive) as launched by kata/KVM here | `--guest-features` |
| guest **memory** | — | *not* an input; only vCPUs matter |
| the `-debug` guest variant | `kata.guestImage.debug` | adds `agent.debug_console…` to the command line |

## vCPU count from a pod's shape

The qemu-snp config sets `static_sandbox_resource_mgmt = true`, so kata sizes
the VM statically from the pod spec rather than hotplugging:

```
vCPUs = ceil(default_vcpus + Σ pod container CPU limits, in cores)
```

`default_vcpus` is 1 (the c8s puller drop-in pins it). A pod where **any**
container has no CPU limit contributes 0, because containerd then reports an
unbounded sandbox quota — that is why every unlimited pod lands on 1 vCPU. CDS
limits CPU to `500m`, so it gets `ceil(1 + 0.5) = 2`.

`--pod-cpu-limit` applies that formula:

```console
$ c8s kata measure --pod-cpu-limit 500m      # CDS's shape
ff0bfd88acd95d702862f1779dc882131fa93031f97da867d334642a0ed9f116f24d09558b7adba2044eeac75b4dba9a
```

Memory follows the same rule (`default_memory + Σ memory limits`) but does not
reach the digest.

## Building a `cds.measurements` set

Enumerate the distinct vCPU counts your workloads produce and measure each:

```console
$ for n in 1 2; do c8s kata measure --vcpus "$n"; done > measurements.txt
$ c8s verify https://<tls-lb> --measurements-file measurements.txt
```

The same list goes into `cds.measurements` / `ratlsMesh.measurements` in a
values file passed to `c8s install --cvm-mode=pod -f values.yaml`.

Keeping that set small is a deployment choice: give every confidential pod the
same CPU limit (or none) and the whole fleet shares one digest.

## The kernel command line

The command line is the fiddliest input, because kata assembles it rather than
reading it from config. `c8s kata measure` reproduces the assembly for the kata
version in `SupportedKataVersion` (`internal/cmds/katameasure/cmdline.go`) and
refuses a guest whose `manifest.json` reports a different `kata_version`;
`--skip-version-check` overrides, and `--cmdline` bypasses derivation entirely.

The golden files under `internal/cmds/katameasure/testdata/` are exact
`qemu -append` strings captured from `/proc/<qemu-pid>/cmdline` on a live SNP
node, and the unit tests assert the derivation matches them byte for byte. To
re-capture after a kata bump:

```console
$ sudo tr '\0' '\n' < /proc/$(pgrep -f 'qemu-system-x86_64.*sev-snp-guest' | head -1)/cmdline \
    | grep -A1 -x -- -append | tail -1
```

Then diff it against `c8s kata measure --vcpus N --json | jq -r .cmdline`.

**Bumping kata** therefore means: re-capture the golden command lines, update
`SupportedKataVersion`, and re-derive every pinned measurement.

## Verifying against a real cluster

The SNP implementation reproduces both live measurements in the table above
from the artifacts on the node, and `pkg/snpmeasure`'s unit tests check it
against `sev-snp-measure`'s own published vectors using that project's 4 KiB
OVMF fixture — so CI validates the algorithm without a multi-GB guest image.
The end-to-end check against the real image is manual:

```console
$ c8s kata measure --vcpus 1 -v          # on a node with the puller's artifacts
```

and compare with the digest a pod actually reports.

## Intel TDX: MRTD

On TDX the value c8s pins is **MRTD**, and it needs no pod-shape input at all:

```console
$ c8s kata measure --platform tdx
c78e2b8b2f66207f3807d8d999f51e04f5eab8f7aa02614a86ddd81b61f4e79c5d7616664fcb190b8eaae2e26d60b12a
```

`--vcpus`, `--pod-cpu-limit`, `--cmdline` and `--debug-console` are **rejected**
on this path rather than ignored, so nobody believes they are pinning a
per-shape value. `--firmware` defaults to `/opt/kata/share/ovmf/OVMF.inteltdx.fd`
(the `firmware` key of `configuration-qemu-tdx.toml`).

### Why one value covers the fleet

MRTD is built during TD build: `TDH.MEM.PAGE.ADD` extends a SHA-384 with each
page's GPA, `TDH.MR.EXTEND` with 256-byte chunks of page *contents*, and
`TDH.MR.FINALIZE` completes it. The pages added before finalize are exactly the
ones named by TDVF's metadata section table, and only the BFV carries the
`MR_EXTEND` attribute. The TD HOB — which is where the vCPU count and guest RAM
size live — is page-added but never content-extended, so its contents never
reach MRTD. The guest kernel, initrd and command line are measured by TDVF into
**RTMR[0..2]**, which `pkg/ratls.VerifyPolicy` does not pin (see the comment on
`Measurements`, and `attestation-go`'s `ExpectedLaunchDigest` → `MrTd` mapping).

Confirmed on live hardware. Two `kata-qemu-tdx` pods on the same node, booting
the same TDVF, differing only in vCPU shape:

| register | pod A (no CPU limit, `-smp 1`) | pod B (`limits.cpu: 500m`, `-smp 2`) | |
|---|---|---|---|
| **MRTD** | `c78e2b8b…60b12a` | `c78e2b8b…60b12a` | **same** |
| RTMR[0] | `8c7ccd95…` | `9ce3cd3f…` | differs — TD HOB (vCPUs, RAM) |
| RTMR[1] | `695c8bf4…` | `695c8bf4…` | same — same `vmlinuz` |
| RTMR[2] | `bd64df1e…` | `1f94cec2…` | differs — cmdline `nr_cpus=1` vs `2` |
| RTMR[3] | zero | zero | unused here |

This is why the kata-image-puller pins `default_vcpus = 1` on the **SNP** shims
only and deliberately leaves the TDX shims unpinned
(`internal/helmchart/c8s/files/scripts/pull-and-configure.sh`).

Practical consequence: give every TDX node the same TDVF and the whole fleet
shares one allow-list entry. Changing the kata-static payload (and so `TDVF`)
is the only thing that moves it.

### Implementation

`pkg/tdxmeasure` is a thin wrapper over
[`github.com/google/gce-tcb-verifier/tdx`](https://github.com/google/gce-tcb-verifier)
`MRTD()` rather than a local reimplementation of the Intel TDX Module Base
Architecture Specification. That library is the only maintained Go
implementation of the algorithm; `go-tdx-guest`, which `attestation-go` already
wraps, parses and verifies quotes but does not predict measurements.

Its `LaunchOptions` API is GCE-shaped, and **only the plain default is correct
for kata/QEMU**:

| options | result on our TDVF |
|---|---|
| `LaunchOptionsDefault("")` | matches hardware ✅ |
| `LaunchOptionsDefaultTDHOBBug("")` | `2815d6db…` — models a Google hypervisor bug ❌ |
| `DisableUnacceptedMemory = true` | `2815d6db…` — changes the TD HOB ❌ |

`pkg/tdxmeasure.launchOptions()` pins the correct one, and
`TestOtherLaunchOptionsAreWrong` fails if upstream ever makes the others
equivalent. **Risk accepted:** a change to the library's default `LaunchOptions`
would silently move the pinned measurement. `TestMRTDMatchesHardware` is the
tripwire — it asserts the hardware-captured digest, so a dependency bump that
moves the value fails the build rather than shipping a wrong pin.

### Re-validating against hardware

The 4 MiB TDVF is not committed. CI's TDX MRTD tripwire job fetches the
pinned TDVF out of the kata-static release the nodes' kata-deploy installs,
sha256-checks it against the pin next to its URL in `.github/workflows/ci.yml`,
and runs the `pkg/tdxmeasure` tests with `C8S_TDVF` set, failing if any test
skips. Elsewhere the hardware check runs only where the firmware exists (a TDX
node, or `C8S_TDVF=/path/to/OVMF.inteltdx.fd`), skipping if the TDVF is not
the sha256 the expected digest was captured from. The CLI wiring is covered in
CI with a synthetic TDVF.

To re-capture the expected MRTD after a kata-static bump, read it from a live
pod's own attestation report. The in-guest attestation-service listens on
`127.0.0.1:8400` inside the guest (the guest has no `curl`, so use bash's
`/dev/tcp`), reachable via the agent debug console on a `--debug` install:

```console
$ SID=$(crictl pods --name <pod> -q)
$ sudo script -qec "/opt/kata/bin/kata-runtime exec $SID" /dev/null
# RD=$(head -c48 /dev/zero | base64 -w0)   # 64 zero bytes, any report_data works
# BODY="{\"report_data\":\"$RD\",\"platform\":\"tdx\"}"
# exec 3<>/dev/tcp/127.0.0.1/8400
# printf 'POST /attest HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' ${#BODY} "$BODY" >&3; cat <&3
```

The response's `evidence.quote` is a base64 TDX quote; its `MRTD` is what
`c8s kata measure --platform tdx` must reproduce. CDS also logs refused
measurements verbatim (`measurement not in allowlist`) if the allow-list is
already pinned.

### TDX limitations

- **RTMRs are not computed.** c8s pins MRTD only, so `measure` does not
  reconstruct RTMR[0..2] (TD HOB, guest firmware, kernel/cmdline). Pinning them
  would need per-pod-shape values and a CC event log policy — see the
  `Measurements` comment in `pkg/ratls/verify.go`.
- **TDVF metadata must be present.** The tool refuses a firmware image without
  a TDX metadata GUID block, a TD HOB section, or whose firmware volumes do not
  tile the image.
- **`MRCONFIGID` / `MROWNER` / `MROWNERCONFIG` are assumed zero.** kata sets
  `mrconfigid` from the init-data digest when the pod carries an init-data
  annotation, so the assumption holds only for pods without one; `MROWNER` and
  `MROWNERCONFIG` are never set. None are part of MRTD, so `measure` is
  unaffected either way, but a policy that pinned them would need capturing
  separately.

## Limitations

These apply to the SNP path.

- **QEMU only.** The VMSA reset state is QEMU's. A different VMM produces a
  different page and a different digest.
- **Direct kernel boot only.** A guest whose `manifest.json` reports a boot
  model other than `kata-direct-kernel` is refused; an IGVM guest is measured
  from the IGVM file, not from these inputs.
- **No initrd.** kata's SNP path boots `vmlinuz` plus a dm-verity rootfs disk;
  the hash table still carries an initrd entry holding the hash of the empty
  string, which is what QEMU writes.
- **`SEV_FEATURES` is an assumption**, defaulting to `0x1`. A host kernel that
  enables DebugSwap would launch guests with `0x21` and every digest would
  move; `--guest-features` covers that.

## See also

- [`kata-guest-base.md`](kata-guest-base.md) — the measured guest image and the
  wider attestation chain.
- [`secrets.md`](secrets.md) — why CDS needs `cds.measurements` to serve secrets.
- [`kata.md`](kata.md) — installing the kata runtime.
