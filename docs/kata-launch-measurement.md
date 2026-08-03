# Predicting a kata guest's launch measurement

`c8s kata measure` computes the SEV-SNP launch digest of a `kata-qemu-snp`
guest offline, from the guest image artifacts plus a pod's vCPU count — no
pod has to boot first.

```console
$ c8s kata measure --vcpus 1
e246273c1efee7dab0f623ffc04c33315fd37925cd9300fdb39d0a19f1b8e38edb95844464577ee89453e4b1eb46f0fb
```

Output is the bare hex digest, one per line, so it pipes straight into
`c8s verify --measurements-file`. `--json` emits the digest plus every input
that produced it; `-v` prints the same inputs to stderr.

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
--cvm-mode=pod` still refuses `--measurements` (`cmd/c8s/install.go`), because
that flag pins the *node* CVM's measurement; the values this tool produces go
into a values file instead.

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

The implementation reproduces both live measurements in the table above from
the artifacts on the node, and `pkg/snpmeasure`'s unit tests check it against
`sev-snp-measure`'s own published vectors using that project's 4 KiB OVMF
fixture — so CI validates the algorithm without a multi-GB guest image. The
end-to-end check against the real image is manual:

```console
$ c8s kata measure --vcpus 1 -v          # on a node with the puller's artifacts
```

and compare with the digest a pod actually reports.

## Why the computation is hand-rolled

`pkg/snpmeasure` implements the ABI directly instead of taking a dependency.
`virtee/sev-snp-measure` is Python. `virtee/sev-snp-measure-go` is Go, but its
README scopes it to *"only supports SNP"* and *"only measures the initial
firmware"* — that is the firmware-only prefix `FirmwareDigest` computes, and
kata's direct-kernel boot with `kernel-hashes=on` needs everything after it:
the kernel/initrd/cmdline hash page and one VMSA page per vCPU. Its OVMF
metadata parser does accept `SNP_KERNEL_HASHES` (`0x10`); that was never the
obstacle.

## SEV-SNP only

`c8s kata measure` refuses to run on a node whose TEE is not SEV-SNP, because
the failure is otherwise silent: kata-static installs `AMDSEV.fd` into
`/opt/kata/share/ovmf/` on **every** node, next to `OVMF.inteltdx.fd`. On a TDX
node the default `--firmware` therefore still parses and still yields a
well-formed 48-byte digest — one that matches nothing, and that refuses every
pod once pinned.

The gate reads the node, not the flags:

1. the shim carrying the puller's drop-in (`runtimes/qemu-snp/config.d/50-c8s.toml`
   vs `runtimes/qemu-tdx/…`, rooted at `--kata-config-dir`) — the config that
   will actually boot this guest;
2. failing that, `/sys/module/kvm_intel/parameters/tdx`, for a node where c8s is
   not installed yet.

The firmware image itself is **not** a usable signal: every OVMF build kata
ships — `AMDSEV.fd`, `OVMF.fd`, `OVMF.inteltdx.fd` — carries both an `ASEV`
metadata table and a `TDVF` one. What marks the SNP build is a populated
`SNP_KERNEL_HASHES` section and a non-zero `SEV_HASH_TABLE_RV`, which
`pkg/snpmeasure` already requires — but that only catches an explicit
`--firmware`, never the dangerous default. `--kata-config-dir ""` skips the
gate, for measuring an SNP fleet from a machine that is not one of its nodes.

### Why TDX is not a flag

The SNP digest is an iterative SHA-384 over page-type-tagged `PAGE_INFO`
entries, ending in one VMSA page per vCPU. TDX's analogue, **MRTD**, is built by
the TDX module from `TDH.MEM.PAGE.ADD` / `TDH.MR.EXTEND` over TDVF and the TD's
initial memory. Different firmware, different measured objects, different
extension rule: none of `pkg/snpmeasure` carries over.

### What c8s pins on TDX

One value. `VerifyPolicy.Measurements` is MRTD on the TDX path
(`pkg/ratls/verify.go`), and `attestation-go`'s TDX verifier maps
`ExpectedLaunchDigest` onto `TdQuoteBodyOptions.MrTd` (48 bytes). RTMRs are not
pinned at all — c8s strips the CC event log out of TDX evidence
(`pkg/attestclient/tdx.go`). So TDX parity for this tool means computing MRTD,
and only MRTD.

### Open: does MRTD vary with pod shape?

On TDX the kernel, initrd and cmdline land in RTMRs measured by TDVF, not in
MRTD, and the puller drop-in already assumes vCPU init (`TDH.VP.INIT`) and guest
RAM size stay out of MRTD (`pull-and-configure.sh`, the `default_vcpus` block —
which is why the `default_vcpus = 1` pin is SNP-only). If that holds, a TDX
fleet needs **one** MRTD for every pod shape and the per-shape enumeration above
disappears, making TDX simpler than SNP rather than harder. It has not been
confirmed on hardware. Settle it there before scoping the work.

## Limitations

- **SEV-SNP only**, and refused on other platforms — see above.
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
