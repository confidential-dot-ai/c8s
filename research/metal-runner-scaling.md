# Scaling the `snp-metal-cvm` runner — why the huge box runs one small runner

> Status: DECISION (2026-07-22). A now, skip B, build toward C. Written after
> the metal lane bottlenecked two rehearsals behind `maxRunners: 1`.

## The confusion this resolves

"The metal box is a 48-vCPU / 93 GB EPYC — why is `maxRunners: 1`?"

Because jobs don't run on the box. They run inside **one standing SEV-SNP CVM
guest** that is 4 vCPU / 16 GB. The host sits at ~3% CPU / 27% memory with ~44
cores and ~65 GB idle right next to a runner that can't fit a second compile.
The box is huge; the runner is not.

## Two ceilings, and they are not the same

| axis | capped by | changeable? |
|---|---|---|
| **vCPU** | the measured boot | **No, not freely.** The guest boots `rke2.igvm` at `smp: 4`; the launch digest (`131b1a32…`) is computed *for* 4 vCPUs (SNP measures the initial VMSA per vCPU). Change the core count and attestation no longer matches — CDS rejects it. The image ships only the smp4 IGVM. Going wider = a base-images ask (publish `guest-smp8/16.igvm` + a new golden digest). |
| **memory** | nothing in the measurement | **Yes.** RAM size is not part of the SNP launch measurement, so the guest can go 16 GB → 48 GB with a one-line manifest change and the same golden digest. |

Memory is what OOM'd it: rke2-on-tmpfs eats ~9 GB of the 16, leaving ~5 GB, so
two concurrent 4-way rust compiles blew it (runs 29854690919 / 29854809091).
That is the entire reason for `maxRunners: 1`.

## The two-layer architecture (why "ARC provisions the runners" is only half true)

1. **Guest VM — NOT ARC.** `provision-snp-metal-cvm.yml` boots one KubeVirt SNP
   CVM over the serial console and installs ARC inside it. Once. This is the
   thing the c8s reaper deleted on 2026-07-22 (vendoring drift, c8s#114).
2. **Runner pods — this IS ARC.** Inside that guest runs a single-node rke2 with
   ARC: a controller + a listener that long-polls GitHub. A job targeting
   `snp-metal-cvm` makes ARC spin up an ephemeral runner *pod*, then tear it
   down. `maxRunners` is the ARC cap on those pods.

ARC autoscales **pods within one cluster**. It cannot autoscale **guests** —
each SNP guest is its own single-node rke2, and ARC can't see across the VM
boundary. That single fact is what separates the three options below.

## The options

| | A: bigger guest | B: N guests | C: ephemeral per-job |
|---|---|---|---|
| parallel unit | runner **pods** | whole **guests** | whole **guests**, 1/job |
| provisioned by | **ARC** (pod autoscaler) | console bootstrap ×N | a per-job launcher |
| ARC installs | 1 | N | 1 or none |
| isolation | N pods share **one** TEE/kernel/tmpfs | N **separate** SNP TEEs | fresh TEE per job |
| vCPU per job | 4, shared N ways | 4, dedicated | 4, dedicated |
| host usage | ~one guest | ~4–5 guests (~17 GB each) | scales to host limit |
| effort | ~10 min, 2 values | a project (see traps) | primitive-v2 future |

### A — bump guest memory + `maxRunners: 2`

Pure ARC change + a VM-size change, no new mechanism. Guest → 48 GB (safe: not
in the measurement), cap → 2. ARC then runs two runner pods in the one guest;
memory stops being the OOM cause. Ceiling: still 4 vCPUs, so two jobs *share*
4 cores — both finish, each slower. For the real pain (two lib merges landing
together and queueing) that is a straight win: 2 slower-in-parallel beats
1-then-1. Practical max ~2–3 before CPU contention dominates.

### B — multiple standing CVMs (looks like the middle option; is a trap)

Two independent reasons, both already hit elsewhere in this repo:

- **The clean form is blocked by the CIDR collision.** The elegant B is *one*
  rke2 cluster with N SNP CVMs as worker nodes → one ARC, one label, pods land
  on confidential nodes. That is exactly the `azure-cvm` model (ARC on AKS,
  runners on CVM nodes in the pool). On metal it is impossible today because the
  host cluster and in-guest rke2 both use `10.42/16` — the same collision that
  forced the console model instead of a reachable guest apiserver.
- **The hacky form trips the exclusive-session rule.** N guests each running
  their own ARC cannot all serve `snp-metal-cvm`: GitHub's broker session is
  exclusive to one listener (the same fact that made the westus SNP cutover
  work by *deleting* the old RG — two listeners can't own one scale set). So
  hacky-B needs distinct labels (`snp-metal-cvm-1`, `-2`…), which breaks the
  single `runs-on: snp-metal-cvm` contract every consumer depends on.

You'd do the work of B and mostly wish you'd done C.

### C — ephemeral per-job CVMs

A fresh SNP CVM booted per job, torn down after. Host-bound parallelism, and
the *most* correct confidential story — no shared blast radius, each job in its
own measured TEE. Needs the in-guest agent transport (a per-job VM can't be
console-bootstrapped — too slow/fragile), which is [[guest-transport]] /
primitive-v2, and it converges with the [[arc-in-cvm]] north star.

## Decision

**A now, skip B, build toward C.**

- A is the cheap real win today and introduces no new failure mode.
- C is the actual answer to "use the huge box" and the strongest confidential
  posture; its prerequisite (an agent channel / guests reachable as nodes) is
  already on the roadmap.
- B's clean form and C share that same prerequisite, so effort spent unblocking
  it should go to C, not to a stopgap that hand-manages 5 console-bootstrapped
  guests.

**None of A/B/C makes a single compile faster** — 4 vCPUs per guest is the
measured-boot ceiling until base-images ships a wider IGVM. They buy *more jobs
at once*, not faster jobs. If per-job speed becomes the pain, the ask is a
wider-SMP IGVM variant, which is orthogonal to all of the above.
