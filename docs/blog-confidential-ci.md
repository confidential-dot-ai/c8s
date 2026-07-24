# Confidential CI: Tests That Run Inside a TEE

**Every change to our attestation libraries now runs inside a real SEV-SNP or Intel TDX machine, and our confidential Kubernetes is exercised the same way, so gaps between code and silicon surface in CI instead of in production.**

Over the past year we have shipped a confidential computing stack: **c8s**, our confidential Kubernetes; **Kettle**, our attested build tool; the attestation libraries underneath both; and **Confidential OS Builder**, which produces the measured images they all run on. Every one of those pieces makes the same promise. Your code runs inside a Trusted Execution Environment, and you can cryptographically verify that it did.

A promise like that is only as good as the last time you checked it. Today we want to talk about the part of the stack that checks it for us on every change: continuous integration that runs inside a real TEE.

## Why does confidential software need confidential CI?

Ordinary CI runs on an ordinary virtual machine. It can compile your code and run your unit tests, and for most software that is enough. For confidential software it is not. A normal runner cannot tell you whether your attestation still verifies against genuine hardware, whether a measured boot still produces the launch measurement you expect, or whether a confidential workload can still get its certificate from a real TEE. Those behaviors do not exist on a plaintext machine. They only exist on confidential silicon.

The tempting shortcut is to simulate: mock the attestation device, stub out the quote, assert against a recorded value. That tests your code against your own assumptions, which is exactly the wrong thing to test. A confidential computing bug is almost always the gap between what the software believes and what the hardware does. If your test never touches the hardware, it never finds the bug.

```
   ordinary CI       code  →  mock the attestation  →  looks fine
   confidential CI   code  →  real TEE hardware     →  pass or fail
```

That is why we test on the real thing. Until recently we did it by hand: stand up a fresh confidential cluster, run the checks, tear it down, roughly once a week or whenever a change felt risky. That does not scale, and it finds regressions long after they land instead of the moment they do. We wanted the opposite. Merge a change, and within minutes watch it run on real confidential hardware, with any problem reported automatically.

## The primitive: boot, attest, run, tear down

At the center is one small, deliberately generic mechanism. Give it a platform and a payload, and it runs a fixed sequence. It boots a measured confidential VM (a CVM) on that platform. It proves the guest is a genuine TEE, not a host advertising capabilities it does not enforce. It reads the runtime launch measurement directly from the hardware, the exact value a verifier would check. Then it runs the payload inside the guest, streams the results back out, and disposes of everything afterward, including anything a cancelled run might have left behind.

What makes it useful is what it does not know. It has no idea what it is testing. The confidential machinery, the booting and attesting and safe disposal of a TEE, is written once and shared. Everything specific to a given project lives in that project's payload, and nowhere else.

## One primitive, many payloads

That split is the whole design, because the payloads have almost nothing in common.

```
  MODEL 1 · NODE-as-CVM        c8s   (the confidential Kubernetes distro itself)
  ──────────────────────────────────────────────────────────────────────────────────────────────

     merge to c8s main              c8s repo (PUBLIC)                 runs on the metal        boots an EPHEMERAL
                                                                      SNP launcher HOST        measured CVM = the cluster:
      push ─▶ "Docker"           confidential-e2e.yml                 ────────────────         install THIS c8s commit, attest
              image build ─▶       └─▶ e2e-c8s.yml        ──────▶     label: cvm-launcher      the launch measurement, prove a
              └─▶ workflow_run         └─▶ cvm-e2e.yml                                          workload gets a CDS cert, teardown
                                       (vendored primitive)

     LANE snp-metal  ✓ ON-MERGE   run 29978275402 (VMI Running + attested)
     LANE azure-snp / azure-tdx   ◐ exist HUB-side (MODEL 3), not wired to a c8s merge

        ┌──────────────────────────────────────────┐
        │  SEV-SNP BARE METAL   EPYC Genoa         │
        │  /dev/sev-guest   IGVM measured boot     │
        │  shared ROX rootdisk, readonly (PR#24)   │
        └──────────────────────────────────────────┘


  MODEL 2 · RUNNER-in-CVM      attestation-rs & kettle   (libraries: run the suite INSIDE a standing runner)
  ──────────────────────────────────────────────────────────────────────────────────────────────

     merge to main ─▶  attestation-rs : confidential-e2e.yml  ( job `tee`, matrix )
                       kettle         : e2e.yml               ( job `tee`, matrix + roundtrip* )
                       each matrix cell = runs-on: <label> ─▶ cargo nextest --features attest --run-ignored all

     LANE snp-metal               LANE azure-snp               LANE azure-tdx               LANE tdx-metal
     runs-on: snp-metal-cvm       runs-on: azure-snp-cvm       runs-on: azure-tdx-cvm       runs-on: tdx-metal-cvm
         ▼                            ▼                            ▼                            ▼
     ┌────────────────────┐       ┌────────────────────┐       ┌────────────────────┐       ┌────────────────────┐
     │ SEV-SNP BARE METAL │       │ Azure SEV-SNP      │       │ Azure Intel TDX    │       │ Intel TDX METAL    │
     │ EPYC Genoa         │       │ AKS node = CVM     │       │ VM (DC4es_v6)      │       │                    │
     │ /dev/sev-guest     │       │ vTPM /dev/tpmrm0   │       │ vTPM + /acc/tdquote│       │ ✗ NO host          │
     │                    │       │ scale-to-zero      │       │                    │       │ ✗ NO TDX image     │
     └────────────────────┘       └────────────────────┘       └────────────────────┘       └────────────────────┘
     ars ✓  kettle ✓              ars ✓  kettle ✓              ars ✓  kettle ✓              ✗ commented out,
     29979358753 / 29979359926    6/6 az_snp_live              14/14 az_tdx_live            no runner exists


  MODEL 3 · c8s-on-CLOUD       confidential-ci hub    (full c8s CLUSTER on cloud · NIGHTLY / DISPATCH, not merge)
  ──────────────────────────────────────────────────────────────────────────────────────────────

     azure-e2e.yml     ─▶ ephemeral confidential AKS (Model B, DC4as_v5 SEV-SNP) ─▶ c8s install --cvm-mode aks,
                                                                                   6 components, NRI enforce,
                                                                                   consumption + NEGATIVE deny
                                                                                   ✓ 29979488305 (busybox NRI-denied)
     azure-tdx-e2e.yml ─▶ ephemeral Azure Intel TDX VM + RKE2 (AKS refuses TDX)  ─▶ c8s install, az-tdx RA-TLS attest
                                                                                   ✓ 29979489430 (E2E_PASS @ 320s)


  STANDING-RUNNER PROVISIONERS (confidential-ci, dispatch)          POD-as-CVM / kata
  ───────────────────────────────────────────────────────           ─────────────────
  provision-snp-metal-cvm.yml ─▶ snp-metal-cvm (readonly ROX)       ✗ NO e2e lane anywhere.
  provision-azure-cvm.yml     ─▶ azure-snp-cvm (Model A)            kata-guest-base.yml only BUILDS
  provision-azure-tdx-cvm.yml ─▶ azure-tdx-cvm (standing TDX VM)    the guest image; nothing
  provision-tdx-metal-cvm.yml ─▶ tdx-metal-cvm ✗ 0 runs (stub)      installs/attests it.

   * kettle roundtrip = GitHub-hosted HTTP client to the REMOTE orchestrator (build.confidential.ai); not a self-hosted runner.
```

**c8s** installs an entire cluster inside the CVM and then proves that a confidential workload receives its certificate from the attestation service. That certificate only issues if the node attests the exact launch measurement we pinned, so a successful certificate is the attestation proof. There is no separate "did attestation work" step to bolt on. The thing the product is supposed to do, and the thing we are verifying, are the same event.

**Our attestation libraries** boot the same measured CVM and run their own test suite against the real attestation device, including the tests that cannot run anywhere else. Each on-merge run executes 244 tests inside a live SEV-SNP guest, and the ones gated on hardware take their true path against the attestation device instead of a mock.

**Kettle** reaches confidential behavior from two directions. It boots the same measured CVMs to run its own TEE-gated integration suite, and it drives a remote build orchestrator's TEE as a client: it commissions a fresh attested build and then verifies the result fail-closed, so the signature, the provenance, the checksums, and the binding to a specific launch measurement all have to check out or the test fails.

Three projects, one mechanism. One installs Kubernetes and proves a certificate. One runs a Rust suite against the hardware. One verifies a build that ran in a TEE somewhere else entirely. They ride the same primitive, and adding a fourth is a matter of writing a payload, not standing up new infrastructure.

## The matrix: SEV-SNP and TDX, metal and cloud

Confidential computing is not a single platform. Our users run on AMD SEV-SNP and Intel TDX, some on bare metal they operate themselves, some in clouds they rent by the hour. The guarantees differ on each.

```
                  bare metal      cloud
     SEV-SNP      live            live
     Intel TDX    next            live
```

So the tests run across that grid rather than on a single representative box. On our own SEV-SNP metal, each run boots an ephemeral measured cluster and proves attested certificate issuance from end to end. The attestation libraries run on a wider spread still: SEV-SNP on metal, and both SEV-SNP and Intel TDX in the cloud, where the payload exercises the cloud-specific attestation paths, the virtual TPM and the provider's quoting service, that do not exist on bare metal. Because the primitive already knows how to boot each platform, a project opts into a new one by naming it, with no rebuild required.

## What it catches

The reason to run tests on real hardware is that hardware disagrees with your assumptions, and CI is where you want that argument to happen. The first automated pass over each project surfaced bugs that a plaintext runner could never have seen.

In the attestation libraries, one test encoded its nonce differently than the hardware contract requires, and a second failure appeared only when two test processes contended for the same virtual TPM session. In Kettle, the integration test suite had bit-rotted and had never once run to completion, so nobody had noticed it was broken. The first two are gaps between code and hardware; the third was a test that had silently stopped running and only got exercised once real integration did. All three are exactly the class of problem this system exists to find, and none of them can surface on a plaintext runner. In each case we fixed it and re-ran the same job, on the same hardware, to prove the fix before merging.

```
change lands  →  runs in a TEE  →  a real problem surfaces  →  fix  →  prove it on hardware  →  merge
```

That loop is the entire point: a change lands, integration runs in a TEE, real problems surface. It is the difference between believing your confidential software works and watching it work.

## What is next

We are widening the grid to Intel TDX on bare metal, where the hardware is already in place, and to confidential pods running alongside confidential nodes.

We are also ripping out the last piece of fragile plumbing: command delivery over a serial console. In its place goes a small attested in-guest agent, the only transport that also works in the cloud, where there is no console to fall back on.

And the long-term aim is to run the CI workflow itself inside a TEE, with the runner's registration gated on attestation. The system under test already runs in the TEE, which is what test fidelity requires; putting the pipeline in there too is about trusting the pipeline itself.

The throughline across everything we build is the same one. Do not ask anyone to trust the host, the cloud, or whoever holds root. Give them something they can verify for themselves. Our CI now holds our own stack to that standard, on every change we make. c8s, Kettle, and Confidential OS Builder are all open source on GitHub. If you are building on confidential hardware and want to test it honestly, read the code, open an issue, or tell us what you would run on the primitive.

## The lanes in full

A compact view of every lane and where it stands:

| REPO \ LANE | snp-metal | azure-snp | azure-tdx | tdx-metal | pod/kata |
|---|---|---|---|---|---|
| **c8s** (node-as-cvm) | ✅ ON-MERGE (boots ephemeral CVM) | ◐ hub nightly (Model B, AKS) | ◐ hub dispatch (ephemeral TDX VM) | ⛔ stub (no host/image) | ⛔ none |
| **attestation-rs** (runner-in-cvm) | ✅ ON-MERGE | ✅ ON-MERGE | ✅ ON-MERGE | ⛔ commented | ⛔ none |
| **kettle** (runner-in-cvm) | ✅ ON-MERGE | ✅ ON-MERGE | ✅ ON-MERGE | n/a | ⛔ none |

`✅` verified green on merge · `◐` green but hub-triggered (nightly / dispatch), not on a c8s merge · `⛔` not wired

And the sweep that verified them all green on real hardware in one afternoon (all via `workflow_dispatch`, no merges):

| Lane | Run | Proof |
|---|---|---|
| c8s snp-metal | 29978275402 | `VMI Running` + `attested` |
| attestation-rs (3 cells) | 29979358753 | snp-metal ✅ · azure-snp **6/6 az_snp_live** · azure-tdx **14/14 az_tdx_live** (0 skipped) |
| kettle (3 cells + roundtrip) | 29979359926 | all cells ✅ · **Verification PASSED ×4** |
| c8s on azure-snp (Model B) | 29979488305 | install + **NRI negative-deny** (busybox blocked at container create) |
| c8s on azure-tdx | 29979489430 | **E2E_PASS @ 320s**, az-tdx RA-TLS attested |
