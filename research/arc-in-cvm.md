# ARC-in-CVM (`confidential-cvm`) — the north star, not the next step

> Status: DESIGN POINTER (2026-07-15). Decision: payloads on the primitive NOW;
> this later. Recorded so the end-state stays visible while we build toward it.

## What it is

A runner label — `confidential-cvm` — where the ARC runner pod itself runs
INSIDE a SEV-SNP (later TDX) CVM. Then `runs-on: confidential-cvm` puts every
job step in a real TEE natively:

- payloads become ordinary workflow steps (checkout, cargo test, actions);
- the serial-console delivery path — the flakiest, slowest, least secret-safe
  part of today's primitive — disappears entirely;
- repos stop writing payload scripts; the whole marketplace of actions works.

Today's honest naming makes the gap visible: `cvm-launcher` is a host-side
container that LAUNCHES CVMs (proven not-a-TEE by where-am-i.yml);
`confidential-cvm` would BE the TEE.

## Why it's not now (the blockers, concretely)

1. **Runner image inside a verity guest.** The ARC runner needs its image +
   a container runtime inside the measured guest. Either the rke2-node flavor
   (guest is a k8s node; ARC schedules runner pods onto it — nested containers,
   no nested VMs needed) or a purpose-built runner guest image. Both are
   base-image work with a measurement lifecycle.
2. **Attestation-gated registration (the actual north star, improvement #14).**
   A runner that merely RUNS in a CVM proves nothing to anyone else. The value
   is: the runner attests, and its GitHub registration token is RELEASED to it
   only against a valid quote — i.e. CDS key-release
   (attest/DESIGN.md P3: verify via CDS, `report_data = H(nonce ‖ pubkey)`
   binding, secret release on success). Then "this CI job ran in a measured
   TEE" is a verifiable claim, not an ops assertion. Prereq chain:
   attest P3 → token release → ARC registration flow.
3. **Capacity + lifecycle.** One metal host runs both the launcher runners and
   the CVMs; runner-pods-in-CVMs multiplies memory pressure (each idle runner
   holds a CVM). Needs scale-to-zero CVMs or a pool sized honestly against the
   host.

   See `metal-runner-scaling.md` for the concrete A/B/C on scaling the built
   `snp-metal-cvm` rail — C (ephemeral per-job CVMs) is this doc's north star
   reached from the scaling angle, and shares the agent-transport prerequisite.

## Cheapest credible path (when we pick this up)

rke2-node flavor already boots a measured single-node k8s cluster as a CVM.
Join that node to the ARC host cluster is wrong (CIDR collision, trust
boundary); instead run a SECOND ARC scale-set controller whose runner pods
schedule onto in-CVM nodes (`kubernetes` mode ARC inside the guest cluster,
registered to the org with its own label). Step 2's token-release gate can come
after a functional (non-gated) `confidential-cvm` exists — but until it does,
document the label as "runs in a TEE" NOT "attested runner".

## What NOT to do

- Don't build a non-confidential simulation of this to "test the mechanics" —
  standing rule; the mechanics ARE the confidentiality.
- Don't retrofit the label onto the launcher runners. One honest rename was
  enough.
