# ADR: the one-line platform matrix — share the RUNNER, not a workflow (2026-07-20)

Decision reached via a 4-lens judge panel + adversarial verification + verified
GitHub-Actions facts (research workflow wf_627ab0ef-020). Foundational: it sets
the shape of the matrix for every future consumer.

## Goal (user's framing)

A matrix `[snp-metal, snp-azure, tdx-metal, tdx-azure]` where any PUBLIC org repo
adds ~one line and the payload runs in a genuine measured TEE of that platform,
on merge. Shared CI infra was in a PRIVATE repo → public consumers can't `uses:`
it → c8s's merge-trigger is currently broken. That block forced the question.

## Decision

**Share the RUNNER, not a workflow — mechanized as a two-shape hybrid (C-as-A):**
- **Lib consumers** ("run my tests in a TEE": attestation-rs, kettle, ~all future
  repos) → one **ephemeral ARC-in-CVM runner LABEL per platform**. Consumer =
  `runs-on: ${{ matrix.runs_on }}` + its own steps. No cross-repo workflow.
- **c8s** ("provision a fresh measured CLUSTER on platform X, install, verify")
  → its OWN in-repo provision orchestration (`uses: ./…`, the-machine-literal).

## Why (verified facts + the resolved asymmetry)

**GitHub facts that constrain this (all `high` confidence, doc-cited):**
- `runs-on: ${{ matrix.runs_on }}` (incl. `[self-hosted, <label>]` arrays via
  `matrix.include`) is fully supported for self-hosted labels → the lib one-line
  matrix is idiomatic and real.
- A reusable-workflow `uses:` MUST be a static literal (no `${{ matrix }}` on the
  ref); you can only matrix the `with:` inputs. So "matrix picks which workflow"
  is impossible — a shared dispatcher must branch internally on a `platform`
  input.
- Public→public reusable calls work; public→PRIVATE is blocked outright (the
  current break). A LOCAL `uses: ./…` call has no visibility problem.

**The asymmetry is structural, not cosmetic** — so the architecture honors it
instead of hiding it:
- Lib cell = "a runner that IS a TEE of type X; run my steps." Maps perfectly to
  share-the-runner (the-machine model; scales to N repos by sharing the runner,
  not a workflow). Evolution seam = a single label string.
- c8s cell = provision a fresh cluster + test it from a kubectl-holding runner —
  a fixture topology, NOT run-steps-in-a-TEE. A standing shared runner would
  cross-contaminate runs (a correctness bug).

**Why not B (one public dispatcher workflow):** the adversary killed its only
advantage. Forcing both shapes behind one `platform` input makes the "single
clean dispatcher" a union type (`payload_b64` OR provision-cluster) with an
internal `if`-switchboard = C living inside B, PLUS two B-only taxes A/C avoid:
(1) a cross-repo `@sha`-sync treadmill (bump N public repos on every dispatcher
change; `@main` throws away supply-chain pinning — reckless with public +
self-hosted); (2) OIDC `job_workflow_ref` homogenization — every consumer's JWT
points at the shared file, so cloud/attestation trust policies can't tell c8s's
cluster creds from kettle's test creds. Under A/C the workflow is in-repo →
`job_workflow_ref` is per-repo → cleaner trust for free.

**Why not pure A:** cracks on c8s (standing-runner cross-contamination) and would
force a toolchain into the verity-sealed metal guest (enlarging the measured
TCB). C takes A's mechanism where it fits (libs) and gives c8s the honest path.

**Fork-safety (load-bearing):** share-the-runner concentrates fork-PR blast
radius on shared TEE runners → the runners MUST be **ephemeral-per-job** (fresh
measured pod per run, torn down after) to recover confinement, + fork-PR
approval gating on the runner group. This is not optional.

## The consumer snippets

Lib (attestation-rs-shaped) — "add a platform" = one array line, zero new files:
```yaml
jobs:
  tee:
    strategy:
      matrix:
        runs_on: [[self-hosted, snp-metal-cvm], [self-hosted, azure-cvm],
                  [self-hosted, tdx-metal-cvm], [self-hosted, azure-tdx-cvm]]
    runs-on: ${{ matrix.runs_on }}
    steps:
      - uses: actions/checkout@v4
      - run: cargo nextest run     # test auto-detects the SNP/TDX device
```
c8s — its own in-repo provision workflow (LOCAL uses → unblocks the merge trigger):
```yaml
jobs:
  cluster-e2e:
    strategy: { matrix: { platform: [snp-metal, snp-azure, tdx-metal, tdx-azure] } }
    uses: ./.github/workflows/e2e-c8s.yml   # lives IN c8s, not confidential-ci
    with: { platform: ${{ matrix.platform }} }
    secrets: inherit
    permissions: { id-token: write, contents: read }
```

## ✅ SPIKE PROVEN (2026-07-21, run 29791698959): ARC runs IN the metal node-CVM

The load-bearing assumption under the lib rail is confirmed on real SNP hardware
(`probe-arc-in-cvm.yml`, reusing the cvm-e2e primitive): ARC installs into the
in-guest rke2, its **listener authenticates to GitHub + registers a runner from
inside the SNP guest** (egress + App auth work in-TEE), an **ephemeral runner
pod comes up Running**, and that pod **reads /dev/sev-guest = genuinely in the
TEE**. Full marker chain green: NS_PRIVILEGED → CTL_UP → LISTENER_REGISTERED →
RUNNER_POD_UP → RUNNER_IN_TEE → PAYLOAD_OK.

Every failure across 4 iterations was standard k8s friction, not a fundamental
blocker — the two load-bearing config facts for the real `snp-metal-cvm` build:
1. **PSA**: label `arc-systems` + `arc-runners` `pod-security…/enforce=privileged`
   (same as c8s-system) or the controller/runner pods never get created
   (deploy 0/1, rs DESIRED=1/CURRENT=0).
2. **Runner overlay**: the runner pod needs `securityContext.privileged: true` +
   hostPath `/dev/sev-guest` (the azure-cvm VALUES_FILE pattern) to read the SNP
   device — lib tests need this. Reuse register.sh's VALUES_FILE.

=> Phase 1 is a BUILD of proven pieces (boot measured rke2-node CVM + register
ARC with the two facts above), not a research risk. The remaining unproven bit
(a real job ROUTING to the in-guest runner) is standard ARC once a runner is
online — cheap follow-up, not a gate.

## Migration path

- **Phase 0 — SOONEST c8s unblock (days):** relocate `e2e-c8s.yml` + the metal
  boot orchestration it needs OUT of private confidential-ci and INTO c8s as
  local workflows; c8s's trigger calls `uses: ./…`. Public→private block gone,
  no public repo, no visibility gymnastics. NOT N-way duplication — this
  orchestration is c8s-specific (libs won't use it once they move to the runner
  rail).
- **Phase 1 — lib share-the-runner rail:** build `snp-metal-cvm` = ephemeral ARC
  pod on the measured rke2-node CVM (image exists); make `azure-cvm`
  ephemeral-per-job. Migrate attestation-rs + kettle to `runs-on: matrix.runs_on`
  + own steps; retire console-delivery for libs (runner IS the TEE). Test
  auto-detects SNP/TDX. Fork-PR approval gating ON.
- **Phase 2 — TDX (each = one array line for every existing lib consumer):**
  `tdx-metal-cvm` on tdx-dev-host-1 (kata / confos PR#51); `azure-tdx-cvm` =
  standalone DCesv5 CVM runner (aks+tdx refused).
- **Phase 3 — c8s converges:** as c8s's install binary collapses provision→steps
  and the in-guest agent replaces console delivery, c8s's `cluster-e2e` runs as
  plain steps on the same labels; its bespoke workflow shrinks and retires.

End state: 4 org-registered ephemeral self-hosted TEE runner labels; a new lib
repo writes the block above; "add a platform" = one array line, **nothing to
sync** (no `@sha`, no shared workflow). c8s converges last, by deleting its
bespoke path — not by adopting a dispatcher.

## The tradeoff we accept

Two consumer shapes, not one uniform interface. Metal provision orchestration
lives in two places (c8s in-repo + the lib rail's runner provisioning) until
Phase 3 collapses it — real duplication carried temporarily. c8s's cell is
bespoke. Ephemeral-per-job recycling + fork-PR gating are load-bearing. In
exchange: no public shared-workflow SPOF, no `@sha` treadmill, no OIDC identity
homogenization, and a seam that's a label string — aligned with the
runner-in-TEE endpoint every roadmap future already walks toward.
