# c8s e2e in CI — design

## ✅ MIGRATED TO THE ORG + GREEN THERE (2026-07-15)

The lane now runs in `confidential-dot-ai/confidential-ci` (private,
`.github/workflows/e2e-c8s.yml`) on the **org** runner and passes end-to-end.

**Runner migration — done.** GitHub App `confidential-ci-runners` (id 4309649,
installation 146850802) scoped to `organization_self_hosted_runners: write` ONLY.
Registered the `confidential-bm` scale set to `confidential-dot-ai` via
`register.sh` APP mode (App creds in a K8s Secret BY REFERENCE, never in helm
values), same `runs-on: confidential-bm` label. Gotchas hit:
- The ARC `gha-runner-scale-set` chart names the AutoscalingRunnerSet after
  `runnerScaleSetName`, so re-registering with the same label **overwrites** the
  old scale set (the cifrai one) — convenient here (that's the migration), but it
  left a stale scale-set-id → listener crash-loop `RunnerScaleSetNotFoundException
  (identifier 3)`. Fix: a clean purge cycle (`register.sh RENAME_FROM=confidential-bm`)
  so ARC re-registers fresh and gets a new id. Then `listener: healthy`.
- **Org-native ghcr auth**: a workflow in a confidential-dot-ai repo pulls the
  private `charts/c8s` with the built-in `GITHUB_TOKEN` (+ `permissions:
  packages: read`) — NO PAT needed. Confirmed working (chart pulled, c8s installed).
- cifrai sandbox repos (`confidential-bm-smoke`, `attestation-rs-ci`) archived.

**✅ GOLDEN ENFORCEMENT NOW REAL (2026-07-15, self-discovering).** Fixed: the
driver reads the node's OWN runtime SNP launch measurement via **configfs-tsm**
(`/sys/kernel/config/tsm/report` → `outblob`, MEASUREMENT at offset 0x90 / 144,
48 bytes — the exact value CDS's `CheckMeasurement`/`LaunchDigestFromSubmods`
compares, case-insensitive hex) BEFORE c8s installs, and pins
`cds.measurements=[<discovered>]` (chart placeholder `RUNTIME_MEASUREMENT`
sed-substituted in-guest). Org run 29458798739 GREEN with `MEAS_ENFORCED` — the
workload cert was ISSUED under the pinned measurement, proving the configfs-tsm
value == what CDS enforces. Self-discovering (correct across image bumps, no stale
constant), fail-closed (a different image measures differently → workload certs
denied), with a fallback to `[]` (accept-any) if configfs-tsm is unavailable so
the lane can't regress. The image `manifest.json` `snp_launch_digest` remains the
WRONG source (it's computed under different assumptions than the KubeVirt boot);
the node's own report is authoritative.

**Original finding (now resolved above):** I pinned
`cds.measurements=[<manifest snp_launch_digest 131b1a32…>]` and CDS returned
`403 measurement_denied: launch measurement not allowed` on WORKLOAD cert
issuance. (The base install stayed green because CDS's OWN serving cert uses
`/attest-key` which SKIPS the measurement check — only workload leaf issuance
enforces it. And I'd misread the sidecar's "entering renewal loop" as success —
it's the sidecar GIVING UP after the initial 403 and scheduling a 6h retry; the
cert was never issued, `tls.crt does not exist after 3m`.) So the
**image `manifest.json` `snp_launch_digest` does NOT equal the node's RUNTIME SNP
launch measurement.** Per the c8s docs order (green-with-`[]`-first, pin after),
the lane runs `measurements: []` = accept-any GENUINE SNP (still a real TEE proof:
CDS serving cert + workload leaf both require a valid hardware SNP quote).
**NEXT (top hardening item):** capture the node's ACTUAL launch measurement from a
live `/attest` report (attestation-cli `launch_digest`) — or recompute it with the
exact KubeVirt boot params (smp, guest policy, IGVM) via steep/sev-snp-measure —
then pin THAT. The manifest value is computed under different assumptions.

## ✅ BARE-METAL SNP LANE GREEN (2026-07-15, run 29 / cifrai sandbox)

`e2e-c8s-snp.yml` runs fully green end-to-end on `confidential-bm` against c8s
`cd361b4`: boot a measured RKE2-node-as-CVM on real SEV-SNP → assert genuine
`sev-snp-guest` + IGVM → install that exact c8s commit **in-cluster** (rke2
helm-controller, OCI chart `charts/c8s:0.1.0-gcd361b4`) → **CDS reaches
`1/1 Running` = attested** (the node self-attests a genuine SNP quote for its
RA-TLS serving cert) → teardown. This is Phase 1 of the north star, proven.

**What made it green (the load-bearing fixes, so they're not relitigated):**
- **In-cluster via console driver** (not external apiserver — CIDR collision):
  deliver ONE driver script over the serial console, it does install+wait+report,
  runner polls `guest-console-log` for `@@markers@@`. Console = bootstrap only.
- **Canonical c8s values** (from docs, not guessed — matches c8s-fleet
  c8s-integration): `cds.node.selector: null` + `tolerations: null` (THE
  single-node CDS-Pending fix — chart default pins `role=cds`); pre-create +
  label `c8s-system` with `pod-security.kubernetes.io/enforce=privileged` (helm
  `createNamespace` can't label → attestation-api privileged pod PSA-rejected →
  whole CDS chain stalls); `cds.measurements: []` for first-green (empty =
  accept-any-attested; a mismatched golden makes peers reject CDS — pin the
  golden only AFTER green); `cds.ratlsPlatform: sev-snp`;
  `attestationApi.cvmMode: node` + `teeDevices.sevGuest: true`; ratlsMesh +
  nriImagePolicy DISABLED (matches c8s-integration; mesh needs kernel netfilter
  modules the monolithic guest lacks — a base-images ask).
- **Canonical install method**: docs say the blessed path is the `c8s install`
  CLI (or `c8s render-values` → Flux HelmRelease). We can't run `c8s install`
  from the runner (needs apiserver reach). We hand-mirror its values via the
  helm-controller HelmChart. TODO to be MORE canonical: `c8s render-values
  --cvm-mode node --hardware-platform sev-snp --single-node --resolve-digests`
  on the runner → feed into valuesContent (pins per-component digests).

**Harness gotchas that cost the most runs (all mine, not the confidential stack):**
- GHA default `bash -e` + `pipefail`: a no-match `grep` in a best-effort loop
  silently kills the step. Use `set +e +o pipefail` in polling steps.
- `nohup driver >/dev/ttyS0` swallows output to nohup.out — launch detached with
  `(setsid ... >/dev/ttyS0 2>&1 &)`.
- Markers in ECHOED commands false-match your own grep (the typed command text
  contains e.g. `echo @@DECODEOK@@`). Build success markers from a runtime var
  so the literal never appears in the command. Bit both progress- and
  delivery-verification.
- Chunked base64 delivery over console: `while read` DROPS `fold`'s final
  newline-less chunk → every delivery truncates identically (unclosed `for` →
  syntax error). Use `while read -r c || [ -n "$c" ]`, and verify byte-count +
  `bash -n` with retry.
- CDS readiness: detect by pod name + `1/1 Running`, not `-l
  app.kubernetes.io/name=cds` (wrong label → false `ready=none`).

**Next:** (1) pin the golden measurement (`cds.measurements: [<golden>]`) now
that it's green, to ENFORCE launch-digest, not just accept-any. (2) prove
consumption end-to-end (schedule a cw workload, assert it runs) per the NVIDIA
lesson. (3) wire the merge trigger in the ORG c8s repo (blocked on the Ameen
GitHub App credential) — the actual "merge → integration → signal" unlock.
Then TDX-metal (Phase 3), cloud (Phase 4).

## Lessons from NVIDIA/k8s-test-infra + NVIDIA/aicr (2026-07-15)

Deep-read of NVIDIA's (non-confidential) ephemeral-GPU-test-cluster infra. They
solved the same shape we have — hardware-dependent e2e on cloud+metal — so the
transfer is high. Key takeaways:

**They validate our choices:**
- **Serial console is the industry norm, not a hack.** holodeck reaches
  non-routable nodes over an out-of-band channel (`SSMTransport` →
  `aws ssm start-session … AWS-StartPortForwardingSession`); k8s-test-infra does
  ALL node ops via `docker exec <node>`, never the pod network. Out-of-band node
  access is standard.
- **Bare-metal-first with a pre-booted CVM = holodeck's `provider=ssh` "BYO host"**
  (skips infra Create) — confirms the metal-SNP lane needs only a provisioner
  driving the existing CVM, the least-effort green gate.
- **Bash-over-ginkgo:** k8s-test-infra has NO ginkgo suite (grep RunSpecs empty);
  e2e is `set -euo pipefail` `validate-*.sh` scripts. A ginkgo `rest.Config` would
  reintroduce apiserver-reachability. YAGNI validated.
- **Simulation is why THEIR problem is easy:** KWOK fake nodes, mock-NVML
  `LD_PRELOAD`, kind-in-Docker colocation. A simulated node has no SNP measurement
  — confirms [[confidential-only-no-simulation]] is why ours is genuinely harder.

**Adopt (ranked):**
1. **In-cluster Job dispatch for the e2e/conformance suite** (aicr
   `validators/runner.go`, results back as CTRF JSON via ConfigMap). The runner
   creates ONE Job and reads ONE result — never routes into the guest pod
   network. Collapses our dozens of slow console polls into: console-apply a Job,
   console-read a result ConfigMap. **This is the fix for our console-polling
   slowness** — shrink the console to bootstrap + attestation + kick-off + read.
2. **Guaranteed teardown = if:always() cleanup + reap-BEFORE-provision** (holodeck
   post-entrypoint; aicr `delete-stale-*` pre-step). Plus a **label-keyed reaper
   gated on LIVE GitHub job status**: read the RunId label off a leaked VMI, GET
   `actions/runs/{id}/jobs`, reap only when all jobs `completed` (404 = safe).
3. **Collision-free naming + run-metadata labels** on every VMI/namespace (RunId,
   SHA, Actor, RunAttempt) so concurrent matrix cells don't collide and the reaper
   attributes each unit to one run.
4. **Prove consumption end-to-end**, not just registration: don't stop at "CDS
   attested" — schedule a workload that exercises the confidential path and assert
   it Runs, fail-closed. (k8s-test-infra schedules a Pod that actually claims the
   device.)
5. **Single declarative Environment/Holodeck CR** for the matrix (provider enum +
   topology + component list) invoked once per cell via `workflow_call`, facts
   discovered from spec files (yq), `fail-fast:false`. Add `provider:
   metal-snp|metal-tdx|gke-snp|gke-tdx` + a `confidential` block (measurements, CC
   mode). Wire only metal-SNP now.
6. **Diff-aware-on-PR + full-on-merge** trigger tiers (dorny/paths-filter); our
   matrix is far under GitHub's 256-cell cap so SKIP aicr's shard machinery.
7. **public-repo + self-hosted safely:** `ok-to-test` approval → push-mirror to a
   trusted `pull-request/<n>` branch (NVIDIA copy-pr-bot) so fork code never runs
   on confidential runners with attestation secrets. Pin every action by SHA.

**The differentiator (our biggest strategic transfer):** aicr's evidence bundle
(in-toto + cosign/Rekor, ADR-007) is **signer-identity-bound, NOT cluster-
physicality-bound** — they openly concede "a contributor can lie to the snapshot
collectors" and defer hardware provenance (`ccManager.enabled:false`). **Binding
the CVM's SNP launch measurement / TDX MRTD into the evidence predicate is exactly
the physicality proof they lack.** That's our moat, not a copy.

**Alternative to the console for routable lanes (noted):** holodeck avoids
host/guest CIDR collisions by owning both nets and fixing disjoint ranges. For us
that would mean **re-CIDRing the guest rke2 podCIDR off 10.42/16** to regain
DIRECT apiserver reachability — cheaper than the console. BUT the guest is a
verity-MEASURED image with baked rke2 config, so this is a **base-images ask** (a
CVM image variant with a non-colliding CIDR), not something we can override at
boot. Worth raising with the base-image owners; until then, serial console.

**SKIP:** all simulation lanes (KWOK/mock-NVML/kind-colocation); holodeck's
AWS/vSphere provider code (single-cloud, no CC); full CNCF conformance dashboards
before the metal-SNP happy path is green; aicr's 256-cap shard machinery.

## Phase 1 build log (2026-07-15) — what's PROVEN, the wall, the pivot

Building `e2e-c8s-snp.yml` (SNP-metal lane) end-to-end on `confidential-bm`, run
against c8s `cd361b4`. Hard-won findings (16 live runs), so they're not redone:

**PROVEN GREEN (the confidential-computing core):**
- Boot a fresh **measured RKE2-node-as-CVM** from the `rke2` image
  (`ghcr.io/confidential-dot-ai/rke2@sha256:79d4…`, shared rootdisk PVC, no clone).
  qemu asserts `sev-snp-guest` + `igvm-cfg …rke2.igvm`; staged IGVM sha matches
  the image's `manifest.json` (`f13625ba…`). Golden smp4 launch digest
  `131b1a32…c55e8c` (from `manifest.json` `measurement.snp_launch_digest`).
- **In-guest rke2 fully comes up**: node `Ready`, apiserver + certs, `rke2.yaml`
  written. Boot to autologin shell ≈ **180s** — boot BLOCKS on
  `systemd-networkd-wait-online.service` (FAILs then releases; ~3 min tax every
  boot — worth flagging to base-image owners).
- **Kubeconfig exfil over the serial console** (the "flakiest link"), now solid:
  - The autologin **root shell is on ttyS0** (not hvc0 — the `console=hvc0` in the
    measured cmdline is a phantom device this qemu doesn't expose; only isa-serial
    `serial0`→`charserial0` exists, which is exactly what `virtctl console` attaches to).
  - **`expect` drives `virtctl console`** (a piped `script` does NOT forward
    keystrokes over the apiserver-proxied console — real pty required).
  - **Decouple send from read**: type the dump command via console, read the
    payload back from the **`guest-console-log` sidecar** (`virtctl console`
    doesn't replay history). `printf MARK; base64 -w0 rke2.yaml; echo MARK`.
  - GHA's default `bash -e`+`pipefail` silently kills best-effort loops
    (`LOG=$(kubectl logs…)` inherits a transient nonzero) — `set +e +o pipefail`.

**THE WALL — reaching the guest apiserver from the runner is a CIDR collision.**
The host cluster's Cilium pod CIDR is `10.42.0.0/16` AND the in-CVM rke2 uses
`10.42.0.0/16` too; under KubeVirt **bridge** networking (forced — masquerade is
broken under SNP) the guest's node IP == the virt-launcher pod IP, inside that
overlapping range. So routing to `<cvm>:6443` is **nondeterministic**: run 13
reached it (`HTTP 401`), runs 14/16 blackholed (`i/o timeout`). It's not the
runner's egress policy — **virt-handler itself** fails:
`dialing VM: dial tcp 10.42.0.76:6443: connect: connection timed out`. Neither
CIDR is changeable (guest is a verity-measured image; host is the whole cluster).
`virtctl port-forward` doesn't save us — it dials the same colliding IP host-side.

**THE PIVOT — install + test IN-CLUSTER, matching the team's real pattern.**
c8s-fleet proves the canonical path: **c8s is installed by Flux running INSIDE the
cluster** (`clusters/c8s-integration/flux-system`, `base/components/c8s-helmrelease-defaults`
HelmRelease) and the e2e suite is **in-cluster** (`base/tests/{attestation-core,
nri-enforcement,tls-lb-health,full-stack}`). Nobody reaches a CVM apiserver from
outside. So the runner should NOT exfil a kubeconfig and helm-install remotely
(my original design — it both fights the collision and diverges from prod).
Instead: the runner drives everything **through the serial console** (100%
reliable), running in-guest `kubectl`/helm-controller against the guest's LOCAL
apiserver (no network hop, no collision). Options, best first:
1. **rke2 helm-controller `HelmChart` CR** (in-guest `kubectl apply` of a small
   manifest) referencing the OCI `charts/c8s` chart + pinned image values +
   ghcr pull secret. rke2's built-in helm-controller installs it. No c8s CLI, no
   external apiserver access. (`charts/c8s` exists as an OCI package; discover its
   semver tag.)
2. **Flux bootstrap** in the guest pointed at c8s-fleet pinned to the commit —
   heaviest, closest to prod.
3. Vendor `test/e2e/*.sh` (they're `kubectl`-only) + run them in-guest via console.
`c8s cds verify` needs the c8s CLI; substitute in-guest `attestation-cli` against
the CDS NodePort, or skip until the CLI is in-guest.

Kernel caveat still stands: `ratlsMesh` stays disabled until base-images adds
`CONFIG_NETFILTER_XT_SET`+`CONFIG_NETFILTER_XT_MATCH_OWNER` (monolithic kernel).

Artifacts so far: `c8s-e2e/e2e-c8s-snp.yml` (external-path build, to be reworked
in-cluster), `c8s-e2e/cluster-prep/` (rke2 rootdisk import + IGVM stage + refs CM
+ RBAC/egress — still valid), `baremetal/kubevirt-rbac.yaml` (+console/portforward).

## Grounded roadmap (2026-07-14 — full-org sweep)

> Source: a 6-area deep-read of the now-accessible confidential-dot-ai org (c8s +
> docs, c8s-charts/operator/fleet, confidential-metal@main incl. the new TDX
> support, steep/igvm-tools, attestation-rs/-go/-service, org CI census).
> Supersedes the guesses below where they conflict.

**Headline:** the org is ~1–2 weeks of glue from the first fully automated lane
(post-merge SNP-metal e2e on c8s main) and ~a quarter from the full 5-platform
matrix. Every ingredient exists; **no repo has any hardware e2e workflow today**,
so the only net-new artifact is the orchestrating workflow itself.

**The single most load-bearing fact:** the PUBLIC `c8s` repo *already* runs jobs
on a self-hosted SEV-SNP runner (`the-machine`, `kata-guest-base.yml`) via
`workflow_run` chained off `Docker`, gated to `main`, never `pull_request`. That
(a) defuses our #1 "public repos can't use self-hosted runners" gotcha (there IS
an approved pattern in the org), and (b) is the exact trigger shape the e2e
workflow should copy verbatim with `runs-on: confidential-bm`
(`kata-guest-base.yml` L47–126: `workflow_run` → gate `head_branch==main` →
checkout `head_sha` → resolve `:<short-sha>` images).

**What c8s actually is (corrects the scoping below):** a Go monorepo — CLI/operator,
CDS (verifies SNP/TDX attestation, signs workload certs from an in-TEE mesh CA),
RA-TLS L4 mesh, digest-allowlist enforcement, measured kata guest image. It has
**zero cluster-provisioning code**: `c8s install` (helm of the chart *embedded in
the checkout* at `internal/helmchart/c8s`) onto an existing k8s/RKE2 ≥1.30
cluster, one TEE per cluster via `--hardware-platform sev-snp|tdx`, shape via
`--cvm-mode baremetal|node|gke|aks`, optional `--kata`. Per-commit
`:<short-sha>` component images exist for every main commit (`docker.yml` +
retag-unchanged) → `c8s install --image-tag <short-sha>` deploys the exact
commit under test with no chart-publish dependency.

**Platform matrix (exists → gap):**

| Lane | Exists today | Gap |
|---|---|---|
| **SNP-metal** | ~90%: our green confidential-bm runners + attested ephemeral SNP CVMs + multi-CVM; **measured RKE2-node CVM image exists** (`ghcr.io/confidential-dot-ai/rke2@79d45313`, standing workload on dev-c8s-integration; readonly rootdisk PVC → N boots, no clone needed); `confai launch/verify/delete` wraps lifecycle + launch-digest | no workflow wires it to c8s pushes; github-runner-dev is stale vs metal main (legacy `lunal.dev/sev-snp` label, no base-image-refs CM → re-provision); serial-console kubeconfig scrape is the flaky link |
| **TDX-metal** | `tdx-dev-host-1` fully provisioned (RKE2 + KubeVirt v1.9 TDVF/QGS, DCAP, TDX rootdisk PVC pre-imported); `confai --platform tdx` launch+verify (MRTD/RTMRs) | no ARC scale set there; pinned attestation-cli v0.4.0 lacks `--expected-mrtd/rtmr*` (release pipeline wedged); no TDX RKE2-node image (all rootdisk/dev-vm plays gated `sev_snp_enabled`) |
| **SNP-cloud (GKE)** | proven once by us (torn down); **c8s-fleet has ephemeral-cluster automation** (`PROVIDER=gke make provision` → `test-gke-<id>`, pick-region by quota, `make teardown AUTO_CONFIRM=1`) | wire provision→install→e2e→teardown into a nightly; secrets bootstrap (GCP SA, fleet SOPS age key, ghcr-secret); quota/latency → nightly not per-push |
| **TDX-cloud** | software-ready only (chart + CLI + attestation-rs main verify gcp-tdx) | no TDX provisioning config exists anywhere; AKS path refuses tdx; quota unknown — weakest leg |
| **GPU-TDX** | `b200-dev-1` (8× B200, vfio, `confai launch --gpu-model B200`, CC-mode tooling; attestation-rs#54 is the explicit ask) | tailnet-only, hand-built PCCS not ansible-ized, no runner — do last |

**Phases (leverage-ordered):**
1. **Post-merge SNP-metal e2e chained off c8s `Docker`** (~1–2 wks): re-provision
   the runner host (fixes label + publishes base-image-refs + import rke2 rootdisk
   instance) → `e2e-snp-metal.yml` copying the `the-machine` trigger pattern →
   boot 1 RKE2-node CVM, `confai verify --platform snp` (enforces launch digest —
   closes attest Phase 1b), scrape kubeconfig → `c8s install --single-node
   --cvm-mode node --hardware-platform sev-snp --image-tag <sha>` → run
   `test/e2e/cw-label-policy.sh`, `mesh-cw-enforcement.sh`, `c8s cds verify`,
   nginx-confidential smoke → `confai delete` in `if: always()`.
2. **Two-CVM CDS CA-handoff e2e** (~1 wk, parallel): c8s `docs/GAPS.md` literally
   says this test "needs multi-node confidential infrastructure in CI" — our green
   multi-CVM job is that primitive; team is on `feat/ca-handoff-probe` right now.
3. **TDX-metal lane on tdx-dev-host-1** (2–4 wks; VM-level TDX e2e ~1 wk): second
   scale set (`confidential-bm-tdx`), unwedge attestation-cli release, VM-level
   attest e2e from the pre-imported TDX PVC first; TDX RKE2 image is the long pole.
4. **Resurrect SNP-GKE as nightly** (1–2 wks, parallel): c8s-fleet provision →
   `c8s install --cvm-mode gke` → e2e → teardown + orphan-reaper.
5. **TDX-cloud** (~1 wk *if* quota): delta on Phase 4 (`confidential_node_type:
   tdx` + c3-* machine types).
6. **Kata pod-as-CVM + GPU-TDX** (last): kata e2e can't nest in a KubeVirt CVM →
   needs dev-c8s-integration time-share or dedicated host; GPU lane closes
   attestation-rs#54.

**Quick wins available now:** enforce launch_digest in the existing green attest
job (steep public → `igvm-tools measure`, or just `confai verify`); re-provision
github-runner-dev (`make provision TAGS=kubevirt,base-image-rootdisk
LIMIT=sev-snp-gh-runner`); wire c8s's unused `test/integration/run.sh`
(docker-compose, mock CDS — needs no hardware) into c8s `ci.yml`; one-PR
attestation-rs version bump to unwedge the release that carries the
`--expected-*` flags; one-line steep `base.yml` fix (pushes the wrong output dir,
so `steep:base` is missing the golden measurements its README promises).

**Top risks:** serial-console kubeconfig scrape (flakiest link); artifact skew
across three pinned supply chains (rke2 image STEEP_REF-pinned + manual; kata
guest bakes per-commit digests; base-cpu-image has no publishing workflow); AMD
KDS fragility (no CRL/backoff in CLI; durable fix = `snphost import` on hosts so
evidence carries VCEK inline — unverified); TDX verify hard-fails on any Intel
PCS outage; keep the `main`-only/never-PR runner posture (fork gating unsolved);
shared substrates (dev-c8s-integration, the-machine) need scheduling/locking;
go module path still `…/bare-metal-infra-management` (import via old path).

**Questions only the team can answer:** what IS the weekly manual checklist
(codify that, not a guess); how is `the-machine` registered (repo-level runner on
public c8s vs an org group allowing public repos — decides Phase 1's trigger
home); can hosts `snphost import` VCEKs; is post-merge-on-main an acceptable
regression gate vs wanting PR-triggered e2e; kata e2e substrate
(dev-c8s-integration time-share vs dedicated); will steep ship igvm-tools in its
release assets + attestation-rs unwedge its release; TDX cloud quota reality;
does the blackwell SNP+GPU host still exist or is b200 the only GPU lane.

---

## Original scoping (2026-06) — kept for the kata-phase detail

> **SUPERSEDED-IN-PART by [`../conformance/DESIGN.md`](../conformance/DESIGN.md).**
> The approach is now: prove the host we have today (`sev-snp-gh-runner`) can test
> all of c8s **via KubeVirt SNP VMs, deferring kata to the very last test.** c8s has
> two deployment shapes — **node-as-CVM** (the node is a confidential VM; runc pods;
> host-side `nri-image-policy`; **no kata**) and **pod-as-CVM** (kata). We test
> ~all of c8s in node-as-CVM mode on a KubeVirt SNP VM; **kata only covers the final
> per-pod-as-CVM enforcement test.** This dissolves the old blast-radius worry (OQ1)
> for everything but that last step, and removes the dependency on `dev-c8s-integration`.
> The detail below (bring-up, allowlist, mesh) still applies — just read it as
> running on a node-as-CVM KubeVirt node first, kata last.
>
> **Original scoping (kata-first framing) kept for reference:** SCOPING — not built;
> the headline risk was **blast radius** (OQ1) of `c8s install --kata` on the shared
> runner node, and the private-image cred (OQ3).

## Goal / definition of done

A CI test that **installs c8s on a real SEV-SNP cluster and proves the flagship
security property end-to-end, fail-closed**:

1. **Bring-up** — `c8s install --kata` → operator + CDS + attestation-api + webhook,
   plus kata-deploy and the `kata-qemu-snp` RuntimeClass, all Ready.
2. **CDS is a genuine TEE** — `c8s cds verify https://<cds-ip>:8443 --measurements
   <golden>` returns exit `0` (its exit codes are a documented CI contract:
   `0` verified / `2` policy fail / `3` evidence unavailable — `operator.md`).
3. **Digest allowlist (the marquee)** — an **allowlisted** confidential workload
   runs (boots as `kata-qemu-snp`, attests, gets a leaf cert at `/etc/c8s/certs`);
   a **non-allowlisted** image is **blocked** (in-guest `policy-monitor` SIGKILLs
   the init PID under `--kata`; host-side `nri-image-policy` denies otherwise).
   Assert **both** outcomes.
4. **Teardown** — `c8s uninstall` (sweeps kata host artifacts; refuses while kata
   pods are still scheduled).

One green run = *c8s actually enforces "only allowlisted digests run inside attested
CVMs" on real hardware.*

## Why this is the highest-value c8s CI

- It's the product's **core claim** — the digest-allowlist + attested-runtime story
  the whole stack builds toward (see `research/kettle-orchestrator-c8s.md`).
- **c8s has no hardware e2e today.** Its CI is unit/chart/build only:
  `ci.yml` (`go test` + `helm template`), `chart.yml` / `docker.yml` (publish),
  `kata-guest-base.yml` + `kernel-snapshot.yml` (image builds). Nothing installs
  c8s on a live SNP cluster or exercises enforcement. This fills that gap.

## The flow (sketch)

```
c8s install --kata --image-pull-secret ghcr-secret
    → kata-deploy + RuntimeClasses + operator + CDS(kata-qemu-snp) + webhook + nri/policy-monitor
c8s cds verify https://<cds-ip>:8443 --measurements <cds-golden>        → exit 0 (genuine TEE)

# positive: allowlisted confidential workload
kubectl apply <allowlisted pod, annotated confidential.ai/cw>          → Running; cert in /etc/c8s/certs
# negative: a digest NOT in the allowlist
kubectl apply <non-allowlisted image pod, annotated>                   → killed; assert never Ready

c8s uninstall
```

## Where it runs — **the #1 open question (OQ1)**

`c8s install --kata` is a **cluster-wide platform mutation** (`operator.md`):
- kata-deploy installs QEMU + the kata runtime + `containerd-shim-kata-v2` on
  **every node** and **restarts containerd** (the RKE2 vs k8s config path is
  auto-detected — c8s supports RKE2, which is what we run);
- a `ValidatingAdmissionPolicy` **rejects non-kata workload pods** (system &
  host-namespace pods exempt) and the webhook injects `runtimeClassName`;
- cluster-scoped CRDs / RBAC / webhook / a host-side NRI image policy.

Our bare-metal is a **single node** (`sev-snp-gh-runner`) that **also hosts the ARC
runners** (`arc-runners` ns). Risks: the containerd restart disrupts running pods;
`arc-runners` is **not** a system namespace, so the VAP/webhook may capture the
runner pods; the NRI image policy could gate the runners' own images. → Almost
certainly needs a **dedicated SNP node/cluster** for the c8s e2e, or confirmed
exemptions + a tolerance for runner churn. **Pin this before anything else.**

## Phasing

| Phase | Scope |
|---|---|
| **P1** | Bring-up + `c8s cds verify` (CDS is a genuine TEE running expected code). |
| **P2** | Digest-allowlist enforcement — allowlisted runs, non-allowlisted blocked. The marquee. |
| **P3** | RA-TLS mesh: two confidential workloads, attested mTLS between them (extends `multi-cvm-attest`). |

## Open questions to pin (before building)

1. **Blast radius / cluster (OQ1, the big one).** Dedicated SNP node/cluster vs the
   shared runner node. See above. Likely needs a second SNP node or an ephemeral
   kata-capable cluster; on a single shared node the install will probably disturb
   the runners.
2. **kata-qemu-snp actually works via `c8s install --kata` on our EPYC/RKE2 node.**
   `pitfalls.md`: the kata-image-puller reconcile loop must hold
   `experimental_force_guest_pull` or sandboxes die with `rootfs ENOENT`; host-side
   image pull is still needed (no nydus-snapshotter). Validate a `kata-qemu-snp` pod
   boots after install.
3. **Private-image credential (OQ3).** c8s images are **private** today —
   `cds` / `c8s` / `get-cert` / `kata-guest-base` → `HTTP 403` anon; only
   `attestation-api` is public. Need a GHCR `read:packages` cred wired three ways
   (`--image-pull-secret` for kubelet; `kata.guestImage.pullerAuthSecret` for the
   in-pod `oras pull`; the baked `ghcr-auth.json` via `READ_PRIVATE_GHCR_TOKEN` for
   guest-pull). Same situation `kettle-build` was in before it went public, and
   `pitfalls.md` says to *"remove this once the artifacts go public"* — so this may
   resolve itself. Pin: obtain the cred, or wait for the images to go public.
4. **c8s CLI provenance (OQ4).** No release → build from source
   (`make` / `go build -tags c8s_node ./cmd/c8s`, needs Go). Runner also needs
   `helm`, `kubectl`, and `crane` (for `c8s install`'s default digest resolution).
5. **Allowlist fixtures + assertions (OQ5).** Positive = an allowlisted image;
   negative = a digest not in the allowlist. How the allowlist is seeded (baked
   `bootstrap-allowlist.json` on the dm-verity rootfs + runtime growth via CDS
   `POST /allowlist`, EAR-authorized and gated by `cds.allowlistWriteMeasurements`)
   and how to **observe the deny** (policy-monitor SIGKILLs the init PID in-guest →
   pod never Ready). Pin the exact images + `kubectl wait`/phase/event assertions.
6. **CDS golden measurement (OQ6)** for `c8s cds verify --measurements`. The
   kata-guest-base launch digest (via `sev-snp-measure`, per `operator.md`) — same
   measurement story as kettle P2. Pin where it comes from (published vs computed).

## What's already determined

- **c8s supports RKE2** (our cluster) — operator auto-detects the containerd path.
- **`c8s cds verify`** gives a clean CI assertion (exit `0/2/3`, JSON output).
- **`c8s uninstall`** handles teardown (sweeps kata artifacts; refuses while kata
  pods are scheduled → delete workloads first or `--force`).
- **Two enforcement flavors:** `--kata` (in-guest `policy-monitor`, the real
  confidential story) vs plain install (host-side `nri-image-policy`). The real
  test is `--kata`; cds also **can't reach Ready without `--kata`** (needs
  `/dev/sev-guest`, only inside an SNP guest — `pitfalls.md`).
- **No c8s release** → build the CLI from source.
- **No hardware e2e exists in c8s today** → this is net-new coverage.

## If/when it lands
Like kettle's, the e2e is a **client of a confidential platform** but here it also
*installs* that platform, so it must run on (or against) a real SNP cluster — it
can't be a stock `ubuntu-latest` job. Natural home once proven: a workflow in
`confidential-dot-ai/c8s` (gated to a self-hosted SNP runner) + a mirror here.
