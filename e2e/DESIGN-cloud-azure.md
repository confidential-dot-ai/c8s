# cloud lane — design (REFRAMED 2026-07-16: Azure-first; GKE demoted, possibly dropped)

> **✅ LANE GREEN (2026-07-16, run 29544550923, 4 iterations).** Every layer
> asserted: quota-aware region pick (northeurope) → ephemeral AKS (DC4as_v5
> SEV-SNP pool) → CLI-from-source `c8s install --single-node --cvm-mode aks
> --operator-keys <per-run>` → 6/6 components with **ratls-mesh + NRI live
> (first lane to test either)** → vTPM `/attest` 200 (7802B evidence) →
> `cds verify` verified + UNSAFE-unpinned warning pinned → allowlist CRUD via
> per-run operator key → consumption proof over the INJECTED image set
> (get-cert/cert-wait must be allowlisted too — found live) → **NEGATIVE:
> non-allowlisted image denied at container-create** ("image not in allowlist",
> NRI fail-closed — first enforcement assertion in the org) → teardown + reaper.
> Iteration lessons in git log: vm-size digit parse; helm's baked 5-min --wait
> vs single-node convergence (explicit gate now); webhook-injected images need
> allowlisting (docs' "and any init containers" is load-bearing).
> Nightly 09:47 UTC. Follow-ups: az_snp_live nextest pod, TCB floors,
> DC2as_v5 cost trial.


> Status: DESIGN-ONLY. **Maintainer guidance (2026-07-16 call): the cloud cell
> is TDX + AZURE, not GKE-SNP** — there's little GCP hardware (Ameen). Whether
> GCP remains a cell at all is an open question. Everything structural below
> (sibling reusable workflow, nodes-are-the-CVMs, policy-only golden,
> always-teardown + reaper) transfers to AKS unchanged; swap gcloud for
> c8s-fleet's `aks_provisioner` role (`az aks create`, SEV-SNP
> `Standard_DC4as_v5` pools; TDX via DCes_v5; confidential-aks-dev cluster
> exists). Azure also carries UNIQUE test coverage: attestation-rs's
> `az_snp_live`/`az_tdx_live` (vTPM+IMDS) run nowhere else.
> **Second maintainer directive: lift the c8s-fleet Flux/`make promote` flow
> into CI-on-merge — do NOT invent a separate cloud install path.**
> Build after tdx-metal (which jumped the queue). **STARTED 2026-07-16 while
> waiting on TDX host/image + PR reviews.**

## Docs-sweep addendum (2026-07-16) — build against THESE, not flagship values

- Blessed install: `c8s install --single-node --cvm-mode aks --operator-keys
  operator.pub`. aks mode = **vTPM `/dev/tpm0`** (attestation-api mounts it;
  NOT teeDevices.sevGuest — do not copy flagship values). `--hardware-platform`
  ignored under aks; **aks+tdx REFUSED** → az_tdx_live becomes a standalone
  DCesv5-CVM mini-lane outside c8s (c8s TDX-on-Azure "in progress").
- **ratlsMesh + nriImagePolicy stay ON** (AKS Ubuntu nodes support both) — the
  Azure lane is the first to test mesh + enforcement surfaces at all.
- **Per-run operator EC keypair** (P-256, openssl one-liners): write tokens
  have no cluster binding — a shared key across ephemeral clusters = 5-minute
  cross-cluster token replay.
- Sizes: DC2as_v5 (smoke, cheap) / DC4as_v5 (dev). Preflight `az vm list-skus
  -l <region> --size Standard_DC`; fallback branch: system pool may refuse CVM
  sizes → user pool + label/taint + drop `--single-node`.
- Bare-evidence verification on DCasv5 pins `generation: milan`.
- Fetch /docs/c8s/tutorials/azure-e2e when building — it is the lane's script.
- Docs claim private component images + PAT scopes; we verified the chain
  anonymous-public — re-verify at build, prefer zero-cred.
- Policy-only golden = the documented UNSAFE posture for cds.measurements —
  assert the UNSAFE warning string deliberately + use TCB floors
  (`--min-tcb-*`) as the cloud-viable enforcement knob.

## Azure lane — concrete shape (from c8s-fleet recon, 2026-07-16)

**Verified from the fleet repo (access granted — admin):**
- **Ephemeral AKS is first-class**: `scripts/run-playbook.sh` — `PROVIDER=aks
  ENV=dev make provision` with no CLUSTER mints `test-aks-<hex>` (ad-hoc stub
  inventory, inherits group_vars), region auto-picked by `pick-region.sh` for
  SEV-SNP SKU + `standardDCASv5Family` quota; ~15–30 min up (async nodepools);
  teardown = `az group delete --no-wait`. Node sizes: `Standard_DC4as_v5` /
  `DC48as_v5` (SEV-SNP).
- **confidential-aks-dev is PRODUCTION-FACING — never a CI target** (public
  domains incl. c8s-aks.confidential.ai, prod Let's Encrypt, reserved PIP,
  fail-closed NRI). Ephemeral-only for CI.
- **Auth is the ONLY hard blocker**: the fleet runs on interactive `az login`;
  no SP, no OIDC federation, no azure/login usage anywhere. CI needs a
  net-new Entra app with a GitHub-OIDC federated credential (subscription
  d0d3b235-667c-42e0-9f9a-e8bda5598f6b — the org sub per the cert-manager SP),
  role: enough to create/delete resource groups + AKS + read quotas
  (Contributor on the sub, or a dedicated CI subscription). ASK: Ameen.
- **Promote-lift boundary (respect it)**: `promote-c8s.sh` deliberately aborts
  in CI for fail-closed component-digest bumps (needs the operator SOPS key +
  kubeconfig — kept out of CI by design), and the promote PR is human-merged.
  So: our lane = ephemeral validate-then-die (needs none of that);
  CD-to-standing-clusters stays a fleet-owner decision. Also: no deployment
  verification exists in fleet CI today (only render validation; landing is
  verified by in-cluster Flux `tests` Kustomization healthChecks) — our lane
  IS that missing verification, on a throwaway cluster.
- **AKS evidence path = vTPM** (`attestationApi.cvmMode: aks`,
  `teeDevices.tpm: true`, `/dev/tpm0`) — same path `az_snp_live` needs
  (vTPM + IMDS). One cluster serves both payloads.

**azure-e2e.yml (sibling reusable workflow, same contract as cvm-e2e):**
1. `provision`: azure/login (OIDC) → fleet's `make provision PROVIDER=aks`
   (checkout c8s-fleet; needs quota-read for pick-region) → kubeconfig via
   `az aks get-credentials`.
2. `install+verify c8s bundle at the sha`: apiserver directly reachable (no
   console!) — `c8s install --cvm-mode aks --hardware-platform sev-snp` (the
   blessed installer) or helm from the source-packaged chart + ancestry-
   resolved image tags (same bundle logic as e2e-c8s payload); then the
   consumption proof: CDS 1/1 + cw workload cert injected + Running.
   Golden: policy-only (cloud — no measured images; maintainer-confirmed).
3. `az-tests` (Azure's UNIQUE coverage): privileged pod on the cluster runs
   the attestation-rs nextest archive with `--features az-snp,attest` and the
   az_snp_live ignored tests (vTPM /dev/tpmrm0 hostPath + tpm2-tools + IMDS
   from pod network). Plain kubectl exec/logs — no console machinery at all.
   (az_tdx_live needs DCes_v5/TDX pools — later cell.)
4. `teardown` `if: always()`: `az group delete` + a reaper for leaked
   `test-aks-*` groups older than N hours (tag groups with run-id at create).

Triggers: dispatch + nightly first (quota + 30-min provision cost); merge-lane
via workflow_call once green, mirroring the metal precedent.

## The one structural decision

**This is NOT a primitive cell.** The bare-metal primitive's mechanics —
KubeVirt boot, serial-console delivery, guest-console-log polling — don't exist
on GKE: the **nodes themselves are the CVMs** and the apiserver is directly
reachable from the runner. Forcing it through `cvm-e2e.yml` would mean stubbing
out most of the file per-platform. Instead: a sibling reusable workflow
`gke-e2e.yml` with the same CONTRACT (payload in, measurement/proof out, teardown
always) and a different transport (kubectl straight to the ephemeral cluster).

Consumers still see one shape: add a matrix row, point at the right reusable
workflow. `e2e-c8s.yml`'s matrix comment already reserves the row.

## Shape (Model B — ephemeral cluster per run, proven once 2026-06-25)

1. **Provision**: either the proven-lean `e2e/provision-gcp.sh`
   (`gcloud container clusters create conf-e2e-$RUN_ID --enable-confidential-nodes
   --confidential-node-type sev_snp`, project `conf-500518`, n2d machines) or
   c8s-fleet's `make provision PROVIDER=gke CLUSTER=test-gke-<id>` (Ansible role
   `gke_provisioner` — heavier, but the fleet team maintains it). Start with
   provision-gcp.sh; converge on the fleet seam when it grows a non-interactive
   mode.
   - Known operational gotchas (from the 2026-06 runs, e2e/README.md): SEV-SNP
     N2D zone stockouts are NORMAL — retry across zones, fall back to
     `CONF_TYPE=sev`; a mid-create cluster can't be deleted (wait, then delete);
     kubectl needs `gke-gcloud-auth-plugin`.
2. **Install + prove**: from the runner (no console!):
   `c8s install --cvm-mode gke --hardware-platform sev-snp --image-tag <short>`
   then the SAME workload-cert proof as the flagship payload (cw sample deploy →
   cert injected → Running).
3. **Teardown** `if: always()` + a label-based reaper (GKE cluster labels
   `ci-run=<run_id>`; reap clusters whose run is completed — mirror of the
   primitive's reap-before-provision, because a killed runner leaks a BILLED
   cluster here, not just a CVM).

## Auth: WIF, no long-lived keys

`host/wire-wif.sh` pattern from the cifrai era: GitHub OIDC → Workload Identity
Federation → GCP SA with `roles/container.admin`. Secrets in the repo: none;
just the WIF provider + SA email as vars.

## Verification depth (honest about what this lane can claim)

- The GCP-managed node launch measurement is NOT ours to pin — golden-based
  appraisal is impossible. This lane's claim is **policy-based**: node is a
  genuine Confidential VM (valid SNP report/VCEK chain, debug off, TCB floor)
  + c8s's own CDS attestation path works on GKE.
- The 2026-06 lane only asserted `confidentialNodes.enabled` (platform
  assertion). The rebuild must do better: run the c8s install and require a
  CDS-issued workload cert — that exercises the real attestation path
  (attestation-api → CDS verify) even without a golden pin.

## Trigger + cost

Nightly + dispatch ONLY (cluster create ≈ 8–15 min, billed; quota is shared).
NOT per-merge — the metal lane is the per-merge gate; this lane catches
GKE-specific drift.

## gke-tdx (notes, further out)

`provision-gcp.sh` already parameterizes `CONF_TYPE=tdx` (needs `--machine-type
c3-*`, GKE ≥ 1.32.2). Quota for C3+TDX unverified. attestation-rs supports
`gcp_tdx` verify. Do after gke-snp is green; same file, one env var.
