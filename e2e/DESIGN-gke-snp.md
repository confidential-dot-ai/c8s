# gke-snp lane — design (build deferred until triggers+consumers land)

> Status: DESIGN-ONLY (2026-07-15 decision). Covers the rent-infra customer
> class (Baseten/Modal/RunPod): SEV-SNP Confidential GKE. Build after Phase 0–2.

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
