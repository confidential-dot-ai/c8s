# Security — runner credentials

How the runner registration credential is handled, and how to rotate it.

## Secret model (#2 — secret-by-reference)

The runner's GitHub credential is the most sensitive thing in this stack: with
`admin:org` it can manage org runners; on the runner it can reach the confidential
infra. So:

- **Never inline it into helm values.** The old path (`--set
  githubConfigSecret.github_token=…`) stored the token in the helm *release*
  secret, so `helm get values` printed it in plaintext — that's how it leaked.
- **Write it to a K8s Secret and reference it by name** (`githubConfigSecret:
  runner-github`). `register.sh` does this: `GH_RUNNER_TOKEN` is read from the
  environment, written straight to the Secret, and **never echoed or written to
  disk**. `helm get values` no longer contains it.
- **Use a dedicated credential, not your personal `gh` session.** Prefer a GitHub
  App (improvement #6) or a fine-grained PAT scoped to org *self-hosted runners*
  — not the `gho_…` token from `gh auth login`.

The Secret still lives in etcd (base64). To store it in git for GitOps, **seal**
it — don't commit plaintext:

- **Bare-metal repo already uses SOPS** — encrypt with `sops -e` to a recipient
  in `ansible/.sops.yaml`, decrypt at apply time.
- **Or Sealed Secrets** (per-cluster controller; `kubeseal` produces a
  `SealedSecret` only that cluster can decrypt) — best for multi-cluster GitOps.
- **Or External Secrets** pulling from a vault.

Until one of those is wired, supply the token via `$GH_RUNNER_TOKEN` at apply time
and keep it out of git entirely.

## Rotation (#1 — your GitHub-account action)

> The current `gho_…` token was exposed (stored in helm release values on both
> clusters and printed by `helm get values`). **Rotate it.** Steps:

1. **Mint a fresh, dedicated credential** (not your `gh` OAuth token):
   - GitHub App (preferred): create/install an org App with the runner
     permissions, download the private key. (See improvement #6 / `org-setup.md`.)
   - or a fine-grained PAT scoped to the org's self-hosted runner administration.
2. **Re-register each scale set** with the new credential (re-points the live
   runner to the new secret; brief, runners are ephemeral):
   ```bash
   # bare-metal
   GH_RUNNER_TOKEN='<new>' ORG_URL=https://github.com/cifrai \
     SCALE_SET=cvm-launcher MODE=template SA=bm-e2e \
     KUBECONFIG=~/dev/conf/github-runner.yaml ./register.sh
   # gcp
   GH_RUNNER_TOKEN='<new>' ORG_URL=https://github.com/cifrai \
     SCALE_SET=confidential-gcp SA=arc-e2e \
     RUNNER_IMAGE=us-central1-docker.pkg.dev/conf-500518/confidential-ci/confidential-runner-gcp:v2 \
     KUBE_CONTEXT=gke_conf-500518_us-central1-a_arc-host ./register.sh
   ```
3. **Revoke the old token** in GitHub (Settings → Developer settings, or
   `gh auth refresh` / re-login to rotate the OAuth token), and confirm the old
   value no longer appears: `helm get values <name> -n arc-runners` should show no
   `github_token`.
4. **Sanity-check** a job still dispatches (`gh workflow run smoke --repo
   cifrai/confidential-bm-smoke`).

## Idempotent register / rename (#3)

`register.sh` is safe to re-run. To rename a scale set, set `RENAME_FROM=<old>` —
it does the clean cycle (uninstall old → purge its `autoscalingrunnerset` /
`ephemeralrunnerset` / `autoscalinglistener` → restart the controller → install
new). Skipping that purge is what left the listener crash-looping on a stale
`ephemeralrunnerset` (`… not found`, `assigned job=0`) during the GKE rename.

## Runner blast-radius hardening (#6)

### Egress — done on bare-metal, staged on gcp
CI runners legitimately need broad **internet** egress (crates.io, ghcr, github,
dl.k8s.io, arbitrary deps), so a tight FQDN allowlist would break builds. The
value is cutting **lateral movement**, not internet access.

- **bare-metal (Cilium): applied + verified.** `baremetal/runner-egress.cnp.yaml`
  allows DNS + the kube-apiserver + the public internet, and default-denies
  everything else — so a CI job can fetch deps and (for the E2E) talk to the API
  server, but **cannot reach other in-cluster pods/services, remote nodes, or
  host-local endpoints**. Verified non-breaking: the matrix bm leg (`cargo build`)
  and `snp-e2e` (kubectl path) both stay green under it.
- **gcp: not enforceable as-is.** `arc-host` has no network-policy datapath
  (no Dataplane V2). Enabling it is a cluster change, and gcp is kept as-is — so
  this is staged. The high-value gcp control would be blocking the **metadata
  endpoint** (`169.254.169.254`) from runner pods to stop WIF/credential SSRF;
  apply it when/if Dataplane V2 is enabled.

### WIF least-privilege — staged (needs a Model-B re-test)
The GKE runner SA (`arc-e2e`) holds **`roles/container.admin`** — project-wide
GKE admin (read/write *every* cluster + its workloads). For Model B it only needs
to create/delete *ephemeral* confidential clusters and operate inside them.

Proposed replacement (validate before cutover):
- a **custom role** with `container.clusters.{create,delete,get,list,update}` +
  `container.operations.{get,list}` for the lifecycle, plus
- **`roles/container.developer`** for the in-cluster (kubectl) access the E2E needs
  (a pure cluster-lifecycle role grants `getCredentials` but no RBAC → kubectl
  Forbidden — which is exactly why this must be tested with a real Model-B run, not
  cut over blind), then remove `container.admin`.

Not applied: it touches gcp and a wrong permission set silently breaks Model-B
provisioning (slow/costly to discover). Stage it with a Model-B verification +
rollback to `container.admin`.

### No static secrets on the runner — current state
Jobs get cloud access via short-lived **WIF/OIDC**, never a static key on the
runner. The only credential on the fabric is the **registration** secret (now
by-reference, above) — keep it that way; never add a long-lived cloud key to a
runner image or job env.
