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
     SCALE_SET=confidential-bm MODE=template SA=bm-e2e \
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

## Related hardening (tracked, not yet done)
- #6 PAT → GitHub App (the real fix for "dedicated credential").
- #7 runner egress NetworkPolicy + least-privilege WIF + no long-lived secrets on
  the runner. The credential here is for *registration*; jobs should get cloud
  access via short-lived WIF/OIDC, never a static key on the runner.
