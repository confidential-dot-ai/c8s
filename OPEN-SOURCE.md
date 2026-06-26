# Open-source repos & self-hosted confidential runners

> Short answer: **forks/strangers already can't trigger your self-hosted runners
> — that's GitHub's default, and you should keep it that way.** The work is in
> deciding *how* OSS contributors' PRs get validated, not in blocking them.

## The risk you're protecting against

A self-hosted runner executes the workflow's code. On a **public** repo, anyone
can open a PR from a fork. If a fork PR could run on your runner, an attacker's
job would execute **inside your confidential infra** with whatever that runner
can reach — Workload Identity → GCP, the ability to spin up Confidential GKE,
the kettle/ccvm toolchain, any cached creds. That's the worst-case for a TEE CI
fabric. So untrusted code must never land on these runners.

## What GitHub already does for you

GitHub **blocks self-hosted runners on public repositories by default.** Concretely:

- A runner group has `allows_public_repositories: false` by default. A **public**
  repo's jobs are simply never dispatched to the group (`assigned job=0`). This is
  exactly the symptom we hit — and for an OSS repo it's the *correct* behavior.
- Even where self-hosted is allowed, **fork PRs require approval** to run any
  workflow (Settings → Actions → "Require approval for all outside collaborators",
  or stricter "Require approval for all external contributors").
- `secrets` and `id-token` (the WIF/OIDC token) are **not exposed to
  `pull_request` runs from forks**.

So the default posture for a public OSS repo is: self-hosted is off, fork code
can't touch your infra. Don't flip `allows_public_repositories` on a runner group
that backs confidential runners.

## How to actually run CI on your OSS repos

Pick based on what each job needs:

### 1. Public checks → GitHub-hosted, for everyone (incl. forks)
`check`, `test`, `clippy`, hosted `release-build` (arm/macOS), `docker-build` — none
need a TEE. Keep these on GitHub-hosted runners so every contributor's PR is
validated, with zero exposure of your infra. This is most of the matrix
(`RUNNER-MATRIX.md`).

### 2. Confidential jobs → only on *trusted* triggers, from a *private* context
The jobs that genuinely need a TEE (the confidential E2E: spin up a Confidential
GKE cluster, attest it, test it) should never run on untrusted PRs. Two patterns:

- **(Recommended) Private CI repo / post-merge.** Run the confidential E2E from a
  **private** repo on `push` to a protected branch — i.e. *after* code review and
  merge, on code you trust. This is what `cifrai/attestation-rs-ci` (private) does
  today. The public OSS repo keeps hosted PR checks; a private repo (or a
  protected branch in the same private project) runs the confidential gate.
- **Same repo, gated to non-fork events.** If you must keep one repo, gate the
  self-hosted jobs so forks can't reach them:

  ```yaml
  confidential-e2e:
    runs-on: confidential-e2e
    # push to a branch in THIS repo (post-merge), or a same-repo PR — never a fork
    if: >-
      github.event_name == 'push' ||
      github.event.pull_request.head.repo.full_name == github.repository
    environment: confidential   # add required reviewers for a human gate
  ```

  Note: this still requires the repo to be **private/internal** (a public repo
  won't dispatch self-hosted at all unless you open the runner group to public —
  don't).

### 3. Add a human gate with Environments
Put the confidential job in an `environment:` with **required reviewers**. Even a
trusted push then waits for a click before it runs on the TEE fabric — a cheap,
auditable approval step.

## Defense in depth (assume something slips through)

- **Ephemeral runners** — ARC tears down the pod after each job (already on); no
  state carries between jobs.
- **Least-privilege WIF** — scope the runner's GSA to only what Model B needs;
  prefer short-lived OIDC tokens over any static key (we use WIF, no static keys).
- **Egress NetworkPolicy** — restrict runner-pod egress to GitHub + the GCP APIs
  it needs (deny the rest) so a rogue job can't exfiltrate or call out freely.
- **No long-lived secrets on the runner** — nothing in env/files a job can read.
- **Pin actions by SHA** (the workflow already does) so a compromised tag can't
  inject code.
- **Branch protection + required reviews** so `push` events only carry reviewed code.

## TL;DR decision table

| Repo type | PR checks (lint/test/build) | Confidential E2E (TEE) |
|---|---|---|
| Public OSS | GitHub-hosted (forks OK) | from a **private** repo, on push post-merge (or env-gated) |
| Private/internal | self-hosted confidential, gated to non-fork events | self-hosted confidential, env-gated |

The rule of thumb GitHub itself gives: **only use self-hosted runners with private
repositories.** For OSS, validate contributors on hosted runners and keep the
confidential gate on trusted, reviewed code.
