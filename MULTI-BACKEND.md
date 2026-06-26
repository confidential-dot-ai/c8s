# Multi-backend confidential matrix

Run the same CI steps across every confidential backend in one workflow:

| Backend label | Platform | Confidential mechanism | Status |
|---|---|---|---|
| `confidential-gcp` | Confidential GKE (GCP) | SEV-SNP/TDX confidential nodes | ✅ live (cifrai, GKE arc-host) |
| `confidential-bm` | bare-metal RKE2 (`sev-snp-gh-runner`) | SEV-SNP KubeVirt VM (IGVM) | ✅ live (cifrai) |
| `confidential-azure` | Azure | SEV-SNP Azure CVM / AKS confidential nodes | ⏳ runner not deployed yet |

The workflow is [`workflows/confidential-matrix.yml`](workflows/confidential-matrix.yml).
Proven green on `confidential-gcp` + `confidential-bm` simultaneously.

## Use it in your repo

Once the runners are live org-wide, opt your CI into confidential compute one of
three ways. **Prerequisite: the repo must be private/internal** — GitHub won't
dispatch self-hosted runners to public repos (see [`OPEN-SOURCE.md`](OPEN-SOURCE.md)).

### Option 1 — run your whole CI across every confidential backend
Copy [`workflows/confidential-matrix.yml`](workflows/confidential-matrix.yml) into
your repo's `.github/workflows/` and replace the example build step with yours.
Every live backend runs the identical steps in parallel; a new backend (e.g. azure)
starts running automatically once it's added to `CONFIDENTIAL_BACKENDS` — no edit
to your workflow.

### Option 2 — pin a single job to a confidential runner
In any workflow, target a backend by its label:
```yaml
jobs:
  build:
    runs-on: confidential-bm        # or confidential-gcp
    steps:
      - uses: actions/checkout@v4
      - name: build deps (self-hosted, minimal runner image)
        if: runner.environment == 'self-hosted'
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev
      - run: make test
```

### Option 3 — matrix an existing CI across backends
Add a small `set-backends` job that emits the live list, then fan your job over it:
```yaml
jobs:
  set-backends:
    runs-on: ubuntu-latest
    outputs: { list: "${{ steps.s.outputs.list }}" }
    steps:
      - id: s
        run: echo "list=${{ vars.CONFIDENTIAL_BACKENDS || '[\"confidential-gcp\",\"confidential-bm\"]' }}" >> "$GITHUB_OUTPUT"
  ci:
    needs: set-backends
    strategy:
      fail-fast: false
      matrix: { backend: "${{ fromJSON(needs.set-backends.outputs.list) }}" }
    runs-on: ${{ matrix.backend }}
    steps: [ ]   # your steps
```
This is exactly how `cifrai/attestation-rs-ci` runs `check`/`test` on every backend
(see `workflows/confidential-matrix.yml` for the exact `set-backends` job).

### Good to know
- **Which backends run** is the org variable `CONFIDENTIAL_BACKENDS` (default
  `["confidential-gcp","confidential-bm"]`), managed centrally — you don't set it
  unless you want a subset.
- **Runners are minimal + ephemeral** (one fresh pod per job, scale-to-zero).
  Install build deps in-job gated `runner.environment == 'self-hosted'`; on gcp the
  baked image already carries the common toolchain.
- **`runs-on` = the backend label**: `confidential-gcp` = Confidential GKE node,
  `confidential-bm` = bare-metal SEV-SNP KubeVirt host (see the table above).
- Spinning up a confidential *VM/cluster* as the test target (vs running build/test
  *on* the runner) is the per-backend E2E — see `baremetal/snp-e2e.yml` and `e2e/`.

## The pattern

```yaml
strategy:
  fail-fast: false                         # one backend failing ≠ cancel the others
  matrix:
    backend: ${{ fromJSON(needs.set-backends.outputs.list) }}
runs-on: ${{ matrix.backend }}             # the label IS the backend
```

A `set-backends` job emits the list (from a `workflow_dispatch` input, else the
repo variable `CONFIDENTIAL_BACKENDS`, else a default). Every backend runs the
identical steps (deps → toolchain → build/test); the *build/test* steps are
platform-agnostic, so the matrix is the clean place to prove parity. (Platform
*provisioning* differs per backend — Confidential GKE node vs KubeVirt SNP VM vs
Azure CVM — so that stays in each backend's own E2E, not the shared matrix.)

## ⚠️ The one rule: only list backends that have a LIVE runner

A matrix label with no registered runner **hangs queued forever**. Job
`timeout-minutes` does **not** help — it only counts once a job is *running* on a
runner, not while it waits for one. A runnerless leg keeps the whole run
`in_progress` (until GitHub expires the queued job, ~24h). So:

- **Don't** hardcode `[confidential-gcp, confidential-azure, confidential-bm]` in
  the matrix while azure has no runner — the azure leg will hang.
- **Do** drive the list from `CONFIDENTIAL_BACKENDS` (or the dispatch input) and
  add a backend only once its runner is registered:
  ```bash
  # today
  gh variable set CONFIDENTIAL_BACKENDS -b '["confidential-gcp","confidential-bm"]' --repo <org>/<repo>
  # after standing up the Azure runner
  gh variable set CONFIDENTIAL_BACKENDS -b '["confidential-gcp","confidential-azure","confidential-bm"]' --repo <org>/<repo>
  ```

`fail-fast: false` is still worth setting so a backend that *has* a runner but
*fails the build* doesn't cancel the healthy backends.

## Adding `confidential-azure`

1. Stand up an Azure confidential runner: ARC on AKS **confidential nodes**
   (SEV-SNP/TDX node pool), or an Azure **CVM** running the actions-runner.
   Register the scale set to the org with `runnerScaleSetName: confidential-azure`.
   (Same `install-arc*.sh` shape; on AKS there's no Rancher proxy, so a plain
   `helm install` works — see `host/` / `baremetal/install-arc-rancher.sh`.)
2. Add `"confidential-azure"` to `CONFIDENTIAL_BACKENDS`. Done — no workflow edit.

## Naming note

The GKE scale set was renamed `confidential-e2e → confidential-gcp` for a
consistent trio. If you rename an ARC scale set, do a clean cycle: `helm
uninstall`, delete leftover `autoscalingrunnerset`/`ephemeralrunnerset`/
`autoscalinglistener`, restart `arc-gha-rs-controller`, then `helm install` the
new name. Skipping the purge leaves the listener crash-looping on a stale
`ephemeralrunnerset` name (`... not found`) → `assigned job=0`, jobs never dispatch.
