# Multi-backend confidential matrix

Run the same CI steps across every confidential backend in one workflow:

| Backend label | Platform | Confidential mechanism | Status |
|---|---|---|---|
| `confidential-gcp` | Confidential GKE (GCP) | SEV-SNP/TDX confidential nodes | ✅ live (cifrai, GKE arc-host) |
| `confidential-bm` | bare-metal RKE2 (`sev-snp-gh-runner`) | SEV-SNP KubeVirt VM (IGVM) | ✅ live (cifrai) |
| `confidential-azure` | Azure | SEV-SNP Azure CVM / AKS confidential nodes | ⏳ runner not deployed yet |

The workflow is [`workflows/confidential-matrix.yml`](workflows/confidential-matrix.yml).
Proven green on `confidential-gcp` + `confidential-bm` simultaneously.

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
