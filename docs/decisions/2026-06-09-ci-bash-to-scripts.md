# 2026-06-09 — Extract CI bash into scripts + a setup-go composite action

## Context

The GitHub Actions workflows (`.github/workflows/`) had grown several blocks of
non-trivial bash embedded directly in `run:` steps, and repeated the same Go
toolchain setup across five jobs. Embedded bash is invisible to shellcheck,
hard to test, and duplicates logic across YAML steps.

The `kata-guest-base.yml` workflow already set the precedent of extracting
substantial logic into standalone scripts (`scripts/build.sh`, `scripts/fetch.sh`,
`scripts/ci/stage-kata-conf.sh`) "so shellcheck sees it".

## Decision

Extracted the substantial embedded bash into standalone, executable scripts and
added one composite action:

| Script | Replaces | Workflow |
|---|---|---|
| `.github/scripts/docker-build-matrix.sh` | "Build Docker matrix" JSON builder | `docker.yml` |
| `.github/scripts/chart-version.sh` | "Determine chart version" | `chart.yml` |
| `.github/scripts/chart-verify.sh` | lint + 2× template (triplicated `--set` block) | `chart.yml` |
| `kata-guest-base/scripts/ci/install-build-deps.sh` | "Install build deps" (apt + sha256-pinned umoci) | `kata-guest-base.yml` |
| `kata-guest-base/scripts/ci/compute-tags.sh` | "Compute tags" | `kata-guest-base.yml` |
| `.github/actions/setup-go-c8s/action.yml` | repeated `actions/setup-go` block (×5) | `ci.yml`, `docker.yml`, `grype.yml` |

Conventions followed:

- **Script location**: repo-wide CI helpers live under `.github/scripts/`;
  kata-specific helpers stay under `kata-guest-base/scripts/ci/` to match the
  existing precedent there.
- **Comments moved, not lost**: the rich WHY comments (measured-boot/TCB
  invariants, the `g`-prefix SemVer rule, the side-branch tag policy) moved into
  the script headers; each `run:` step keeps a short pointer.
- **Scripts validate their env** (`: "${VAR:?...}"`) and keep `set -euo pipefail`.

## Things deliberately NOT changed

- **SHA-pinned actions kept** (not reverted to `@v4`/`@v5` tags). The
  `github-action` skill suggests floating major tags, but SHA pinning is the
  stronger supply-chain posture and is the established convention in this repo.
  The single setup-go SHA now lives in the composite action.
- **`kata-guest-base.yml`'s own `setup-go` stays explicit** (not routed through
  the composite). That workflow checks c8s out under a `path: c8s` subdir
  alongside two sibling repos, so the local-action reference would be
  `./c8s/.github/actions/setup-go-c8s` — and this is the expensive (45-min),
  hard-to-test, self-hosted, security-critical build. Keeping its action
  reference explicit and auditable beats saving one SHA reference. Revisit if we
  ever want a single source for the setup-go pin.
- **Tiny inline bash left inline** (3-line apt installs, AppArmor stop/restart
  toggles, the `IMAGE_TAG` wrapper around `fetch.sh`). Extracting these would be
  over-engineering.
- **Caching**: already strong (setup-go module cache, Docker GHA layer cache,
  the dedicated `go-modules` warm-up job, and the four restore/save split caches
  in the kata workflow). No new caches added — the remaining gaps are scan jobs
  where it isn't worth it.

## Verification

- `bash -n` clean on all five scripts.
- All workflows + the composite action parse as YAML.
- Smoke-tested the three `GITHUB_OUTPUT`-producing scripts against the original
  inline logic (fan-out / single / tag / none for the matrix; main / vX / side
  branch for tags; tag vs `base-g<sha>` for the chart version) — output is
  byte-for-byte identical.
- Not exercised end-to-end on a runner; `actionlint`/`shellcheck` were not
  available locally.
