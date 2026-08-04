# Improvement plan: shrink the codebase, build the harness

**Date:** 2026-08-04. **Status:** §B executed on branch `cleanup/dedupe-and-shrink`
(this branch); §A, §C, §D, §E remain proposed. Scope corrections found while
executing §B are noted inline as *[executed]* remarks.

Guiding idea (from [OpenAI's harness-engineering post](https://openai.com/index/harness-engineering/)):
optimize the repo for agent legibility, encode taste as mechanical rules, keep the repo the
single source of truth, and run continuous garbage collection so the codebase shrinks rather
than grows. c8s scores well on layering and CI hygiene; it fails on agent onboarding docs,
has ~590 lines of verified duplication, and several docs that have silently become fiction.

---

## A. Make the harness exist (agent legibility) — highest leverage

1. **`AGENTS.md` and `CLAUDE.md` are not in the repository.** `AGENTS.md` is a symlink into
   `.claude/confidential-ai/`, which is excluded by a developer's *global* gitignore; both files
   show as untracked. On a fresh clone `AGENTS.md` is a dangling symlink and every coding agent
   starts with zero instructions. This violates the repo's own rule
   (`docs/engineering-standards.md` Appendix B: "CLAUDE.md present").
   → Track a real `AGENTS.md` + a one-line `CLAUDE.md`; vendor shared standards into `docs/`.
2. **AGENTS.md has no repo-specific content.** 113 lines of org-generic policy (Rust rules,
   Argon2id…), zero mentions of c8s components, no repo map, no pointer to `docs/` or
   `docs/pitfalls.md` (the best agent doc in the repo), no build/test commands, no mention of
   the `make manifests` / `check-crd-chart` coupling.
   → Rewrite as a ~70-line table of contents: what c8s is, repo map (`cmd/` shims →
   `internal/cmds/<name>/` real code; `pkg/` public; embedded chart in `internal/helmchart/`),
   how to add a subcommand / chart value / CRD field, the make targets, linked doc index.
3. **No docs index; orphaned docs.** Only 7 of 17 `docs/*.md` are reachable from README;
   `volumes.md` (flagship new feature) and `GAPS.md` have **zero inbound links**. Half the
   corpus has zero outbound links.
   → Add `docs/README.md` index grouped by audience; link from README + AGENTS.md; CI check
   that every `docs/*.md` appears in it.
4. **Untracked parallel knowledge stores rot.** `.serena/memories/` already contradicts the
   repo (wrong module path, wrong go version, wrong `make fmt` behavior) while holding the one
   fact the tracked docs lack (the `assam`/`cert-issuer` → `cds` merge, #76).
   → Fold useful facts into tracked docs; retire the rest.

## B. Delete code (~590 lines of verified duplication) — *executed on this branch*

All ten items landed (see the `refactor(...)` commits on this branch); the repo's non-test
source shrank by ~370 lines net while gaining direct tests for the new shared helpers.
Scope corrections discovered while executing, recorded so the next pass doesn't redo them:

- **#3**: a generic cross-package `httpjson` helper was rejected — `allowlistclient` and the
  secrets client encode endpoint-specific semantics (ETag/304 handling, tri-state 200/201/409
  results) that a shared helper would obscure. Only `attestclient`'s four genuinely identical
  loops were collapsed (package-local `do`/`ok`). The triplicated `StatusError` types stay:
  two are exported pkg API and 12 lines each.
- **#5**: the `PublicTLS.Mode` divergence is **intentional, not drift** — `c8s verify`
  gathers evidence for offline verification and never binds a connection, so the mode check
  doesn't apply. The shared helper (`ratls.AttestedCertFromDiscovery`) covers the common
  parsing; mode policy stays with lbdiscovery.
- **#6**: the two enforcers' `sandboxTokenSigner`/`startAdmissionInventory` differ in failure
  posture on purpose (nri fails closed; policy-monitor degrades open, with load-bearing
  comments) — only the mechanically identical atoms moved (`SandboxContainer.Key/Compare`,
  `ResolveAdvertiseHostForCDS`, `VersionFromETag`).
- **#7**: the release wire types went to the server package (`credrelease`, exported) with
  client-side aliases, not `pkg/issuerapi` — that package documents itself as the CDS
  signing/handoff contract, which this is not.
- **#10**: the JSON error-envelope and logger unifications were dropped — `cdsattest`'s text
  logger and `certutil`'s JSON logger differ in format and failure posture (not duplicates),
  and unifying the envelope would add a cross-server import for four lines.

Ordered by deletable lines; items marked ⚠ are on attestation trust paths (correctness-class —
do these carefully, keep the existing tests).

| # | Consolidation | ~LOC | Notes |
|---|---|---|---|
| 1 | Extract shared sidecar core from `internal/cmds/getvolume` + `getsecret` (config struct, flags, `fetchChallenge`, `newClient`, retry loop are byte-identical); use `fileutil.WriteAtomic` instead of `getsecret`'s hand-rolled copy | 225 | Both have flow/e2e tests |
| 2 | `ratlsmesh/main.go:439` duplicates `runInGuestCDSUpgrade` (`in_guest_linux.go:452`) — call the extracted one; delete local `parseHexMeasurements` (verbatim copy of `ratls.ParseHexMeasurements`, already imported) | 68 | |
| 3 | Shared `httpjson` helper (PostJSON/GetJSON/StatusError) for `pkg/attestclient` (4 hand-rolled request loops), `pkg/allowlistclient`, `internal/cmds/secrets/client.go`; `StatusError` is declared identically 3× | 60 | |
| 4 | ⚠ Digest-from-annotations helper in `pkg/types` (delegating to `types.ParseDigest`) replacing copies in `rtmr3measurer/measurer.go` and `policymonitor/allowlist.go` (regexes already spelled differently) | 50 | |
| 5 | ⚠ `DiscoveryDocument.AttestedCert()` in `pkg/types` replacing `internal/lbdiscovery.verifyDocument` + `internal/cmds/verify/discovery.go` parsing — the copies have **already diverged** (`verify` skips the `PublicTLS.Mode` check) | 45 | Fixes real drift |
| 6 | Move sandbox-token scaffolding (`sandboxTokenSigner`, `startSandboxDigests`, `startAdmissionInventory`, `AdmittedKey`) from `nri-image-policy` + `policymonitor` into `pkg/workloadclaims`; export `allowlistclient.VersionFromETag` | 40 | |
| 7 | ⚠ `rtmr3.ForOperatorKey()` in `pkg/rtmr3` replacing duplicated `SHA384(0x00*48 ‖ SHA384(pubkey))` in `credrelease/binding.go` and `getkubeconfig/verify.go`; move `releaseRequest`/`releaseResponse` wire types into `pkg/issuerapi` | 35 | `pkg/rtmr3` exists precisely to own this and has 1 importer |
| 8 | Export `ratls.RATLSTransport`/`RATLSHTTPClient`; `internal/localverify/ratlsclient.go` duplicates the transport block byte-for-byte | 20 | |
| 9 | `trimSlash`/`cmdCtx` (byte-identical in `cmds/secrets` + `cmds/volume`) → `cmdsutil`; `Authorizer` interface → `pkg/operatorauth` | 20 | |
| 10 | Scattered: `MeasurementAllowed` re-export, shared `craneDigest`, `boolPtr`→`ptr.To`, unify JSON error envelope on `internal/attestation.WriteError`, move `certutil.NewJSONLogger` (a logging helper in a cert package) to `cmdsutil` | 30 | |

**Explicitly not duplication (keep, but rename):** `pkg/attestationclient` (attestation-api
verifier client) vs `pkg/attestclient` (CDS client; imports the former) are different layers.
The names differ by four characters and mean different services — rename (e.g.
`pkg/attestationapi` / `pkg/cdsclient`) or add disambiguating doc headers. Likewise
`internal/allowlist` (CDS server store) / `pkg/allowlist` (schema, canonical, 22 importers) /
`pkg/allowlistclient` (HTTP client) are correctly separated.

`cmd/` is already exemplary (10–16-line shims) **except** `cmd/c8s/install.go` (1915 lines) +
`uninstall.go` + `render_values.go` — the only real logic left in `cmd/`; move to
`internal/cmds/` for consistency when next touched.

## C. Fix docs that have become fiction

1. **`docs/GAPS.md` is wrong, not just stale**: tells users to set `assam.measurements` /
   `certIssuer.measurements` — keys that no longer exist anywhere (now `cds.measurements`,
   `ratlsMesh.measurements`); lists handoff, secret release, and per-workload allowlists as
   unimplemented — all three shipped. README keeps a separate, *current* gaps list.
   → Delete GAPS.md in favour of README's list, or make it canonical and link it. One register.
2. **`docs/THREAT_MODEL.md`** ("living document", last updated 2026-07-10) says secret release
   "doesn't exist" (it shipped: `internal/secrets/`, `docs/secrets.md`) and never mentions
   `volumed` — a new *privileged host DaemonSet* handling volume keys. A threat model missing
   the newest privileged component is its own worst-case failure mode. → Update both sections.
3. **`README.md`**: roadmap lists encrypted volumes and attestation-gated secrets as future
   (both shipped); "allowlist gates digests only" contradicts
   `docs/allowlist-and-capabilities.md` (command/args policy is enforced); component/library
   tables omit `volumed`, `policy-monitor`, `rtmr3-measurer` and 5 `pkg/` entries.

## D. Mechanical enforcement (encode taste as rules)

Already good: pinned toolchain derived from go.mod, `go test -race`, govulncheck, CRD↔chart
drift check, coverage non-regression gate, mutation testing (advisory), SHA-pinned actions.
Missing — each converts a prose rule into a gate, cheapest first:

1. **Dependabot/Renovate** — `engineering-standards.md` §124 calls pins without a bump bot
   "a rot machine" and mandates the bot; there is none.
2. **CI ignores docs** — `ci.yml` `paths:` excludes `**.md`, so docs-only PRs run zero checks;
   add a markdown link checker + docs-index completeness check on those paths.
3. **`make lint` ≠ CI lint** — local is fmt+vet; CI adds golangci-lint + check-crd-chart.
   Fold golangci-lint into `make lint` so green-locally means green-in-CI.
4. **Widen `.golangci.yml`** (currently defaults + `unused`): `errorlint` (enforces the `%w`
   rule), `noctx`/`contextcheck` (enforces "every network call has a timeout"), `bodyclose`,
   `gosec`, `unparam`, `dupl` (would have caught most of §B), and a deadcode pass.
5. **PR-title lint** — conventional commits are mandated in CONTRIBUTING.md, unenforced.
6. **Doc freshness**: `<!-- last-verified: date, commit -->` header per doc + a scheduled
   cheap-LLM docs/code parity check (already contemplated by engineering-standards §101/§174) —
   the one control that would have caught C.1–C.3 automatically.

## E. Keep it shrinking (continuous GC)

- Recurring agent task (weekly): run the duplication detector + deadcode over the repo, file
  small refactor PRs; update this plan's §B table as items land.
- Rule for new code (add to AGENTS.md): a second implementation of anything in `pkg/` or
  `cmdsutil` is a lint failure, not a style choice — extend the shared package instead.
- When a component is renamed or merged (as with `assam`/`cert-issuer` → `cds`), grep docs for
  the old name in the same PR; the docs parity check backs this up.
