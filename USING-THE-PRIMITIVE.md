# Run your repo's tests inside a confidential VM

**One primitive, any repo.** If your code needs real confidential computing to be
tested (attestation, measured boot, TEE-gated certs — i.e. most of our stack),
you don't build CVM plumbing. You write a **payload** and call the primitive.

```
                confidential-dot-ai/confidential-ci
                .github/workflows/cvm-e2e.yml   ← THE PRIMITIVE
   boot a measured CVM on a platform → assert it's a genuine SEV-SNP guest →
   discover its runtime launch measurement → RUN YOUR PAYLOAD inside it →
   stream progress → tear it down (always) + reap leaked CVMs
                              ▲
        ┌─────────────────────┼─────────────────────┐
     c8s repo            attestation-rs           kettle            ← CONSUMERS
  payload: install     payload: cargo test    payload: build +      (your repo)
  c8s + cw e2e         --features attest      verify an image
```

You own **WHAT** (your payload) and **WHEN** (your trigger). The primitive owns
**WHERE** (booting/attesting/tearing down a CVM per platform).

## Add it to your repo

```yaml
# .github/workflows/confidential-e2e.yml
name: confidential-e2e
on:
  push:
    branches: [main]        # merge → integration → issues surfaced
  workflow_dispatch:

jobs:
  payload:
    runs-on: ubuntu-latest
    outputs:
      b64: ${{ steps.p.outputs.b64 }}
    steps:
      - uses: actions/checkout@v4
      - id: p
        run: |
          # YOUR test, as a bash script that runs INSIDE the CVM.
          cat > payload.sh <<'EOF'
          set -x
          # ... whatever proves your change works in a real TEE ...
          echo "@@PAYLOAD_OK@@"      # ← the success gate. No marker = failed run.
          EOF
          echo "b64=$(base64 -w0 payload.sh)" >> "$GITHUB_OUTPUT"

  e2e:
    needs: payload
    uses: confidential-dot-ai/confidential-ci/.github/workflows/cvm-e2e.yml@main
    with:
      platform: snp-metal          # bare metal, SEV-SNP (more cells coming)
      runner: confidential-bm
      flavor: base-cpu             # plain attested VM | rke2-node = a k8s cluster
      payload_b64: ${{ needs.payload.outputs.b64 }}
    secrets:
      ghcr_user: ${{ secrets.GHCR_USER }}     # only if your payload pulls private images
      ghcr_token: ${{ secrets.GHCR_TOKEN }}
```

That's it. No KubeVirt, no attestation code, no teardown logic in your repo.

## The payload contract

Your script runs **as root inside the CVM**. You get:

| given | what it is |
|---|---|
| `$MEAS` | the CVM's **runtime SNP launch measurement** (from configfs-tsm) — the exact value CDS/verifiers compare against. Use it to pin/enforce. |
| `$K` | in-guest `kubectl` (timeout-wrapped). Only meaningful for `flavor: rke2-node`. |
| `$GHCR_USER` / `$GHCR_TOKEN` | registry creds, if you passed them |
| `say <WORD>` | helper: emits `@@WORD@@` |

You must:
- `echo "@@PAYLOAD_OK@@"` on success — **that is the gate**. Anything else = failure.

You may:
- emit `@@ANY MESSAGE@@` for progress — markers are relayed to the run log live, so
  a stuck payload is debuggable without a shell.
- emit `@@FAIL_<REASON>@@` to fail fast instead of waiting for the timeout.

## Choosing a flavor

| flavor | you get | use when |
|---|---|---|
| `rke2-node` | the CVM **is** a single-node k8s cluster (measured RKE2 node image); `$K` talks to it | you're testing something that runs *on* a cluster (c8s) |
| `base-cpu` | a plain attested CVM | you just need a real TEE to run a binary/test in |

If your payload needs a toolchain the image doesn't ship (e.g. Rust), say so —
flavors are a knob on the primitive, not something you work around in your repo.

## What you get for free

- a **genuinely attested** CVM (asserted `sev-snp-guest` + IGVM measured boot; not a simulation)
- the node's real launch measurement, so you can **enforce fail-closed**
- teardown **always** (the CVM is tmpfs — deleting it is total), plus a reaper that
  cleans up leaked CVMs without ever killing a live run's
- live progress in your run log

## Triggers: the standing rule (follow the existing precedent)

**Confidential hardware is driven post-merge or manually — never by `pull_request`.**
This is not a new policy; it is what `c8s` already does. Both workflows there that
touch the SNP build host (`runs-on: the-machine` — `kata-guest-base.yml`,
`kernel-snapshot.yml`) use `workflow_run` off `Docker` and/or `workflow_dispatch`,
and neither has a `pull_request:` trigger. Their own comment states the reason:

> *"No `pull_request:` trigger: the build is long … Cost of a post-merge break is
> 'revert + open follow-up'; paid PR feedback isn't worth the build × every push.
> Use workflow_dispatch to rebuild on demand."*

Three reasons this is right for confidential e2e too:
1. **Throughput** — the lane boots a real CVM on ONE shared metal host and is
   serialized (the guest console is exclusive per VMI). PR-gating queues every PR
   behind ~25 min of single-host work.
2. **Safety** — a fork PR is untrusted code. It gets no secrets and a read-only
   token, but it would still *execute on our SEV-SNP hardware*. Post-merge means
   only already-merged code ever runs there.
3. **It's the shape the vision asks for** — "merge to main → integration happens →
   issues surfaced".

Same-repo PRs from org members are a *lower* risk (they already have write access),
so PR-triggering a **private** repo is defensible — but hold off on throughput
grounds until there's more than one metal host.

### The template (copy it; don't paraphrase it)

For a consumer that cascades off a build (the `c8s` shape), mirror
`c8s/.github/workflows/kata-guest-base.yml` exactly:

```yaml
on:
  workflow_run:
    workflows: ["Docker"]     # the build that publishes the images you test
    types: [completed]
  workflow_dispatch:          # the manual escape hatch

concurrency:
  # keyed on the TRIGGERING run's head_sha, NOT github.ref: under workflow_run
  # github.ref is ALWAYS the default branch, so a per-ref key collapses distinct
  # commits into one group and cancels the wrong builds
  group: ${{ github.workflow }}-${{ github.event.workflow_run.head_sha || github.sha }}

jobs:
  e2e:
    if: |
      github.event_name == 'workflow_dispatch' ||
      (github.event.workflow_run.conclusion == 'success' &&
       github.event.workflow_run.head_repository.full_name == github.repository &&
       (github.event.workflow_run.event == 'push' ||
        github.event.workflow_run.event == 'workflow_dispatch') &&
       (github.event.workflow_run.head_branch == 'main' ||
        startsWith(github.event.workflow_run.head_branch, 'v')))
```

What each guard buys you:
- `conclusion == 'success'` — don't cascade off a failed build.
- `head_repository.full_name == github.repository` — **the fork guard.** Already
  unreachable (fork pushes don't trigger base-repo workflows), but per the c8s
  comment it "makes the invariant **local instead of inferred**". Keep it.
- `workflow_run.event == push|workflow_dispatch` — excludes the build's own PR runs.
- `head_branch == main || v*` — only refs that actually publish images.

And when you check out the code under test, use **`github.event.workflow_run.head_sha`**,
not `github.sha` — under `workflow_run`, `github.sha` is the workflow file's ref, not
the commit that triggered you.

## Notes / current limits

- **Platforms:** `snp-metal` today. `tdx-metal`, `gke-snp`, `gke-tdx` are cells we add
  to the primitive — consumers won't change, they just gain matrix rows.
- **Public repos:** a self-hosted runner only serves a *public* repo if its runner group
  allows public repos. Talk to us first, and use the post-merge template above.
- **Chart-tag resolution (c8s consumers):** `charts/c8s:0.1.0-g<sha>` only exists for
  commits that touched `internal/helmchart/**` (the publish workflow is path-filtered),
  so a merge that doesn't touch the chart has no tag at its sha. Resolve "latest chart
  tag ≤ this sha" rather than assuming one exists at it.
- **Secrets:** your payload is delivered over the guest serial console, so anything you
  bake into it (tokens) lands in the guest console log and as unmasked base64 in the
  Actions log. Don't put long-lived credentials in a payload until we close that gap.
