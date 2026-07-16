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

## Notes / current limits

- **Platforms:** `snp-metal` today. `tdx-metal`, `gke-snp`, `gke-tdx` are cells we add
  to the primitive — consumers won't change, they just gain matrix rows.
- **Public repos:** a self-hosted runner won't serve a *public* repo unless its runner
  group allows public repos. If your repo is public, talk to us first — the safe shape
  is post-merge (`workflow_run` off a build), never `pull_request` from forks.
- **Secrets:** your payload is delivered over the guest serial console, so anything you
  bake into it (tokens) lands in the guest console log. Don't put long-lived
  credentials in a payload until we close that gap.
