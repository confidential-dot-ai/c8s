# RFC: KMS token bootstrap — keep the dev-KMS root token off the control plane

**Status:** RFC — no code changes proposed yet.
**Pairs with:** confidential-dot-ai/c8s#109 (introduces the dev KMS + broker),
review comment 3638582075.
**Author:** first-pass proposal; needs a decision before either variant is
implemented as a follow-up PR.

## Problem

The `kms.enabled` deployment in #109 wires the dev OpenBao's root token as a
Helm value (`kms.devRootToken`, defaulting to the literal string `root`),
rendered into a `<release>-openbao-dev-cred` `Secret`, mounted by both the
openbao pod (as `VAULT_DEV_ROOT_TOKEN_ID`) and the secret-broker pod (as
`--openbao-token-file`). Every hop is control-plane-visible:

- The Helm values file, if templated, ends up on disk on the operator's
  laptop.
- The rendered `Secret` is retrievable by any principal with `get secrets`
  in the release namespace.
- The env var is visible to any principal with `get pods` (env with
  `valueFrom.secretKeyRef` is dereferenced when the pod is described).

Under the c8s threat model the control plane is untrusted. A control-plane
holder who reads that `Secret` gets the OpenBao root token and can, from
outside the mesh, extract every KV item the broker gates — which is precisely
what the attestation-gated release policy exists to prevent. The whole
attested-KMS story is undercut by one control-plane read.

## Non-goal

**Not this RFC:** the production KMS (external, attested, with its own trust
argument). This RFC scopes only the dev/demo KMS the chart ships. Production
runs an operator-provided OpenBao/Vault whose credential arrives via the
operator's normal secret-management, out of chart scope.

## Landing constraint

`main` doesn't contain the KMS or broker yet — both arrive with #109 and #63.
Any follow-up implementation must land **after** #109, and its scope crosses
files #109 owns (broker OpenBao client init at
`internal/cmds/secretbroker/openbao.go`, the `kms-openbao.yaml` and
`secret-broker.yaml` templates). This RFC exists so we can pick a shape
before #109 ships and re-open its files.

## Variants considered

### A. Operator-key-driven unwrap

The `c8s install` operator already carries an attested identity (via CDS
issuer). Have the operator generate the dev token locally, wrap it under
the openbao pod's future public key, and stash the wrapped blob in a
`ConfigMap`. The openbao pod boots, derives its keypair, unwraps, uses as
`-dev-root-token-id`. The broker separately learns the token by receiving
its own wrapped copy, unwrapped inside its TEE. Nothing plaintext ever
touches the control plane.

**Requires (net-new):** a sealing/unwrapping primitive in the c8s stack —
the operator's mesh identity is TLS, not KMS; nothing today wraps to a
future TEE public key. Writing that primitive (and its trust argument) is
its own multi-week effort. **Verdict:** deferred as a real net-new
capability, not appropriate for a dev-KMS follow-up.

### B. Startup generation, no plaintext in k8s

The broker and openbao pods coordinate at startup so a token that never
existed in Helm values becomes the shared credential. Three shapes:

1. **B1. Shared pod.** Colocate openbao + broker as containers in one pod;
   an init container writes a random token to an in-memory volume both
   read. Simplest mechanically. Costs: they scale together, can't be
   rolled independently, and coupling a "backing store" with its "attested
   proxy" in one pod muddles the trust boundary the two enforce
   separately. **Verdict:** rejected — architectural regression to save
   one Secret.

2. **B2. Init-container publishes to a k8s Secret in-cluster.** An init
   container generates a random token and `kubectl create secret` it into
   the release namespace; both pods mount it. **This still puts the token
   in a `Secret`** — control-plane holders still harvest it. Only benefit
   over today: no plaintext in the Helm values file. **Verdict:** rejected
   — misses the point.

3. **B3. OpenBao cert-auth using the broker's mesh identity.** Enable
   OpenBao's `cert` auth method. The broker authenticates to OpenBao by
   presenting its CDS-issued mesh cert; OpenBao maps the cert's CN/SAN to
   a policy granting KV read on the paths the broker's release policy
   covers. **No shared secret exists** — the credential IS the already-
   attested TLS identity. **Verdict:** recommended.

## Recommendation: B3 — OpenBao cert-auth

### Shape (dev KMS only — chart-shipped)

At openbao pod startup, a one-shot init container (or a `postStart` hook)
runs against the local openbao:

```sh
bao auth enable cert
bao write auth/cert/certs/secret-broker \
    display_name=secret-broker \
    certificate=@/etc/mesh-ca/ca.crt \
    allowed_common_names=<broker-mesh-SAN> \
    token_policies=secret-broker
bao policy write secret-broker - <<'EOF'
    path "secret/data/*" { capabilities = ["read"] }
    path "secret/metadata/*" { capabilities = ["list"] }
EOF
```

The mesh CA bundle is fetched from CDS at startup (an existing capability
via `c8s get-cert --ca-out`). The broker's SAN is the deterministic
`c8s-secret-broker.<ns>.svc` name the chart already gives it.

The broker's OpenBao client (`internal/cmds/secretbroker/openbao.go`) gains
a `--openbao-auth=cert` mode: instead of holding a token, it calls
`POST /v1/auth/cert/login` with its mesh TLS cert as client-auth, receives
a short-lived token, and refreshes on 403. The existing AppRole re-login
path is a good template — the login shape is nearly identical.

### Trust argument

- **What's off the control plane:** the token — never generated, never
  stored, never mounted.
- **What replaces it:** the broker's CDS-attested TLS identity, which is
  already the trust anchor for every other broker-authenticated flow.
- **What OpenBao trusts:** the CDS mesh CA at
  `/etc/mesh-ca/ca.crt`. That bundle is public (CDS-vouched, not secret),
  so no ancillary secret leaks. Its provenance is the same one every
  ratls-mesh sidecar trusts.
- **What the control plane still sees:** the `cert` auth configuration
  (bao write payload) in a `Secret` or `ConfigMap` if we render it there.
  This is bootstrap policy, not a credential — a control-plane holder who
  swaps it opens the broker up but does not learn anything already in
  OpenBao. That's a downgrade vs today's "reads root token, empties KV
  offline" but still a real gap; mitigated by re-checking the cert-auth
  config from within the broker's attested startup as an integrity check
  (same shape as the existing release-policy checksum roll).
- **Under kata:** unchanged. The broker's mesh identity is issued to the
  broker pod (whether kata-wrapped or not); OpenBao only sees the TLS
  layer.

### Migration

`kms.devRootToken` **stays** as a deprecated value for one release, wired
only when `kms.legacyStaticToken: true` — an explicit opt-back-in for
in-flight installs. Chart renders a Helm `NOTES.txt` warning when
`legacyStaticToken` is true. Remove both after one release.

### Scope of the follow-up PR

- `internal/cmds/secretbroker/openbao.go` — add `cert` auth login, refresh
  on 403.
- `internal/cmds/secretbroker/cmd.go` — new `--openbao-auth=cert` flag;
  document `token`/`approle`/`cert`.
- `internal/helmchart/c8s/templates/kms-openbao.yaml` — add the init step
  (either an init container running `bao` locally, or a `postStart` exec
  after `-dev` starts).
- `internal/helmchart/c8s/templates/secret-broker.yaml` — flip the mount
  from the dev-cred Secret to the mesh CA + broker cert paths already
  present; drop `--openbao-token-file` in the cert-auth branch.
- `internal/helmchart/c8s/values.yaml` — deprecate `devRootToken`, add
  `kms.legacyStaticToken` guard.
- Tests: `internal/helmchart/chart_test.go` for the rendering fork;
  `internal/cmds/secretbroker/openbao_test.go` for the cert-auth login
  path (mockable via `httptest.Server`).

Rough size: ~300 LoC net, mostly template branching and a login handler
mirroring AppRole.

## Open questions before implementation

1. **`bao auth enable cert` on `-dev`.** Confirm the dev server accepts the
   auth-method configuration at startup (the dev harness is quirky about
   what state persists). If not, run the bootstrap after the server is
   ready via a small init loop.
2. **Cert-vs-SAN matching under kata.** The broker's SAN is set by the
   webhook or the operator at inject time; verify it's stable across
   restarts (otherwise the OpenBao mapping needs re-write on every roll).
3. **Renewal cadence.** The mesh cert renews at whatever interval the
   webhook sets (default 6h); the OpenBao cert-auth login yields a
   separate token TTL. Pick a token TTL that outlives normal renewal
   jitter (e.g. 24h) or wire the broker to re-login on cert rotation.
4. **Production external KMS.** Cert-auth generalizes cleanly to an
   external OpenBao/Vault the operator points at; the operator adds the
   broker's mesh CA to that store's cert-auth config. This RFC does not
   commit to that shape but leaves it unblocked.

## Decision needed

- **Land as RFC-only, do B3 implementation as a subsequent PR after
  #109?** (Recommended path.)
- **Reject B3 and accept the static token for the dev KMS as a permanent
  dev-only compromise?** (Legitimate if we accept the trust gap is
  bounded to demo clusters.)
- **Explore variant A (operator-key sealing) instead?** Larger effort;
  requires its own primitive-design RFC first.
