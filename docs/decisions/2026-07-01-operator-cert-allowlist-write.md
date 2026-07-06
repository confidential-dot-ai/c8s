# 2026-07-01 — Operator auth for allowlist writes + `c8s allowlist`

> Update (PR review): the credential started as an X.509 cert chaining to a CA
> pinned on CDS. During review we simplified the shipped ("stop-gap") form to
> **pinned operator public keys** (no CA, no cert, no `x5c`); the CA-certificate
> model is retained below as the planned **future improvement**. Sections reflect
> that split.

## Context

CDS serves the image-digest allowlist that `nri-image-policy` enforces on every
node; it is the cluster's image-integrity control. CDS could already mutate the
allowlist via `POST`/`DELETE /allowlist`, gated by `EARWriteAuthorizer`: the
caller had to present a CDS-issued EAR whose launch measurement was listed in
`--allowlist-write-measurements`, body-bound via a `pbh` claim.

That path was never wired end to end. No endpoint minted an allowlist-write EAR:
`/attest` returns a certificate, `/attest-key` returns an EAR bound to a public
key but with **no `pbh` claim** (which the handler rejects). So there was no way
for anyone — human operator or in-cluster component — to actually write the
allowlist, and no CLI to do it. `pkg/allowlistclient.Add/Delete` were dead code.

We wanted an operator-facing CLI (`c8s allowlist`) to add/remove digests and
upload a whole allowlist, with credentials supplied by flag/file/env.

## Decision

Authorize allowlist writes (`POST`, new `PUT`, `DELETE /allowlist`) with an
**operator key**, verified at the application layer, and add a `c8s allowlist`
CLI.

- **Credential (shipped stop-gap)**: an operator EC private key whose **public**
  key CDS pins (`cds --operator-keys`, `cds.operatorKeys`, `c8s install
  --operator-keys`). The operator holds the private key; only public keys are
  handed to CDS. Public keys are not secret, so the chart stores them in a
  **ConfigMap** (not a Secret).
- **Wire format** (`pkg/operatorauth`): the client mints a short-lived
  ES256/384/512 JWT signed with the operator private key and carrying `pbh`
  = base64url(SHA-256(request body)) plus `htm`/`htu` (method and URL path, per
  RFC 9449 DPoP naming — path only, not the full URI, for proxy tolerance). CDS
  verifies the signature against its pinned keys, checks freshness, requires
  `iat`, rejects `exp−iat` beyond `MaxTokenValidity` (5m) so the replay bound
  holds regardless of what tooling minted the token, matches `htm`/`htu`
  against the request, and re-hashes the body against `pbh`. A captured token
  cannot be replayed against a different payload, verb, or path. No `aud`
  claim: CDS has no cluster identity a verifier could check, so two clusters
  pinning the **same** operator key accept each other's captured tokens within
  the 5m window — pin distinct keys per cluster (see `docs/GAPS.md`).
- **App layer, not transport mTLS**: CDS serves RA-TLS (it attests *itself* to
  clients). Turning on TLS client-cert verification would change the handshake
  for every mesh client on the listener. App-layer verification is scoped to the
  write handlers, leaves RA-TLS untouched, and gives body-binding for free.
- **`PUT /allowlist`** (new) atomically replaces the whole set; **CDS owns the
  version** and bumps it — the operator never supplies a version.
- **Operator-auth only**: the EAR/measurement write path is removed
  (`--allowlist-write-measurements`, `cds.allowlistWriteMeasurements`), along
  with the `EARWriteAuthorizer` type and the `cds/allowlist-write` resource —
  nothing could mint a valid allowlist-write EAR, and keeping the dead
  authorizer meant the handler tests exercised an auth path no deployment ran.
  Recover it from git history if the attested-CVM write path lands.

### Future improvement — CA + operator certificates

Replace flat key-pinning with a CA that CDS pins and per-operator certificates
(chain carried in the JWT `x5c` header). This gives delegated issuance and
CA-based revocation instead of editing a pinned-key list, and single-file
(cert+key) operator credentials. It is a superset of the stop-gap — the JWT/pbh
envelope and app-layer verification are unchanged; only the trust anchor (pinned
keys → CA) and the token's key material (bare key → x5c chain) differ. Tracked
in `docs/GAPS.md`.

## Alternatives rejected

- **Attested-EAR self-attestation** (CLI mints a body-bound EAR via a
  new/extended endpoint): purest fit with the existing model (only approved
  launch measurements can write), but the CLI must run inside an approved SNP
  CVM — not an operator laptop. Deferred; the operator-cert path can coexist
  with it later.
- **Static operator bearer token**: simplest, but a long-lived shared secret
  that rewrites the integrity control if leaked. Rejected in favor of per-
  operator keys.
- **CA + operator certificates now**: the stronger model (delegated issuance,
  CA-based revocation), but it needs a cert-issuance/renewal story to be usable.
  Deferred to the future-improvement above so the CLI can ship; key-pinning is
  the stop-gap.
- **Transport mTLS on the CDS listener**: fleet-wide handshake change on an
  RA-TLS listener.

## Consequences / trust boundary

- Any holder of a pinned operator key can rewrite the allowlist. Protect
  operator private keys (vault/HSM/hardware token).
- **Revocation is coarse (interim).** Operator keys are long-lived and CDS
  consults no CRL/OCSP. Revoking a compromised operator means removing its
  public key from `cds.operatorKeys` and re-installing. The CA future-improvement
  above replaces this with proper revocation.
- **The pinned-key list is host-supplied config, read only at CDS start, and not
  yet part of CDS's attestation.** A control-plane that swaps the ConfigMap and
  restarts CDS could pin its own key — the same unattested-config gap as the
  allowlist seed. Committing it via HOST_DATA/initdata and surfacing it in `c8s
  cds verify` is tracked in `docs/pitfalls.md` / `docs/GAPS.md`.
- Pin CDS measurements (`c8s allowlist --measurements`) so an operator cannot be
  tricked into writing to a rogue CDS.
- Writes fail closed: with no `cds.operatorKeys`, `POST/PUT/DELETE /allowlist`
  are rejected while reads keep serving.
- See `docs/THREAT_MODEL.md` (allowlist write auth) and `docs/pitfalls.md`
  (body-binding coordination).
