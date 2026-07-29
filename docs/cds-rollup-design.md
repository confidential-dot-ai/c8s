# Design: CDS attestation roll-up for browser and CLI clients

_Draft, 2026-07-29. Scopes branch `feat/cds-rollup` across c8s, c8s-verify-js,
TEErminator._

## The problem

A client today can verify: real TDX silicon, the audited guest image
(MRTD + RTMR[1]/[2]), this operator's deployment (RTMR[3]), a fresh nonce bound
into `report_data`, and that the LB's leaf chains to a mesh CA **pinned out of
band**.

It cannot verify **what policy the cluster enforces**. An operator holding
`op.key` can upload a permissive allowlist and no measurement the client checks
changes. `docs/ratls.md` is explicit that the current binding "distinguishes
honest workloads only".

That makes the attestation much less useful than it looks: we prove the code is
audited, but not that the thing admitting workloads is admitting the right ones.
CDS is supposed to be the attestation roll-up — the component that says "here is
the allowlist I enforce, and here is my key" — and nothing surfaces that.

## What already exists (verified on the live cluster, 2026-07-29)

The mechanism is built and unused, not missing.

The CDS **RA-TLS serving certificate** (self-signed, `CN=RA-TLS Workload`,
port 8443 / NodePort 30808) carries:

```
1.3.6.1.4.1.59888.1.1   attestation  (TDX quote)
1.3.6.1.4.1.59888.1.3   config-claims
```

Decoded from the live cert:

```
operatorKeysDigest   c4c5b8b62a54d586a17d1d556c5028e9d2b31b5a0839aa2a673db4a27ed7d693
seedDigest           f35f2e22a90b1e60623bed02525660804396bae6f746522c96521c053aff189e
workloadDigest       0000…0000   (UnsetDigest — CDS is not a workload)
```

`internal/cmds/cds/run.go:215` builds them; `pkg/ratls` folds the claims DER
into REPORTDATA as
`SHA-384("c8s/config-claims/v1\0" ‖ framed(pubkey) ‖ framed(claimsDER) ‖ framed(nonce))`,
so the **hardware vouches for the digests, not just the key**.

`c8s verify --kind cds --allowlist-seed` already checks this. Nothing else does.

### The gaps, precisely

| # | gap | evidence |
|---|---|---|
| 1 | tls-lb publishes the **wrong CDS cert**. `/.well-known/cds-cert.pem` returns the mesh **leaf** (`issuer=c8s Mesh CA`, ext `.1.1/.1.2`, no claims), not the RA-TLS serving cert that carries `.1.3`. Different fingerprints. | live fetch |
| 2 | No client parses `.1.3`. `c8s-verify-js` does **no** custom X.509 extension parsing at all. | `grep 59888 src/` → empty |
| 3 | `c8s-verify-js` never verifies CDS. `cds_cert_pem` in the bundle is the **LB's own leaf + issuing CA** (PROTOCOL.md:68), used only for the chain check. The name misleads. | `verify.ts:257-265` |
| 4 | TEErminator's `cds-cert` mode is a stub that fails closed and points at c8s-verify-js "for this flow today" — which does not implement it either. | `proxy.go:227`, `TODO.md` |
| 5 | The EAR (CDS-signed JWT) is defined but never populated by the LB or read by clients. | PROTOCOL.md:69 |
| 6 | CDS RA-TLS is a NodePort, not publicly routable. | no NAT forward |

## The trust chain we want

```
pinned out of band:  CDS measurement (MRTD/RTMR1/RTMR2 from the build manifest)
                     operator key      (→ expected RTMR[3])
                     expected seedDigest (published alongside the allowlist)
        │
        ▼
1. verify CDS quote ──▶ genuine TDX, audited image, our operator key
        │              └─ config-claims: seedDigest, operatorKeysDigest
        │                 → "this CDS enforces allowlist X"
        ▼
2. mesh CA is DERIVED from the verified CDS, not pinned by hand
        │
        ▼
3. verify LB quote, chain its leaf to that mesh CA
        │
        ▼
4. "I am talking to a component admitted by a CDS that is provably
    enforcing allowlist X" — transitive trust, rolled up
```

The important consequence: **the mesh-CA pin stops being an out-of-band TOFU
step.** Today the client must obtain the mesh CA somehow and trust it. Once CDS
is verified, the CA is a *derived* value — and the CA rotates on every
reinstall, which is precisely what made pinning it painful.

## Two shapes

### A. Two round trips, long-lived cache  *(recommended)*

1. `GET /.well-known/c8s/cds-attestation?nonce=N` → CDS RA-TLS cert + quote
2. Client verifies it, extracts `seedDigest` + mesh CA, **caches** keyed by
   (cert fingerprint, measurement)
3. Per session: the existing LB attestation, chained to the cached mesh CA

Cache lifetime bounded by the CDS cert TTL (`cds.ratlsCertTTL`) and re-checked
when the LB's leaf fails to chain. Cheap steady state: one extra fetch per
cache miss, not per session.

- **+** CDS and LB verified independently; LB stays stateless about CDS
- **+** cache survives across sessions and page loads
- **−** first load is two round trips
- **−** freshness of the cached CDS verdict needs a policy (below)

### B. One round trip, LB carries the CDS evidence

The LB includes the CDS RA-TLS cert + quote in its attestation bundle, and
extends the transcript to cover them:

```
transcript = … ‖ LP(cds_cert_der) ‖ LP(cds_quote)
```

- **+** one fetch, and the CDS evidence is bound to the same client nonce, so
  freshness is solved for free
- **−** LB must hold and refresh CDS evidence; couples their lifecycles
- **−** bundle grows by a TDX quote (~5 KB) on every request

**Recommendation: A, with B's transcript trick as a later optimisation.** A
keeps the components independent and the cache makes the second trip rare.
Freshness is the one thing A must get right.

### Freshness: decided — cache long-lived, CDS is a CA

**Decision (2026-07-29): cache the verified CDS verdict for a long time, keyed
on cert fingerprint. No CDS attest endpoint.**

The CDS RA-TLS cert commits an *issuance* challenge (`.1.2`), not a
client-supplied one, so `c8s verify` correctly reports "freshness NOT proven".
That sounds like a problem and isn't, because liveness is not what this
attestation is for.

CDS is a **certificate authority for confidential computing**. The claim being
cached is "this key belonged to a genuine, measured CDS that vouched for
allowlist X" — a statement about a key, not about what is running this instant.
Web PKI treats roots the same way: nobody re-attests a CA per connection.

Consequences:

- cert rotation is a **cache miss**, not a failure — re-attest and continue
- freshness where it genuinely matters (is the LB I am talking to alive and
  genuine *now*) stays with the LB's nonce-bound attestation, which already
  works and is unchanged
- a CDS attest endpoint is **not needed**; dropped from scope

The one property to preserve: the cached entry must be keyed on the cert
fingerprint **and** the verified measurement, so a re-issued cert from a
different image cannot silently reuse a cached verdict.

### Note on "expose" vs "attest"

Exposing the CDS RA-TLS cert *is* how the client attests CDS — the TDX quote
rides inside it as extension `.1.1`, and REPORTDATA binds the cert's public key
together with the claims DER. Verifying the cert therefore proves a genuine TD,
running the measured image, holds this key and vouches for that allowlist
digest. There is no separate attestation object to fetch.

Demonstrated end to end on the live cluster with
`c8s verify --kind cds --mode ratls-cert --image-manifest … --operator-key …`,
which returns the attested `allowlist-seed digest` from nothing but the cert.
The client-side work is the verification (parse `.1.1`, verify quote, check
measurements, read `.1.3`) — the transport work is only making those bytes
reachable.

## Deltas per repo

### `c8s`

- **Expose the right cert.** New tls-lb route `/.well-known/c8s/cds-attestation`
  returning the CDS **RA-TLS serving cert** (the one with `.1.3`) plus its
  quote. Do not reuse `/.well-known/cds-cert.pem` — that serves the mesh leaf
  and changing it would break existing callers. Consider renaming that route
  in docs to `mesh-leaf.pem`; the current name is actively misleading.
- No CDS attest endpoint: CDS is treated as a CA and its verdict is cached (see Freshness).
- `pkg/ratls` already exports `ExtractConfigClaimsBytes` — reuse rather than
  reimplement.

### `attestation-rs`

- Expose the config-claims extension bytes from the WASM verifier so a browser
  can read `seedDigest` without shipping an X.509 extension parser in JS.
  The Rust side already parses the cert.

### `c8s-verify-js`

- `verifyCdsAttestation(bundle, { measurements, expectedRtmr3, expectedSeedDigest })`
  → returns `{ meshCaPem, seedDigest, operatorKeysDigest }`
- Cache keyed by cert fingerprint; TTL from `notAfter`
- `C8sClient` gains `cdsAttestationUrl` and `expectedSeedDigest`; when set,
  the mesh CA is **derived**, and `meshCaPem` becomes optional
- New error code `seed_denied`, matching the `rtmr3_denied` shape — and the
  same rule: an absent claim fails closed, never passes

### `TEErminator`

- Implement `--mode cds-cert` for real, replacing the stub: fetch + verify CDS,
  cache the verdict, pin the derived mesh CA, then attest the LB as today
- `--expected-seed-digest` alongside `--expected-rtmr3`

### `c8s-verify-poc`

- Publish the expected `seedDigest` in `/_refs`
- The allowlist panel currently shows data **fetched from the endpoint being
  verified** — informative, not verified. Either label it as such, or gate it on
  the attested `seedDigest` matching. Do not ship it unlabelled; it implies more
  than it proves.

## Order

1. c8s: expose the CDS RA-TLS cert + quote through tls-lb  ← unblocks everything
2. attestation-rs: surface config-claims from WASM
3. c8s-verify-js: verify + cache + derive mesh CA
4. TEErminator: same, replacing the stub
5. poc: publish the seed digest, gate the allowlist panel

Steps 1 and 2 are independent and can go in parallel. Nothing here needs a CVM
relaunch — the CDS already emits the claims.
