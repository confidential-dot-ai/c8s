# `feat/cds-rollup` + `feat/runtime-measurement-pinning` — branch notes

_Temporary. Delete before merge; the durable material belongs in `docs/ratls.md`._

Base: `origin/main` @ `c61839c`. Everything here was exercised against a live
bare-metal **Intel TDX** cluster (8×B300), not only unit tests.

---

## The problem

A verifier could establish "genuine TDX, running an audited image" and then had
to **take the rest on trust**:

| Question | Before |
|---|---|
| Which guest OS booted? | `--measurements` pins **MRTD**, which on TDX covers firmware only |
| Which CA issues this cluster's certs? | mesh CA handed over out of band |
| What may run here? | `seedDigest` — the allowlist **at boot**, frozen thereafter |
| Where do I get CDS's certificate? | nowhere — nothing published it |

Each gap has the same shape: a pin that reads as enforced and enforces less than
it appears to.

---

## What changed

**1. `MRTD` is firmware-only — pin RTMR[1]/[2]** (`8a5d307`)
`3ace878` and `c61839c` publish an **identical MRTD** despite different
`disk.raw`, `roothash` and `uki.efi`. Guest identity lives in RTMR[1] (kernel)
and RTMR[2] (rootfs). Adds `--expected-rtmr1/2/3` and `--image-manifest` (reads
the confos build manifest, so the reference comes from the image pipeline rather
than from the endpoint under test).

**2. `pkg/rtmr3` → `pkg/runtimemeasure`** (`e0bd7d8`)
Named for the function (runtime workload measurement), not for one vendor's
register. Adds `ForOperatorKey`, deduplicating three hand-rolled copies of
`SHA384(0x00*48 ‖ SHA384(pubkey))`.

**3. `meshCADigest` — config-claims v2** (`df20ca4`, `9bc0ee2`)
CDS's RA-TLS certificate is self-signed and served without a chain, so attesting
CDS proved nothing about which CA it issues under. The claims now commit
`SHA-256(mesh CA DER)`, plus `--mesh-ca` / `--mesh-ca-digest` to pin it.

**4. `allowlistDigest` — config-claims v3, re-issued on change** (`22e75cd`, `172a606`)
`seedDigest` attests boot state. Observed live: the store went version 2 → 7
while the attested digest never moved, so pinning it cannot catch a permissive
entry added after startup — the case a verifier most needs.

Freshness comes from **re-issuance, not a timestamp**: the digest is bound into
REPORTDATA and cannot be updated in place, so `watchAllowlistReissue` swaps the
serving cert whenever the live digest changes. The certificate fingerprint
becomes the cache-invalidation signal — clients cache long-lived and re-attest
exactly when policy moves. No staleness window, so no dial to set wrong.

It polls the version row rather than hooking each mutation: every write path
bumps that row, so a future mutation that forgets a hook cannot bypass it, and a
briefly-lagging certificate is fail-closed anyway (a client hashing
`GET /allowlist` sees a mismatch and refuses).

**5. `discovery.cds_identity` — publish CDS's own certificate** (`2110f42`)
The attest-once step previously **could not happen at all**. `/.well-known/cds-cert.pem`
is `alias /tls/cert.pem` — the **LB's own leaf** — and `cds_tls.certificate_pem`
is that same leaf. Both names mean *"the cert CDS issued to me"*, not *"the cert
of CDS"*; that reading cost real time.

`get-cert` records the certificate it **already verified at issuance** rather
than re-dialling (a second dial could return a different certificate than
issuance actually trusted). `ratls.ClientConfig.OnVerifiedPeer` fires only after
attestation succeeds — the ordering is what the tests assert, since a failed
handshake must never record a certificate that then gets republished as trusted.

---

## Wire-format compatibility

Version bumps, not optional fields: `UnmarshalConfigClaims` demands a byte-exact
round-trip, so an added element is a different encoding by construction. v1 and
v2 still parse, with absent fields reading as `UnsetDigest` — which a real pin
can never match, so **old claims cannot be replayed to satisfy a new property**.
A pre-v3 verifier rejects v3 claims outright rather than silently ignoring a
field. Fail closed, not fail quiet.

---

## How this was tested

Unit + integration: `go test ./...` green, `gofmt` clean, `go vet` clean.

Everything below ran against the **live TDX cluster**, with a CDS image built
from this branch and served from a local registry:

```
allowlist mutated  → cert c385515… → 57ad4fb…      (fingerprint changed)
                     allowlistDigest 12ef98ea… → 7a802012…
                     sha256(raw GET /allowlist)     7a802012…   ← independent check
entry removed      → cert 83196ed…, digest back to 12ef98ea…    ← both directions
meshCADigest       → byte-matches sha256 of the CA fetched independently from CDS /ca
```

Negative cases, all exit 2:

| `--allowlist` real served bytes | ✓ VERIFIED |
|---|---|
| `--allowlist` tampered (extra permissive entry) | ✗ names both digests |
| `--allowlist-digest` junk | ✗ |
| `--mesh-ca` impostor CA | ✗ |
| v2 certificate against a v3 pin | ✗ (unit test) |

**Every pin here got a negative test because a `--mesh-ca` fail-open earlier in
this work passed its positive test happily.** The pin was wired into
`ratls.VerifyPolicy` only, while `c8s verify` enforces claims in its own block in
`newOutcome`; an impostor CA returned VERIFIED. Each new pin is now wired into
**all three** sites — the `VerifyAttestation` guard, `checkClaimsPins`, and the
CLI comparison block — and the code comments say so.

---

## What is missing / known-open

- **`--workload-claims` is off**, and finishing it would not close the identity
  gap people expect. `enforceWorkloadCombination` (`internal/cmds/cds/attest.go:374`)
  matches on the **image-digest set only** — it ignores argv and discards which
  entry matched. Two workload entries sharing a digest and differing only in argv
  (exactly our Kimi-K3 vs Qwen3 setup) produce an **identical `workloadDigest`**.
  Higher-value follow-up: have CDS stamp the **matched workload entry** (name, or
  a digest over its argv). CDS already performs the match and already signs the
  leaf — it just throws the result away.
- **Enabling `--workload-claims` is not a chart change.** It needs (a)
  `workload_claims.socket_dir` in the baked confos NRI config, (b) the operator's
  `--workload-claims-host-dir`, whose chart gate is `nriImagePolicy.enabled` —
  **false** when the plugin is baked into the guest image rather than
  helm-installed — and (c) a containerd restart to create the socket. CDS's side
  is already wired (`cds/run.go:246`).
- **Downgrade**: replaying an old, internally consistent (cert, allowlist) pair
  is not blocked; only the 24h `notAfter` bounds it. Monotonic
  fingerprint tracking is designed, not implemented.
- **`--resolve-digests=true`** (the default, and what the runbook uses) puts a
  `--workload-ref` image into the boot floor, where it is admitted **by digest
  alone regardless of argv** — structurally defeating argv pinning, and restored
  on every CDS restart. `-f` cannot override it: `install.go:1648` uses
  `--set-string`. Worth a separate fix.
- **`cds.persistence.enabled=false`** (the default) silently resets the allowlist
  to the install seed on restart.
- `docs/ratls.md` still describes claims v1.
