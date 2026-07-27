# Secrets broker

How c8s releases application secrets to attested workloads: the CDS brokers
secrets from an internal store to pods whose **attested container-digest set**
is granted them by the allowlist's path policy (`paths`, see
[`allowlist-and-capabilities.md`](allowlist-and-capabilities.md)). This is the
consumer of the `PathPolicy` field the allowlist has carried since
`eb8e4b3`.

> **Trust model.** Unchanged: the host, hypervisor, and Kubernetes control
> plane are untrusted; the trust boundary is the TEE. Two consequences drive
> every choice below. Control-plane data (annotations, pod specs, sidecar
> args) is a *request*, never a grant — grants come only from the attested
> allowlist. And ordinary Kubernetes Secrets/ConfigMaps/PVs are plaintext to
> the control plane, so secrets never touch them: not in etcd, not in env,
> not on a host-readable disk.

## What ships in this PR (and what does not)

Ships: the store interface and an in-memory store, the CDS broker endpoints,
the broker identity, and the `c8s secrets` operator CLI (deposit / read-back /
delete). Adapters to external key managers (openbao, vault, AWS KMS)
implement `secretstore.Store` in their own PRs. Workload-side delivery (the
injected `c8s-secrets` init container and webhook machinery) is the next PR;
the fetch endpoint is exercised by the CLI and tests until then. Workload
runtime **writes** are deferred with their first consumer — the write grants
in policy already have meaning, but no in-pod write path ships yet.

This supersedes the unmerged `split/secret-broker` standalone-broker branch
family (`c8s-secret-broker` Service, `internal/cmds/secretbroker`,
`confidential.ai/secrets-inject`): the broker logic lives **in the CDS**, so
the platform's existing root of trust stays the only root of trust.

## The model

Secrets are scoped by **(workload entry, path)**. A workload entry is the
allowlist's named init/main container set with per-container policy; the
path is a filesystem path the entry grants to a given container digest.

- **Deposit** is operator-only: `c8s secrets put <entry> <path> <value>`,
  authorized by the pinned operator key (the same credential as allowlist
  writes) and wrapped to the broker encryption key in transit.
- **Release** is attestation-gated: a pod proves its TEE, claims its
  init/main container digest set, and receives exactly the paths the
  resolved entry grants to each claimed digest.
- **Grant precision is entry-scoped**, never the per-digest union: the fetch
  gate resolves the claimed set to exactly one entry, mirroring the
  combination gate at cert issuance.

**Tenant rule.** Two entries with identical container sets are one security
domain — anything running that set may claim either entry's secrets.
Per-tenant secrets therefore require a per-tenant digest in the workload set
(e.g. a per-tenant loader image). Identical-set entries with grants are a
configuration error: the broker fails closed (403 `entry_ambiguous`), and
`c8s allowlist lint` flags them at write time.

## The fetch flow

```
pod (c8s-secrets init)                 CDS
─────────────────────                  ───
GET /secrets/broker-identity  ──────►  signing leaf (mesh-CA-issued)
                                       + encryption pubkey (bound by signature)
verify chain against mesh CA
(from get-cert's CA bundle)

POST /authenticate            ──────►  challenge (single-use, 60 s TTL)
ephemeral X25519 keypair
evidence := TEE(REPORTDATA =
  transcript(challenge, request))
POST /secrets/fetch           ──────►  consume challenge
  {challenge, evidence,                VerifyEnforced(evidence, transcript)
   init/main digests,                  measurement pin — FAIL CLOSED when empty
   response_pubkey, requests}          resolve set → exactly one entry
                                       per request: digest ∈ entry,
                                         path ∈ entry's read grants
                                       store.Get(entry, path)
                            ◄──────    wrap to response_pubkey
                                       + sign with broker signing leaf
verify signature; unwrap; stage
```

The transcript mirrors `/attest` (`ratls.ReportDataForKeyAndClaims`): a
domain-separated, length-framed SHA-384
`SHA-384("c8s/secrets-fetch/v1\0" ‖ framed(challenge) ‖ framed(canonical(request)))`,
so the evidence binds the whole release decision — claimed set, response
key, and requested paths.

Grant resolution per `(entry, digest, path)` is the union across the
entry's containers with that digest (the `AdmitsContainer` semantic):
`deny` (default) grants nothing, `any` grants any requested path, `allow`
glob-matches (`/**` is a subtree). Empty `paths: []` yields an empty result.

## Why the broker identity and the wrap exist

`/attest` binds the response to the requester's key: a relayed certificate
is useless to anyone but the keyholder, and a fake CDS's certificates fail
loudly at first mesh use. A secrets fetch has no equivalent by default —
and the default client posture today is TOFU (`--cds-measurements` unset
accepts any attested endpoint), where a fake or relaying CDS would read
every secret and could fabricate responses silently. So:

1. **Response wrap.** The fetch request carries an ephemeral X25519 public
   key bound into the evidence transcript; the response is sealed to it
   (X25519 → HKDF-SHA256 → AES-256-GCM, `pkg/secrets`). A relay learns
   nothing — only the pod holding the ephemeral private key unwraps.
2. **Broker identity.** At startup CDS issues itself a signing leaf from
   the mesh CA (in-process) plus an X25519 encryption key bound to that
   leaf, served at `GET /secrets/broker-identity`. Clients verify the chain
   to the mesh CA (the pod's get-cert bundle; the CLI's `/ca` read) before
   trusting responses or depositing values. A same-measurement fake CDS can
   copy config, but it cannot hold the mesh CA key, so it cannot mint this
   identity.
3. **Hard measurement pin.** `/secrets/fetch` fails closed when
   `cds.measurements` is empty — unlike `/attest`, where the documented
   "pin nothing yet" posture degrades to loud failures, secrets degrade
   silently.

Deposits are likewise wrapped to the broker encryption key, so a fake
broker never sees operator plaintext either.

## The store

`internal/secretstore.Store`:

```go
type Ref struct{ Entry, Path string }
type Store interface {
    Get(ctx context.Context, ref Ref, requester types.Digest) ([]byte, error)
    Set(ctx context.Context, ref Ref, value []byte) error
    Delete(ctx context.Context, ref Ref) error
}
```

`Get` receives the requesting container digest so per-caller backends
(leased credentials) are expressible; single-value stores ignore it. The
shipped implementation is in-memory, last-write-wins.

**Durability posture.** The store is deliberately not persisted: a PV of
plaintext is host-readable, and etcd is plaintext to the control plane.
Consequences, by design: a CDS restart loses deposited secrets (re-deposit
with the CLI); secrets do not ride `/handoff`; staged pods keep what they
staged. A durable, attested-backend store is an adapter-PR concern.

## Endpoints

| Route | Caller | Gate |
|---|---|---|
| `POST /secrets/fetch` | workload init container | challenge + evidence + measurement pin (fail-closed empty) + entry resolution + per-(digest, path) grant |
| `GET /secrets/broker-identity` | any client | none — integrity from the chain to the mesh CA |
| `PUT /secrets/entries/{entry}/paths/{path}` | operator CLI | operator JWT (body-bound), value wrapped to broker encryption key |
| `GET /secrets/entries/{entry}/paths/{path}?pubkey=` | operator CLI | operator JWT; response wrapped to the query's ephemeral key |
| `DELETE /secrets/entries/{entry}/paths/{path}` | operator CLI | operator JWT |

Errors use the standard envelope with these codes: `invalid_challenge`,
`verification_failed`, `measurement_denied`, `measurement_not_configured`,
`grant_denied`, `entry_ambiguous`, `secret_not_found`. Metrics:
`c8s_cds_secrets_fetch_total{result}`, `c8s_cds_secrets_operator_total{op,result}`.
Audit logs record entry, path, caller digest, launch digest, decision, and
value *size* — never values.

## Security posture

**Strong.** Fake/relay brokers read nothing and fabricate nothing (wrap +
mesh-CA-anchored identity + hard pin). The control plane cannot fetch with
its own identity — it has no TEE evidence. Non-allowlisted code can never
run and therefore never fetch. Grants are entry-scoped per (digest, path);
annotations and specs are requests only. Plaintext exists only in CDS
process memory (the release hop), pod tmpfs (in-TEE RAM), and the
requester's view — never etcd, env, or PV.

**Residual — claim forgery (Corner-5 class).** Any admitted workload can
run the fetch flow itself and claim *any allowlisted digest set*: CDS
verifies the evidence and the allowlist membership of the claim, not that
the claim reflects what the pod runs (the same gap as
[`getcert-workload-binding.md`](getcert-workload-binding.md) Corner 5, and
the allowlisted-image fetch-proxy vector is exercisable by the control
plane with no workload cooperation). The impact escalates from "satisfies a
verifier pin" to "exfiltrates secret material" — and write-poisoning joins
it when workload writes ship. The closes are measured-digest consumption
(TDX RTMR3 event-log verification at CDS) and/or SPIFFE-style agent
identity, both tracked follow-ons; SNP has no runtime-extend register, so
the SNP close is the identity work. This residual is catalogued in
[`THREAT_MODEL.md`](THREAT_MODEL.md) §5 (Addressable).

**Operator mitigations today.** Keep the allowlist tight: floor images
admit argv-blind, and any permissive-argv image is a potential fetch
proxy. Secrets-bearing containers should pin argv exactly (lint enforces a
warning; treat it as an error). Pin `cds.measurements` — the broker
refuses to serve without it.

## CLI

```
c8s secrets put <entry> <path> <value|@file|->   # deposit (wrapped, operator-signed)
c8s secrets get <entry> <path>                   # read-back (stdout raw; -o json for base64)
c8s secrets delete <entry> <path>                # remove
```

Persistent flags mirror `c8s allowlist`: `--url`, `--measurements` /
`--measurements-file`, `--timeout`, `--operator-key` (or
`C8S_OPERATOR_KEY`), `-o text|json`, `--insecure`. The CLI verifies the
broker identity against the `/ca` bundle before any value crosses the
wire.

## Operator checklist

1. Add path grants to the workload entry (`c8s allowlist workload edit`):
   `paths: {policy: allow, read: ["/secrets/model/**"]}`. Keep argv exact;
   lint warns otherwise.
2. Deposit: `c8s secrets put vllm-llama /secrets/model/dek @dek.bin`.
3. (Next PR) annotate pods: `confidential.ai/c8s-secrets-read-vllm:
   /secrets/model/dek`, all images digest-pinned.
