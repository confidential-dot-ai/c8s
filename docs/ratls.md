# RA-TLS: how c8s components authenticate each other

RA-TLS (Remote Attestation TLS) is ordinary TLS 1.3 with one substitution: a
peer is trusted not because its certificate chains to a CA, but because the
certificate itself carries hardware attestation evidence proving that the TLS
key was generated inside a genuine TEE running measured code. Every trust
decision in c8s that crosses a machine boundary — mesh traffic between pods,
certificate issuance, allowlist reads, CA handoff — rides on it.

This doc walks the process step by step: what is in an RA-TLS certificate, how
a handshake verifies it, how the self-signed bootstrap regime upgrades to
CDS-issued certificates, what the whole construction does and does not
guarantee, how it operates under the two confidential shapes (node-as-CVM and
pod-as-CVM), and which certificate is used where.

Companion docs: [THREAT_MODEL.md](THREAT_MODEL.md) (adversaries, gates,
residual risk), [`cmd/ratls-mesh/DESIGN.md`](../cmd/ratls-mesh/DESIGN.md) (mesh
dataplane), [install-flows.md](install-flows.md) (which components deploy in
which mode).
The implementation is [`pkg/ratls`](../pkg/ratls/), with the CDS client flow in
[`pkg/attestclient`](../pkg/attestclient/) and
[`pkg/ratls/cdsclient`](../pkg/ratls/cdsclient/).

## The idea: bind a TLS key to the hardware root of trust

A TEE (AMD SEV-SNP or Intel TDX guest) can ask its hardware for an
**attestation report**: a structure, signed by a key fused into the CPU, that
contains the guest's **launch measurement** (a digest of exactly what booted)
and 64 bytes of caller-chosen **REPORTDATA**. c8s puts a hash of a
freshly-generated TLS public key into REPORTDATA. The signed report then says,
with the silicon vendor's authority: *this public key belongs to a key pair
created inside this measured guest*.

```text
AMD ARK ──signs──▶ ASK ──signs──▶ VCEK  (per-chip key, TCB-versioned)
(root, in verifier)                  │
                                     │ signs
                                     ▼
                          ATTESTATION_REPORT
                          ├─ MEASUREMENT: launch digest of the guest
                          ├─ REPORTDATA:  SHA-384(TLS pubkey ‖ nonce)
                          └─ policy bits: debug, TCB level, ...
                                     │
                                     │ binds (hash match)
                                     ▼
                          ECDSA P-256 TLS key pair
                          (generated in TEE memory, never on disk)
                                     │
                                     │ authenticates (TLS 1.3 handshake)
                                     ▼
                          the TLS session
```

For TDX the chain is the Intel equivalent (provisioning certification chain →
Quoting Enclave signs the quote) and the pinned measurement is MRTD. Everything
downstream is platform-agnostic.

Because trust flows from the hardware chain, the certificate's own signature is
irrelevant: RA-TLS certificates are self-signed, and the verifying side sets
`InsecureSkipVerify: true` and does all real verification in a
`VerifyPeerCertificate` callback (`pkg/ratls/tls.go`). A compromised network,
control plane, or host cannot mint a passing certificate — only the hardware
can sign a report, and only code inside the TEE ever holds the private key.

## Anatomy of an RA-TLS certificate

`pkg/ratls` builds certificates like this (`cert.go`, `extension.go`,
`provider.go`):

1. **Key generation.** An ECDSA P-256 key pair is generated in process memory.
   It is never written to disk and never leaves the TEE.
2. **Key→report binding.** `REPORTDATA = SHA-384(PKIX-DER(pubkey) ‖ nonce)`,
   zero-padded to the 64-byte REPORTDATA field (same layout on SEV-SNP and
   TDX). The nonce is optional on mesh handshakes (TLS 1.3 already prevents
   replay of the *session*) and mandatory in the CDS issuance flow (it proves
   report freshness). Certificates always use this plain binding
   (`ReportDataForKey`). One flow folds extra context in — the CDS handoff's
   operator-key commitment (`ReportDataForKeyWithContext`) — as a
   domain-separated, length-framed transcript,
   `SHA-384("c8s-report-data-context-v1\0" ‖ framed(pubkey) ‖ framed(nonce) ‖ framed(context))`
   with `framed(x) = uint64-BE(len(x)) ‖ x`, so no two distinct field triples
   share a preimage.
3. **Evidence.** The component asks its **local attestation-api** (`POST
   /attest`, the Rust service from
   [attestation-rs](https://github.com/confidential-dot-ai/attestation-rs))
   for evidence over that REPORTDATA. The hardware signs the report inside the
   TEE.
4. **Certificate.** A self-signed X.509 certificate is created with the
   evidence embedded as a custom extension:

   ```text
   OID 1.3.6.1.4.1.66378.1.1  (RA-TLS attestation extension)
   TEEAttestation ::= SEQUENCE {
       teeType     INTEGER,      -- 1 = SEV-SNP, 2 = TDX
       report      OCTET STRING, -- evidence, two shapes (below)
       certChain   OCTET STRING  -- optional inline VCEK chain
   }
   ```

The full `1.3.6.1.4.1.66378.1` arc a c8s certificate may carry:

| OID | Extension | Stamped by |
|---|---|---|
| `…1.1` | RA-TLS attestation (`TEEAttestation`, above) — `extension.go` | the attesting component, on its own certificate and on its CSR |
| `…1.2` | SHA-256 audit digest of the issuance evidence — `pkg/certutil` | CDS, on every issued leaf |
| `…1.4` | pod sandbox ID — `sandbox.go`, see [Sandbox identity](#sandbox-identity-which-workload-is-behind-a-key) | CDS, on a leaf whose requester presented a sandbox token |

`…1.3` was the config-claims extension; it is retired and not reusable.

The `report` field carries one of two shapes, auto-detected on parse
(`extension.go`):

- **Bare-metal SNP**: the raw 1184-byte `ATTESTATION_REPORT`. Kept raw so a
  bare-metal report stays extractable by offline SNP verifiers.
- **Everything else** (`az-snp`, `gcp-snp`, `tdx`, `az-tdx`): the attestation-api's
  JSON evidence envelope, forwarded verbatim to `/verify` at handshake time. Both
  TDX shapes must use the envelope (c8s deliberately ships no in-process quote
  parser — see `verify.go`): native `tdx` carries a bulky `cc_eventlog` that is
  stripped before embedding, while Azure-vTPM `az-tdx` (the TD quote wrapped in the
  HCL report, alongside the vTPM quote) has no eventlog and is embedded as-is.
  Azure evidence wrapped in a Hyper-V HCL header is normalized back to the raw
  report where needed (`snp_report.go`).

Certificates live 24h by default and rotate in the background at 50% of TTL;
the old certificate keeps serving until the new one is provisioned, so an
attestation-api hiccup degrades rotation, not traffic (`tls.go`).

## The handshake, step by step

Both sides of a mesh connection run the same logic; the diagram shows one
direction. "attestation-api" is always the verifier's **own, same-TCB**
instance — never one across the network (see Guarantees).

```text
   A (dialer)                                B (listener)
   ──────────                                ────────────
1. TCP connect ────────────────────────────▶
2.             ◀───────────────────────────  TLS 1.3 ServerHello + leaf cert
                                             [ext 1.3.6.1.4.1.66378.1.1:
                                              report with REPORTDATA =
                                              SHA-384(B's pubkey)]
3. parse cert, extract extension
4. POST /verify to A's LOCAL attestation-api:
     { evidence, expected REPORTDATA,
       allow_debug, min_tcb }
   ◀── verdict: hardware chain valid,
       REPORTDATA matches, policy holds,
       launch digest = M
5. require M ∈ measurement allowlist
6. client cert ────────────────────────────▶ mTLS: B runs steps 3–5 on
                                             A's certificate
7. ◀═════════ application bytes, TLS 1.3 ═════════▶
```

Step by step:

1. **Server certificate provisioning is lazy and cached.** The first handshake
   triggers key generation + attestation (steps 1–4 of "Anatomy"); later
   handshakes reuse the cached certificate until rotation.
2. **The client sends no PKI trust anchors.** `NewClientTLSConfig` sets
   `InsecureSkipVerify: true`; `VerifyPeerCertificate` does the work.
3. **Extension extraction.** Missing extension → `ErrNotAttested`, connection
   refused (unless the CA-chain path applies — see dual verification below).
4. **Delegated verification.** The verifier computes the REPORTDATA it
   *expects* from the peer certificate's public key, then forwards evidence +
   expectation + policy to its local attestation-api `POST /verify`. The
   attestation-api checks the hardware signature chain (ARK→ASK→VCEK for SNP,
   Intel collateral for TDX), the REPORTDATA match (key binding), the debug
   policy (`AllowDebug`, default reject), and the minimum TCB (SNP only).
   There is **no in-process verification fallback**: no reachable
   attestation-api means no connection (fail closed).
5. **Measurement policy.** The verified launch digest returned by the
   attestation-api is compared against the caller's allowlist
   (`VerifyPolicy.Measurements`; SNP LAUNCH_DIGEST or TDX MRTD, 48 bytes). An
   **empty allowlist accepts any genuine TEE** — deliberate bootstrap
   ergonomics, loudly warned, and unsafe in production
   ([THREAT_MODEL.md](THREAT_MODEL.md) §5 Open).
6. **mTLS.** Servers configured with a `ClientPolicy` require a client
   certificate and verify it the same way (steps 3–5, roles swapped).

Verification failures map to typed sentinels (`errors.go`):
`ErrSignatureInvalid` (hardware chain), `ErrKeyBinding` (REPORTDATA mismatch —
the key was not generated in that TEE), `ErrPolicyViolation` (measurement not
allowlisted), `ErrNotAttested`, `ErrInvalidReport`, `ErrUnsupportedTEE`.

## From self-signed to CA-issued: the CDS regime

Self-signed RA-TLS needs zero infrastructure, but it verifies hardware
evidence on **every** handshake (with an attestation-api round trip), and it
gives relying parties no revocable, nameable identity. The Certificate
Distribution Service (CDS) layers a conventional CA on top — with the twist
that a CSR is signed **only after** the requester proves, via the same RA-TLS
evidence flow, that its key lives in an attested, measurement-allowlisted TEE.
"Bind identity to measurement": no verified measurement, no certificate.

```text
   requester                        CDS                    local attestation-api
   (get-cert / ratls-mesh)          ───                    ─────────────────────
   ──────────────────────
1. POST /authenticate ────────────▶
   ◀──────────────────────────────  challenge (single-use, 32 B, TTL-bound)
2. generate P-256 key + CSR
   (SAN = workload id / node)
3. REPORTDATA =
   SHA-384(CSR pubkey ‖ challenge)
   POST /attest (REPORTDATA) ─────────────────────────────▶
   ◀───────────────────────────────────── TEE evidence bound to key+challenge
4. POST /attest
   { challenge, evidence, CSR } ──▶
                                    verify evidence (CDS's own
                                    same-TCB attestation-api),
                                    enforce cds.measurements,
                                    validate SAN / CN policy,
                                    sign CSR with the mesh CA
   ◀──────────────────────────────  leaf certificate chain + CA bundle
```

Properties worth noting:

- **The transport for steps 1 and 4 is itself RA-TLS.** CDS self-provisions an
  RA-TLS serving certificate bound to its own launch measurement; clients pin
  it with `--cds-measurements`. The challenge–response plus the RA-TLS channel
  close the bootstrap window against a pod-network impostor — *iff*
  measurements are pinned.
- **The mesh CA private key exists only in CDS process memory** (P-384, CN
  `c8s Mesh CA`, 1-year validity, generated at startup). It is never a
  Kubernetes Secret, never on disk. With `cds.handoff.enabled`, a replacement
  replica adopts the CA from the surviving peer over the attested `/handoff`
  flow — the key crosses the wire only as recipient-encrypted ciphertext
  (X25519-ECDH → HKDF-SHA256 → AES-256-GCM, gated on both sides' EAR
  measurements and operator-key-policy equality). Without handoff, a
  (singleton) CDS restart mints a fresh CA and workloads re-bootstrap; see
  THREAT_MODEL.md §9.
- **Issued leaves are capped at 24h** and always carry a SHA-256 digest of
  the issuance evidence as an audit extension. When the CSR itself embeds an
  RA-TLS extension — the mesh client and get-cert both do, bound to the bare
  key with no nonce — it is copied into the leaf, which is what keeps the
  attestation fallback working on CDS-issued certs (`internal/issuer/sign.go`).
- **The challenge is the freshness proof.** Single-use and TTL-bound
  server-side; REPORTDATA commits to it, so recorded evidence cannot be
  replayed into an issuance.
- **CA bundle distribution is continuity-checked.** `GET /ca` is deliberately
  unauthenticated; consumers seed trust from the *authenticated* issuance
  response and afterwards accept only bundle updates signed by an
  already-trusted CA (`pkg/ratls/cdsclient`). A MITM'd `/ca` read cannot
  inject a new root.
- **EAR tokens, not certs, for key-only attestation.** `POST /attest-key`
  runs the same challenge/evidence flow but returns a signed EAR JWT (ES256,
  JWKS at `/.well-known/jwks.json`) for a caller-held key instead of signing
  a CSR. Callers already holding an EAR can have a CSR signed via
  `POST /sign-csr`. Used by CDS's own handoff machinery.
- **The serving certificate commits only CDS's key and measurement** — not its
  operator-key set, not its allowlist seed. A verifier cross-checks the key set
  CDS *serves* at `/operator-keys`, fetched over that attested serving cert
  (`c8s cds verify --operator-keys`). The operator-key set is REPORTDATA-bound
  only on the `/handoff` and `/attest-key` paths
  (`ReportDataForKeyWithContext`).

### Dual verification and the upgrade path

Peers configured with a CA bundle accept **either** proof
(`dualVerifyPeerCallback`, `tls.go`):

1. **CA chain** (fast path): standard X.509 verification against the mesh CA
   bundle. No attestation-api call, no KDS dependency, per-connection cost is
   plain TLS.
2. **RA-TLS attestation** (fallback): the full evidence verification above.

This is what makes the bootstrap order-free: ratls-mesh boots self-signed with
no CDS dependency, a background goroutine obtains a CDS-issued certificate
(exponential backoff) and hot-swaps it via `CertManager.SwapProvider` — old
cert serves until the new one is ready — and mixed fleets interoperate
throughout. The multi-cert CA pool also absorbs CA rotation: old and new CA
coexist for the transition window, updated at runtime from `/ca` polling
(`DynamicCACert` + `UpdateCACerts`).

The trade to know about: a CA-chain-verified peer proved its measurement **at
issuance time**, not at handshake time — such a peer is "chains to the mesh
CA", not "runs launch digest X". `VerifyPolicy.RequireCAEvidence` is the
mechanism that would close the gap: it makes a valid chain insufficient and
re-verifies the leaf's copied nonce-free `.1.1` evidence per connection,
measurement allowlist included. **No profile sets it today**, so the gap is
open in practice — see [THREAT_MODEL.md](THREAT_MODEL.md) §5 Addressable.

## What RA-TLS guarantees — and what it does not

A successful handshake against a pinned policy proves, assuming the
[THREAT_MODEL.md](THREAT_MODEL.md) §6 assumptions hold:

1. **Genuine TEE.** The peer's evidence was signed by real AMD/Intel silicon —
   a hypervisor, control plane, or network attacker cannot forge it.
2. **Key residency.** The peer's TLS private key was generated inside that
   TEE (REPORTDATA binds the key), so nothing outside the encrypted guest —
   including the host — can hold or exfiltrate it.
3. **Code identity.** The guest booted exactly an allowlisted image: its
   launch digest (SNP LAUNCH_DIGEST / TDX MRTD) is in the verifier's pinned
   set. *This guarantee only exists when measurements are pinned.*
4. **Runtime policy floor.** Debug-mode guests are rejected by default;
   on SNP a minimum TCB (microcode/SNP firmware level) can be enforced.
5. **Channel security.** TLS 1.3 with ephemeral key exchange protects
   confidentiality and integrity; certificates rotate halfway through their
   TTL (24h default).
6. **Issuance freshness** (CDS flow): the challenge nonce in REPORTDATA
   prevents replaying recorded evidence into new certificates.

What it does **not** guarantee:

- **Nothing, with an empty measurement allowlist.** Any genuine TEE — including
  an attacker's own CVM on the pod network — is accepted. Both CDS and
  ratls-mesh ship with empty pins, warn loudly, and export
  `ratls_mesh_measurement_pinning=0` for alerting. Pinning is the operator's
  explicit production step.
- **A trustworthy verdict from an untrusted verifier.** The attestation-api's
  `/verify` response is **unsigned**; whoever can impersonate the configured
  `AttestationApiURL` forges "valid". Every deployment therefore keeps the
  verifier in the same TCB as the verifying component: a same-node DaemonSet
  behind `internalTrafficPolicy: Local` (node-as-CVM) or an in-guest loopback
  service (pod-as-CVM). Do not point it across a trust boundary.
- **Per-handshake measurement of CA-verified peers.** See "Dual verification"
  above: after the CDS upgrade, mesh peers are verified by CA chain only.
- **Full TDX runtime measurement.** Policy pins MRTD; RTMR[0..3] are not yet
  pinned, and `MinTCBVersion` is dropped on the TDX path (GAPS).
- **Workload-granular identity beyond the TEE boundary.** The unit of
  hardware attestation is the TEE: the whole node in node-as-CVM, one pod under
  pod-as-CVM. The sandbox ID narrows this — a leaf names the pod sandbox CDS
  issued it to, and CDS issues only after the sandbox's own inventory reports
  images that are all allowlisted (see Sandbox identity) — but that ID is
  vouched by the mesh CA signature, not by hardware evidence, and it is only as
  good as the inventory's honesty about what it admitted. The gate is
  membership, not composition, so it does not say the pod runs one particular
  workload. Enforcing per-workload measurement at `/attest` is unimplemented
  (GAPS §Trust model).
- **Post-boot integrity.** The launch digest covers boot state; runtime
  compromise inside a measured guest is out of scope (that is the image
  allowlist and guest lockdown's job — [kata-image-policy.md](kata-image-policy.md)).
- **Availability.** A hostile host can always refuse service; RA-TLS turns
  host compromise into DoS, not data exposure.

## Sandbox identity: which workload is behind a key

The attestation so far binds the *key* and the *launch measurement* — the image
that booted. It says nothing about **which workload** stands behind a mesh key
when the TEE holds more than one. A CDS-issued leaf names the **CRI pod
sandbox** it was issued to:

```text
OID 1.3.6.1.4.1.66378.1.4  (pod sandbox ID extension)
SandboxID ::= IA5String     -- e.g. containerd's 64-hex sandbox ID
```

The **inventory** is the component that admitted the pod's containers —
nri-image-policy on node-CVM, policy-monitor inside the kata guest — so it is
the arbiter of both which sandbox a process belongs to and what runs in that
sandbox. It serves two disjoint surfaces (`pkg/workloadclaims`):

| Surface | Route | Listener | Caller bound by |
|---|---|---|---|
| tokens | `POST /sandbox` | node-CVM: a node-local Unix socket. kata: the guest's loopback `127.0.0.1:8401` (`workloadclaims.GuestTokenPort`) | node-CVM: kernel peer credentials (`SO_PEERCRED` + `SO_PEERPIDFD`). kata: the guest boundary — one pod per guest, so there is no caller to disambiguate |
| identity + digests | `GET /identity`, `GET /digests/{sandboxID}` | `:1019` (`workloadclaims.DigestsPort`), mutually-attested RA-TLS | the client leaf's launch measurement (CDS's) |

The token surface cannot enumerate other sandboxes; the network surface cannot
mint identity.

### The privileged port is the inventory's identity

`DigestsPort` is a compiled constant, not a deployment value, and it is
privileged (`< 1024`, IANA-unassigned). Binding it requires the node's own
network namespace, which the chart's `deny-host-namespaces`
ValidatingAdmissionPolicy withholds from tenant pods
(`hostNamespacePolicy.enabled`, on by default). A pod can bind any port inside
its own netns, so an unprivileged port would let any workload answer as the
inventory.

That is what CDS's trust in the sandbox-token signing key rests on, because
measurement cannot make the distinction: on node-CVM every pod shares the node's
launch digest, so "attested TEE on an allowed measurement" is satisfied by every
tenant. "Answers on `:1019` in the node's network namespace, at an address inside
an operator-configured node CIDR" is not.

Two things this rests on that attestation does not enforce:

- the ValidatingAdmissionPolicy (or an equivalent PodSecurity floor) holds. It
  is a values flag, and it exempts the release namespace and `kube-system`.
- privileged node DaemonSets — CNI, CSI, the NVIDIA GPU operator — *can* bind
  the port. They are already root inside the node CVM and can read another
  pod's memory directly, so they are effectively part of the node's TCB;
  sandbox identity does not narrow that set.

### The sandbox token

get-cert fetches the CDS challenge for this issuance first, then POSTs its CSR
public key and that challenge to `/sandbox`. The inventory resolves the
*caller's* identity to a sandbox — nothing the caller sends names the pod — and
signs

```text
SandboxToken ::= SEQUENCE {
    version        INTEGER,            -- 2
    sandboxId      IA5String,
    keyDigest      OCTET STRING (32),  -- SHA-256(requester PKIX pubkey DER)
    nonce          OCTET STRING,       -- the CDS challenge for this issuance
    inventoryHost  IA5String           -- IP of the node/guest serving :1019
}
```

with an in-process P-256 key. The signature is ECDSA over
`SHA-256("c8s/sandbox-token/v1\0" ‖ tokenDER)`, and the envelope
(`workloadclaims.SignedSandboxToken`) is just `token` and `signature`: it
carries **no** credential for the signing key. CDS resolves the key by dialing
`GET /identity` at the signer's own privileged port.

`inventoryHost` is an IP only — the port is not carried, since CDS holds it. The
key is never persisted; an inventory restart mints a new one, which CDS picks up
because it re-reads `/identity` on every issuance rather than caching a
credential.

### Issuance

get-cert forwards the envelope opaquely in the `/attest` request body
(`sandbox_token`). **It never reports its pod's images.** CDS then, in order
(`internal/cmds/cds/attest.go`):

1. reads `inventoryHost` out of the *unverified* token
   (`workloadclaims.UnverifiedInventoryHost`). The host names the endpoint
   holding the key that would verify the signature, so it has to be read before
   verification can happen; it is trusted for nothing else. It only selects a
   dial target, and a wrong value simply yields a key the signature fails under.
2. requires that host to be a routable unicast IP literal (no names — DNS would
   decide the destination after the check — and no loopback, link-local/IMDS,
   multicast, or unspecified address) inside a CIDR the operator configured with
   `--sandbox-inventory-cidr`. Unset means CDS refuses every request carrying a
   sandbox token. A pod's IP is in the pod CIDR, so a workload cannot name
   itself as its node's inventory.
3. fetches the signing key from `https://<host>:1019/identity` over
   mutually-attested RA-TLS (`workloadclaims.DigestsClient.InventoryKey`,
   pinning the same measurement allowlist `/attest` uses and presenting CDS's
   own RA-TLS certificate).
4. verifies the token signature under that key, requires `version == 2`,
   requires `nonce` to be the same single-use challenge it is consuming for this
   request, requires `keyDigest` to name the CSR key — whose possession the CSR
   signature and evidence binding already prove — and requires the sandbox ID to
   be syntactically valid.
5. verifies the requester's evidence, measurement, and CSR policy as usual.
6. asks `GET /digests/{sandboxID}` at the same endpoint and gates issuance on
   the answer: every image the sandbox is running must be allowlisted.
7. stamps the sandbox ID into the leaf's signed area
   (`internal/issuer/sign.go`).

So the ID is redeemable only by the get-cert holding the bound key, usable only
for the one issuance whose challenge it carries — no clock, no replay window —
and signed by a key that answered on a privileged port inside the operator's
node range. An unreachable inventory, an unknown sandbox, or a non-allowlisted
image refuses the certificate, and so does an **empty** digest set — a sandbox
always runs at least the sidecar that is asking, so an empty answer is no
evidence at all rather than "nothing to check". A request carrying no token gets
a leaf with no sandbox ID.

Because the digests are fetched live from the admitting component rather than
reported by the requester, the binding holds at **first** issuance: get-cert's
own sidecar container is already tracked when it asks for the token, and step 6
reads whatever the sandbox is running at that instant.

The gate is **membership only** — it does not require the running set to match a
whole workload entry. Issuance lands at arbitrary points in the pod lifecycle
(a user init container running, main containers coming up one at a time, one
restarting, completed init containers reaped), and in each the running set is a
strict subset of what the pod declares. Requiring the whole set would deny
ordinary lifecycle states, permanently so once init containers are reaped.
Membership is subset-safe, so it holds in all of them.

The consequence: a leaf's sandbox ID says *this key belongs to pod X*, not *pod
X runs exactly workload Y*. Whole-set enforcement belongs where the pod is
complete and the stake is high — secrets release — and is not implemented yet.
Per-container digest and argv policy is still enforced continuously at
admission by nri-image-policy / policy-monitor
([allowlist-and-capabilities.md](allowlist-and-capabilities.md)).

### What vouches for the ID

The sandbox ID rides the leaf's **signed area**; it is **not** folded into
REPORTDATA. The mesh CA signature, not the hardware evidence, is what
authenticates it. The verifier encodes that:

- `ratls.VerifyCert` and `ratls.VerifyAttestation` **fail closed** when
  `VerifyPolicy.SandboxID` is set — neither checks CA provenance.
- The pin is enforced only on the CA-verified branch of
  `dualVerifyPeerCallback` (`checkSandboxPin`, `verify.go`), after the chain
  verifies against the CA pool.

A self-signed RA-TLS peer can put any string in the extension and must never
satisfy a pin.

**Residual trust.** The key's provenance is "answered on `:1019` at an address
inside a configured node CIDR, over RA-TLS on an allowed measurement". That
narrows to a *node*, not to a process: anything able to bind that port on a node
— the inventory, or a privileged node DaemonSet — can sign for any sandbox that
node admitted. Under kata each guest holds one pod, and the token's host selects
which guest CDS asks, so a cross-guest forgery fails. Fleet-wide the residual is
a peer node: it shares the launch measurement, and the threat model already
grants the host the ability to serve its own TEE attestation on the pod network,
so a hostile node could in principle answer for a node whose traffic it can
intercept ([getcert-workload-binding.md](getcert-workload-binding.md),
Corners 6–7).

### Reading a peer's sandbox ID

Pinning answers "is this peer *X*?"; a relying party often needs "*which*
workload is this?" — to authorize, route, or log.
`ratls.PeerSandboxID(*tls.ConnectionState)` returns a verified peer's sandbox
ID off a live connection (an HTTP server passes `r.TLS`), or `""` when the leaf
carries none. It reads the extension and does **not** re-verify. Call it only
on a connection your verify callback admitted, and only where that callback had
a CA pool: on the attestation fallback the extension is peer-chosen and means
nothing.

### Verifying from outside

`c8s verify --sandbox-id <id>` pins the ID and **requires** `--mesh-ca`, a PEM
bundle the target's leaf must chain to — that chain is what authenticates the
reported ID. Whenever the evidence verifies and the leaf carries an ID, the
verdict reports `sandbox_id` alongside a `sandbox_id_note` naming what stands
behind it ("not verified: … pass `--mesh-ca`" or "verified: the leaf chains to
the supplied mesh CA"), so an unqualified ID never reads as attested.

### Deployment

Both shapes are wired.

- **node-CVM.** nri-image-policy — a host process containerd launches, not a pod
  — serves the token socket in `nriImagePolicy.hostPaths.runtimeDir`, which the
  webhook mounts read-only into the `c8s-cert` sidecar, and `/identity` +
  `/digests` on `:1019`. The node IP it signs into tokens comes from the
  installer DaemonSet's downward API `status.hostIP`, written to a `node-ip`
  file beside the socket; `nriImagePolicy.sandboxDigests.advertiseHost`
  overrides it. Route inference is the last resort and is wrong under the
  chart's own default, since the plugin dials the CDS NodePort over loopback.
- **kata.** policy-monitor serves the token route on the guest's loopback
  `127.0.0.1:8401` and the digests routes on `:1019` inside the guest. No
  socket, no mount, and no configuration selects it: the port is compiled, so
  the untrusted host cannot disable the binding by withholding a value.
  `$C8S_SANDBOX_DIGESTS_ADVERTISE_HOST` overrides the advertised guest IP.

get-cert picks the shape with `--workload-claims-guest`, which the webhook
injects under kata (and then injects no socket volume). Both endpoints are
compiled in, so the flag selects a shape and never an address: a wrong setting
fails closed against a port nothing serves.

CDS must be able to reach every node and kata guest on `:1019`, and
`cds.sandboxInventoryCIDRs` (`c8s install --node-cidr`) must cover those
addresses — unset means CDS refuses any request carrying a sandbox token.

An empty measurement allowlist does not disable any of this — it tracks the same
posture `/attest` takes (see "What RA-TLS guarantees"): both ends still require
a hardware-attested RA-TLS peer, they just pin no measurement, so any TEE can
answer as the inventory and any TEE can read what a node runs. Both ends log it
as UNSAFE outside development. The token verification and the issuance-time
allowlist gate are unaffected. A `--measurements` entry that is not hex fails
CDS startup rather than silently unpinning the callback.

What does disable the callback is a CDS with no `--ratls-platform`: it has no
RA-TLS identity to present, so it makes no callback and **refuses** any request
carrying a sandbox token. In the kata guest, CDS measurements that fail to
*parse* (a typo, as opposed to being unset) disable tokens and get-cert issues
without a sandbox ID; on node-CVM the same typo fails the plugin's config
validation at startup.

A digests endpoint that fails to start is logged, not fatal, on both
inventories: containerd sets `required_plugins`, so a plugin exit takes
container creation down node-wide, whereas a missing digests endpoint only
degrades issuance — CDS refuses the tokens it cannot check.

### Cross-implementation note

A non-Go verifier (e.g. `c8s-verify-js`) reading a sandbox ID needs only the DER
IA5String at OID `1.3.6.1.4.1.66378.1.4` plus a mesh-CA chain check — the ID is
not part of any hash preimage, so there are no canonical-serialization traps.
The token and digests formats above are internal to the inventory↔CDS path and
are never presented to a relying party.

## Operation under the two confidential shapes

The RA-TLS machinery is identical in both shapes; what changes is **where the
TEE boundary sits**, and therefore where the components run, which device
evidence comes from, and what one attested identity covers.

```text
NODE-AS-CVM — one TEE, one identity, per node
╔═ node CVM (SEV-SNP/TDX guest; measured IGVM+UKI+dm-verity boot) ══════╗
║  workload pods (runc) ─┐ get-cert sidecars                            ║
║  ratls-mesh DaemonSet ─┼─ shares the NODE's TEE identity              ║
║  CDS (one pod)        ─┘                                              ║
║  attestation-api DaemonSet ── evidence from the node's TEE device     ║
║    (/dev/sev-guest, TDX TSM configfs, or vTPM on AKS)                 ║
╚═══════════════════════════════════════════════════════════════════════╝
   host / hypervisor: untrusted, sees ciphertext

POD-AS-CVM (kata) — one TEE, one identity, per pod
   host: ADVERSARIAL — operator+webhook, containerd, kata-shim,
         kata-deploy, image puller all run here, outside every TEE
╔═ workload pod CVM (kata-qemu-snp/tdx; measured guest image) ══════════╗
║  workload container(s) + get-cert sidecar                             ║
║  ratls-mesh (in-guest systemd service)      ┐ baked into the          ║
║  attestation-service @ 127.0.0.1:8400       ├ dm-verity rootfs —      ║
║  policy-monitor                             ┘ inside the measurement  ║
╚═══════════════════════════════════════════════════════════════════════╝
╔═ CDS pod CVM ═════════════════╗  ╔═ tls-lb pod CVM ══════════════════╗
║  same baked stack + CDS       ║  ║  same baked stack + nginx/attest  ║
╚═══════════════════════════════╝  ╚═══════════════════════════════════╝
```

### Node-as-CVM (base layout on CVM nodes)

The whole Kubernetes node is one confidential VM; pods are ordinary runc
containers inside it. (This is the base component layout — `c8s install` with
`--cvm-mode node|gke|aks` wiring the right TEE device — deployed onto nodes
that are themselves CVMs. Base on non-CVM nodes has the same layout and no
confidentiality.)

- **Evidence source:** the per-node attestation-api DaemonSet mounts the host
  TEE interface (`/dev/sev-guest`; TSM ConfigFS reports on TDX hosts; vTPM on
  AKS). Its Service uses `internalTrafficPolicy: Local` so `/attest` always
  produces evidence for the *caller's own node* — and so `/verify` verdicts
  never cross a node boundary.
- **RA-TLS endpoints:** ratls-mesh runs as a host-network DaemonSet
  (outbound :15001, inbound :15006). iptables/ipset interception DNATs
  pod-to-pod TCP through it; the node-to-node leg is attested mTLS; the final
  host-to-local-pod dial is plaintext *inside the node's encrypted memory*
  (see [`cmd/ratls-mesh/DESIGN.md`](../cmd/ratls-mesh/DESIGN.md)).
- **Identity granularity:** one launch digest covers the node — kubelet, CNI,
  every pod. All pods share the node's TEE identity; a workload leaf's SAN
  names the workload, but the attestation behind it is the node's quote. Pods
  are only kernel-isolated from each other.
- **Certificates:** get-cert sidecars fetch mesh-CA leaves from CDS through
  the node's attestation flow; ratls-mesh runs self-signed or `--cert-mode
  cds`.

### Pod-as-CVM (kata)

Every in-scope pod is its own `kata-qemu-snp`/`kata-qemu-tdx` CVM with its own
launch digest. The node is a launchpad and is fully adversarial; the chart
refuses to render host-side security components at all (they would be
theater), and CDS and tls-lb run in their own kata CVMs.

- **Evidence source:** the attestation-service is baked into the measured
  guest image and serves loopback `127.0.0.1:8400` inside each pod's VM. The
  guest kernel exposes the TEE device natively. The verifier, the mesh, and
  the image-policy enforcer are all *inside the launch measurement* — the host
  cannot swap them without changing the digest every peer pins.
- **RA-TLS endpoints:** `ratls-mesh in-guest` runs as a systemd service in
  each guest (same ports, fixed). Configuration arrives via the baked
  environment contract (`C8S_WORKLOAD_ID`, `C8S_CDS_URL`,
  `C8S_MESH_MEASUREMENTS`, `C8S_CDS_MEASUREMENTS`, ...). It always runs in
  CDS mode with a dynamically-fetched CA bundle. In-guest iptables REDIRECTs
  all non-loopback TCP through the proxy — no ipsets, no Kubernetes API
  dependency inside the guest.
- **Identity granularity:** per pod. Tenants on one node are isolated from
  each other by hardware memory encryption, and each workload proves its own
  guest state independently.
- **Sharp edges** (both tracked in [THREAT_MODEL.md](THREAT_MODEL.md) §5 /
  [pitfalls.md](pitfalls.md)): UID-0 egress is exempted from in-guest
  interception (so the attestation-service can reach AMD KDS) — root
  workloads bypass the mesh, run workloads non-root; and guests bake
  `C8S_MESH_INBOUND_PASSTHROUGH=tcp:8443` so the CDS/tls-lb front doors can
  accept certless external clients — inbound :8443 is unmeshed in every
  guest.

## Which certificate is used where

| Certificate | Private key lives | Signed by | Presented where | Verified by | Purpose |
|---|---|---|---|---|---|
| Self-signed RA-TLS cert (mesh bootstrap / `--cert-mode self-signed`) | ratls-mesh process memory (in the TEE) | itself — trust is the embedded attestation | mesh inbound :15006 and outbound dials (mTLS both ways) | peer's RA-TLS verification: local attestation-api `/verify` + measurement allowlist | pod-to-pod transport before (or without) CDS |
| CDS RA-TLS serving cert | CDS process memory | itself — attestation bound to CDS's own measurement | CDS API (:8443) | clients pin `--cds-measurements` (get-cert, ratls-mesh, allowlist CLI, nri-image-policy, policy-monitor) | protect the issuance/allowlist API from pod-network impostors |
| Mesh CA (P-384, CN `c8s Mesh CA`, 1y) | CDS process memory only — never a Secret, never disk | self-signed root, or adopted from a peer via attested `/handoff` (recipient-encrypted) | never served as a leaf; public bundle via `GET /ca` and issuance responses | continuity check: new bundle must be signed by an already-trusted CA | root of trust for the CA-chain fast path |
| CDS-issued workload leaf (≤ 24h) | pod volume written by get-cert (`/etc/c8s/certs`, key 0600) — inside the pod's TEE in both shapes | mesh CA, after challenge–attest–certify | workload's own listeners; tls-lb upstream mTLS | chain to the mesh CA bundle | nameable workload identity (SAN = workload id / `c8s-<id>` Service), plus the sandbox-ID extension when the requester presented a sandbox token |
| CDS-issued mesh leaf (`--cert-mode cds`) | ratls-mesh process memory | mesh CA; the leaf preserves the CSR's RA-TLS extension (CN `ratls-mesh-<nodeIP>`) | mesh ports, replacing the self-signed cert after `SwapProvider` | dual verification: CA chain fast path, RA-TLS fallback | post-bootstrap mesh identity without per-handshake attestation cost |
| tls-lb public leaf | tls-lb pod volume (get-cert init container), or an operator-supplied `publicTLS` Secret | mesh CA (default) or external CA | public HTTPS front door | browsers: standard TLS; verifiers: `cds-attest` binds the leaf SPKI or session keys into SNP REPORTDATA | TLS termination for external clients, attestably bound to the TEE |
| Inventory identity/digests certs (self-signed RA-TLS, both ends) | nri-image-policy / policy-monitor process memory; CDS process memory for the client side | itself — attestation bound to the node's / guest's own measurement | the inventory's `:1019` endpoint (fixed, privileged), mTLS both ways | mutual: CDS pins the inventory measurement, the inventory pins CDS's | let CDS resolve the sandbox-token signing key and ask what a pod sandbox is running before issuing that pod a leaf |
| EAR JWT (token, not a cert) | per-process P-256 signer key in CDS memory (rotated with overlap) | CDS EAR issuer, ES256 (JWKS at `/.well-known/jwks.json`) | `/attest-key` responses; presented to `/sign-csr` and `/handoff` | JWKS + issuer + measurement + key-binding checks | TEE-bound authorization for key-only flows (CA handoff, EAR-gated signing) |

Adjacent surfaces that are deliberately **not** RA-TLS:

- **The admission webhook's TLS** is ordinary Kubernetes PKI (Secret +
  `caBundle`) — it is availability/injection machinery, not a confidentiality
  boundary, and its material is visible to etcd readers (THREAT_MODEL.md §2).
- **Browser verification** cannot use RA-TLS (browsers cannot inspect
  certificates mid-handshake). External clients get a challenge–response
  attestation and a post-quantum over-encrypted channel instead — see
  [c8s-verify-js](https://github.com/confidential-dot-ai/c8s-verify-js)
  and THREAT_MODEL.md §10.
- **Attested RKE2 credential release** (`c8s cred-release` /
  `c8s cds request-handoff`) and the operator/allowlist CLIs are RA-TLS
  *clients* of the surfaces above rather than new certificate types.

## Reading order for the curious

1. [`pkg/ratls/extension.go`](../pkg/ratls/extension.go) — the binding and the
   extension format (start here).
2. [`pkg/ratls/tls.go`](../pkg/ratls/tls.go) + [`verify.go`](../pkg/ratls/verify.go)
   — handshake wiring, rotation, dual verification, delegated verification.
3. [`pkg/attestclient/client.go`](../pkg/attestclient/client.go) — the CDS
   challenge–attest–certify flow.
4. [`cmd/ratls-mesh/DESIGN.md`](../cmd/ratls-mesh/DESIGN.md) — the dataplane
   that puts it on every connection.
5. [`pkg/workloadclaims`](../pkg/workloadclaims/) — the inventory's two
   surfaces, the sandbox token, and the digests callback.
6. [getcert-workload-binding.md](getcert-workload-binding.md) — how a pod's
   sandbox identity is established and how CDS gates issuance on what that
   sandbox runs.
7. [THREAT_MODEL.md](THREAT_MODEL.md) — what all of this is for.
