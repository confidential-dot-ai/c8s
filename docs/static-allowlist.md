# Static allowlist: sealing the policy into the mesh CA

`cds --static-allowlist` turns the allowlist
into a launch-time constant. The seed document becomes the one policy the CDS
instance enforces for its whole lifetime, every write endpoint is disabled,
and the mesh CA certificate is minted carrying two extra extensions:

- `1.3.6.1.4.1.66378.1.1` — the standard RA-TLS attestation extension, over
  the **CA public key** (`REPORTDATA = SHA-384(PKIX(pubkey))`, the same
  nonce-free binding every serving certificate uses).
- `1.3.6.1.4.1.66378.1.3` — the static-allowlist stamp:
  `SHA-256(Allowlist.Canonical())` of the sealed document
  (`pkg/ratls/staticallowlist.go`).

This exists so an end user can trust that the operator is not swapping a good
pod for a malicious one between two HTTPS requests to a workload behind
tls-lb. The dynamic allowlist cannot give that guarantee: its seed is an
operator-rendered ConfigMap and its write API accepts operator-signed
mutations, so between two requests the operator can widen the policy, let a
malicious image in, and have CDS issue it a valid mesh leaf. Sealing removes
the write path and makes the enforced policy a *verifiable identity* of the
deployment.

## Why the CA certificate is the right carrier

The fresh verification paths already commit the CA certificate bytes. Both
`/.well-known/c8s/attest-pq` and `/.well-known/c8s/attest-lb` bind
`SHA-256(mesh_CA_DER)` into the client-nonce-fresh `report_data`
(`pkg/overenc/identity.go`). Anything inside the CA certificate is therefore
covered by per-request hardware evidence with **zero protocol change**: a
relying party that verifies one attest-lb response has, transitively, a fresh
commitment to the sealed policy digest.

The chain, per HTTPS request:

```
client nonce ──► fresh TEE report (tls-lb guest, pinned launch digest)
                   report_data ⊇ H(serving leaf) ‖ H(mesh leaf) ‖ H(mesh CA cert)
mesh CA cert ──► …1.1 evidence binds the CA public key to a pinned CDS launch
                 …1.3 seals SHA-256 of the one policy that CDS enforces
mesh leaf    ──► …1.5 matched-workload stamp {name, version, allowlistDigest}
                   must name the expected workload under the same digest
```

The end user pins **one value** — the canonical allowlist digest, printed by
`c8s allowlist digest <file>` and reproducible offline from the published
document — plus the usual launch-measurement reference values.

The `…1.3` value alone is CA-self-asserted. What upgrades it to "enforced" is
the pairing the verifier requires: the embedded `…1.1` evidence proves the CA
key was generated inside a measured CDS, and the measured CDS code refuses to
start unless the digest it stamps is the digest of the document it loaded,
then refuses every mutation. Changing the policy therefore means launching a
new CDS, which mints a new mesh CA — and every pinning client notices,
because the CA hash in the fresh evidence changes.

## Node-as-CVM: the primary deployment

Node-as-CVM is where the seal composes end to end, because every enforcement
component sits inside one measured boundary:

- The **nri-image-policy plugin**, its containerd registration
  (`required_plugins` — a plugin that fails to register blocks all container
  creation), and its baked floor live on the dm-verity root, inside the node
  launch digest (`node-guest-image/c8s/image-policy.yaml.in`).
- With the seed baked into the node image, the **policy content** is inside
  the node launch digest too, not just its hash inside the CA.
- CDS runs from an image whose digest is in the measured floor, and its
  evidence is the node's evidence.

### Build: bake the seed into the node image

To bake the sealed policy into the measured image, drop the allowlist
document at `node-guest-image/c8s/static-allowlist.json` (gitignored — it is
per deployment) before building. The build validates it and stages it at
`/etc/c8s/static-allowlist.json` on the verity root
(`node-guest-image/c8s/mkosi.sync`, `stage_static_allowlist`). Baking it
changes the node launch measurement — that is the point: the reference values
the end user pins now imply the policy.

Record the value to publish:

```sh
c8s allowlist digest node-guest-image/c8s/static-allowlist.json
```

The document must carry every image the node runs beyond the baked floor —
the chart components (`c8s.allowlistSeedJSON` is what a non-static install
would have rendered; `helm template` shows it) and the workload entries,
including a named entry for the workload behind tls-lb so its leaves earn the
`…1.5` stamp.

### Install

```sh
c8s install --cvm-mode=node --hardware-platform=tdx --single-node \
  --measurements-config measurements.json \
  --static-allowlist \
  --bootstrap-allowlist workloads.json \
  --set cds.allowlistSeedHostPath=/etc/c8s/static-allowlist.json
```

- `--static-allowlist` renders `cds.staticAllowlist=true` and is refused next
  to `--operator-keys` (a sealed allowlist has no write path). It also
  satisfies the operator-keys preflight: key-less is the design here, not an
  oversight.
- `--bootstrap-allowlist` folds a `c8s.allowlist/v1` document into the install
  seed — its floor digests and its named workload entries. Under a seal this
  is the only way a workload entry gets in, since nothing can be written after
  CDS starts; the entry for the workload behind tls-lb is what earns its
  leaves the `…1.5` stamp.
- `cds.allowlistSeedHostPath` mounts the baked file into CDS instead of the
  chart's ConfigMap seed. On node-as-CVM the "host" path is the measured
  guest root, so the mount is verity-backed. (Without it the ConfigMap seed
  still works and still seals — the digest is still committed and immutable —
  but the content then rides an operator-rendered ConfigMap rather than the
  measured image, so only the CA stamp, not the node measurement, speaks for
  it.)

The install prints the publish-and-pin recipe on success: export the served
document, print its canonical digest, and hand both to relying parties.

At startup CDS **replaces** the store with the seed (`seedStoreStatic` — a
persistent DB from an earlier, wider policy cannot leak entries into the
sealed set), computes the snapshot digest, fetches evidence for the fresh CA
key from the node's attestation-api, and self-signs the sealed CA. Any
failure — unreadable seed, unreachable attestation-api — aborts startup: a
sealed CDS never comes up with an unstamped root.

### Verify (operator or end user)

```sh
c8s verify https://workload.example.com --kind lb \
  --measurements <node-launch-digest> \
  --mesh-ca mesh-ca.pem \
  --static-allowlist \
  --allowlist allowlist.json \
  --workload api
```

`--static-allowlist` (requires `--mesh-ca`) makes the verdict additionally
require:

1. Exactly one certificate in the `--mesh-ca` bundle carries the `…1.3`
   stamp.
2. That CA's embedded `…1.1` evidence verifies, binds the CA's own public
   key, and its launch digest passes the same measurement policy as the
   target (`--measurements` / `--measurements-config` / `--image-manifest`).
3. With `--allowlist`, the sealed digest equals SHA-256 of the held bytes
   (fetch them with `c8s allowlist export`, or use the published document).
4. Any `…1.5` matched-workload stamp on the target's leaf was decided under
   the sealed digest — a leaf stamped under a different policy document is
   `static_allowlist_skew`, a hard failure.

The sealed CA also verifies offline, because it is an ordinary self-signed
RA-TLS certificate:

```sh
c8s verify --from-file mesh-ca.pem --measurements <node-launch-digest> \
  --mesh-ca mesh-ca.pem --static-allowlist --allowlist allowlist.json
```

### What this buys, concretely

Between two HTTPS requests verified against the same pinned
`(allowlist digest, reference values, workload name)`:

- The operator cannot widen or swap the policy: there is no write path, and a
  replacement CDS (any seed, any code) mints a different CA — the fresh
  `report_data` commitment breaks immediately.
- A malicious pod not in the sealed allowlist is never admitted (measured NRI
  plugin, deny-by-default) and never issued a mesh leaf (issuance-time
  membership gate against the sealed snapshot).
- Routing the client to a different allowlisted workload trips the `…1.5`
  name pin.

## What it does not buy (unchanged residuals)

- **Composition drift inside the sealed set.** Issuance gates on membership;
  the whole-entry match only feeds the `…1.5` stamp, and an already-issued
  named leaf keeps asserting until `--named-cert-ttl` (6h ceiling). With a
  static policy re-issuance is cheap: shorten `cds.namedCertTTL` for the
  workload behind tls-lb, and gate ingress with
  `tlsLb.attest.expectedWorkload`.
- **The leaf stamp is still CA-vouched.** The seal narrows what the CA can
  honestly stamp, and the CA evidence narrows who can be the CA — but a
  runtime exploit of measured CDS code still owns the CA key. Same TCB
  assumption as everything else.
- **CDS restart still re-bootstraps.** A sealed CDS restarting re-seeds the
  same document and re-seals the same digest, but mints a new CA key, exactly
  as today (docs/operator.md, "CDS singleton").
- **Pod-as-CVM (kata) commitment into HOST_DATA/MRCONFIGID.** The init-data
  key for it is reserved (`initdata.KeyCDSAllowlistSeedSHA256`) and not yet
  wired; under kata the seal currently rests on the CA stamp plus CDS's
  launch measurement, without the seed content being measured. Tracked as a
  follow-up.
