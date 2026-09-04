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

## What the seal rests on

The `…1.3` stamp is authenticated by the CA's self-signature, and the CA's
evidence binds only the CA *key* to a launch measurement. So the stamp is as
trustworthy as the answer to: could anything other than the real CDS, running
`--static-allowlist` on exactly this document, have held that key? On
node-as-CVM every pod on every node booted from the same image gets the same
evidence, so the answer has to come from admission control — and a dynamic
allowlist on a second node of the same image would admit a forger. The seal
therefore requires the policy to be inside what the measurement implies: the
document is baked on the dm-verity root and the baked NRI plugin enforces
exactly it, with no pull (`allowlist.static_path`), so image `M` admits only
the sealed set, anywhere. At startup CDS checks that the seed it read from the
baked path hashes to `--static-allowlist-digest`, the digest the operator
installed with, and refuses to come up otherwise.

Sealing is therefore node-as-CVM only. `c8s install` refuses
`--static-allowlist` with `--cvm-mode=pod`, and the chart refuses
`cds.staticAllowlist` with `kata.enabled`: a kata CDS runs a guest image
shared with every other pod, so its measurement cannot carry this
deployment's policy.

## Node-as-CVM

The operator's path, end to end:

1. **Compose the policy.** The sealed document must carry the platform's own
   component images (at the exact tag being deployed) plus every workload.
   `c8s render-allowlist` renders the same seed `c8s install` would, resolved
   to digests, and folds in the workload entries:

   ```sh
   c8s render-allowlist --cvm-mode=node --hardware-platform=tdx \
     --image-tag v0.10.0 --bootstrap-allowlist workloads.json > static-allowlist.json
   c8s allowlist digest static-allowlist.json   # the value relying parties pin
   ```

2. **Bake it into the node image.** Locally, with the toolchain
   `node-guest-image/README.md` ("Build it") describes:

   ```sh
   CONFOS_DIR=../confidential-os-builder MODULE_SIG_KEY=module-signing.key \
     C8S_GPU_ATTEST=0 C8S_PLATFORM=tdx C8S_REF=<short sha> \
     C8S_STATIC_ALLOWLIST=static-allowlist.json node-guest-image/build
   # → ../confidential-os-builder/output/c8s/{disk.raw,manifest.json,static-allowlist.json,...}
   ```

   `C8S_GPU_ATTEST=0` keeps the NVIDIA driver, GPU CC enforcement and signed
   modules but composes the plain `attest` profile, so the bake needs no
   `libnvat`, no attestation-rs build and no `ATTEST_GPU_BIN`/`LIBNVAT`; c8s
   consumes no GPU evidence today. Leave it unset to match CI's profile set,
   which additionally needs those inputs (set as `c8s-image.yml` sets them,
   on a host that resolves libnvat's ICU 74 and `libxml2.so.2` deps).
   `C8S_REF` selects the c8s component images the image bakes and pins, so
   they must be published at that commit (`docker.yml` on main, or a
   `workflow_dispatch` for a branch).

   or in CI, which publishes the sealed image under its own tags and never
   moves a floating one:

   ```sh
   gh workflow run c8s-image-publish.yml -f c8s_ref=<short sha> \
     -f static_allowlist="$(base64 -w0 static-allowlist.json)"
   # → node-guest-base:rke2-tdx-<sha>-sa<digest12> (+ -cdi)
   ```

   The build stages the document at `/etc/c8s/static-allowlist.json` on the
   verity root, renders the NRI plugin's config with `static_path` set and
   the pull URL blanked (`node-guest-image/c8s/mkosi.sync`), and ships the
   document beside `manifest.json` in the artifact. The launch measurement
   changes — that is the point.

3. **Boot and install.** Boot the sealed image as usual, fetch the attested
   kubeconfig, then:

   ```sh
   c8s install --cvm-mode=node --hardware-platform=tdx --single-node \
     --measurements-config measurements.json \
     --static-allowlist --bootstrap-allowlist static-allowlist.json
   ```

   Under `--cvm-mode=node`, `--static-allowlist` requires
   `--bootstrap-allowlist` and treats it as the baked document: the install
   points CDS at the baked path (`cds.allowlistSeedHostPath`) and pins the
   document's canonical digest (`cds.staticAllowlistDigest`). CDS refuses to
   start if the file the node carries hashes to anything else, so installing
   the wrong policy against an image — or the right policy against an
   unsealed image — fails loudly instead of sealing something the node does
   not enforce.

4. **Publish and prove.** As before: export the served document (`GET
   /allowlist` returns exactly the baked one), capture the mesh CA, hand out
   the image manifest, and verify with `c8s verify --static-allowlist
   --allowlist`. A relying party can now also pull the image artifact and
   recompute the digest from the `static-allowlist.json` it contains.

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
