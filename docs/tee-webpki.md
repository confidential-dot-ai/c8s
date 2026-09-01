# TEE WebPKI

Status: experimental design and implementation branch.

## Purpose

The current TLS-LB has two public TLS modes.

- `webpki` uses a normal public certificate. Kubernetes supplies its private
  key. An untrusted control plane can copy that key.
- `cds` keeps the private key inside a TEE. Normal web clients do not trust the
  private mesh CA.

`tee-webpki` combines the required properties. A public CA signs the public
certificate. The cluster TLS private key is created inside the confidential
cluster. Kubernetes never receives that private key.

## Threat model

The Kubernetes control plane and the physical host are not trusted. They can
copy manifests, public keys, measurements, certificates, and network traffic.
They can start another copy of an approved image. They must not obtain the
cluster TLS private key or the CDS mesh CA private key.

The old CDS handoff was removed in commit `7a1d876d` (PR 503). It accepted a
peer that had an approved launch measurement and a copy of the public operator
key set. Those values do not prove that the peer belongs to the live cluster.
An offline copy could ask for the mesh CA private key.

The replacement has these additional conditions.

1. The successor presents a client certificate signed by the current mesh CA.
2. That certificate contains the expected matched-workload stamp.
3. The successor presents fresh, nonce-bound TEE evidence for its request key.
4. The request binds the transfer key to the live cluster certificate.
5. One CDS process accepts one successor. An identical retry is idempotent.
   A different request is rejected.
6. The successor restores all transferred state before it requests activation.
7. The old CDS freezes allowlist, secret, and certificate-state mutations. It
   keeps read and certificate service.
8. The successor restores the snapshot and listens while it is NotReady and
   frozen.
9. Activation makes the old CDS NotReady. The old CDS stays frozen and serves
   reads and certificates during the endpoint drain delay.
10. The old CDS retires after that delay. The successor then becomes mutable
    and Ready.
11. The old CDS cannot resume in that process.

The predecessor owns the bounded drain timer after it authenticates activation.
A client disconnect cannot stop retirement. The same successor retries
transport errors, HTTP 429/5xx responses, and a lost success response until its
activation deadline. A retry during drain waits for the same timer. A retry
after retirement receives the same success result.

An offline copy cannot obtain the current mesh certificate. A same-image pod
cannot obtain a named certificate unless the current CDS verifies its live
container inventory against the active allowlist.

## Cluster TLS state

CDS is the source of truth for this state:

- one random seed for the cluster TLS private key;
- the current public certificate chain;
- one random seed for the ACME account key;
- the public ACME registration and renewal state.

TLS-LB replicas receive the state only over a mesh-authenticated connection.
Each replica derives the same private key inside its TEE. The public
certificate can enter through a ConfigMap. The sidecar verifies that it
matches the protected key before it stores or serves it.

The CDS rolling handoff carries this state, the application-secret store, and
the mesh CA. The old CDS uses
one leadership gate to stop all mutations before it creates the transfer
snapshot. It returns to active service if snapshot validation or encryption
fails before it commits a transfer response. The new CDS restores the snapshot
before it becomes Ready.

## Certificate flow

1. TLS-LB gets its named mesh identity from CDS.
2. TLS-LB gets the cluster TLS state from CDS.
3. TLS-LB derives the private key and writes a CSR to TEE memory.
4. An issuer signs the CSR. Kubernetes may carry the public certificate only.
5. TLS-LB verifies the chain, hostnames, and key match.
6. TLS-LB stores the public certificate state in CDS and reloads nginx.
7. `attest-lb` binds fresh evidence to the exact public leaf that nginx serves.

The renewal sidecar writes the new public chain and signals nginx. It stays
NotReady if nginx does not load the new chain. The init container does not
start nginx with a temporary certificate. It waits for a valid public chain
and fails when the configured wait time ends.

## Receipt evidence

The receipt endpoint can fetch the active operator public-key set from the
live CDS. It returns the PEM set and its canonical
`operatorauth.KeySetHash`. It binds that exact key-set hash into TDX report
data and the mesh identity proof. This hash commits to the complete framed key
set. It is not the SPKI fingerprint of one operator key.

A GPU-worker `cds-attest` sidecar can request local NVIDIA evidence. The local
attestation service derives the GPU nonce from the same report-data transcript
as the CPU TDX evidence. The application must collect one receipt from each
required GPU worker. Its verifier must validate every CPU and GPU bundle and
check the expected worker and GPU set. TLS-LB does not aggregate GPU evidence.

`c8s verify` verifies one saved GPU-worker receipt with the official NVIDIA
NRAS verifier from `attestation-rs` v0.5.0. Use the commit in
`node-guest-image/attestation-rs.ref`. This one source lock also
builds the guest evidence producer. Build the helper as follows and put
`attestation-cli` on `PATH`:

```bash
git checkout "$(cat ../c8s/node-guest-image/attestation-rs.ref)"
cargo build --locked -p attestation-cli --release \
  --features attest,nvidia-gpu --bin attestation-cli
```

Use `--nvidia-gpu-user-nonce <hex> --nvidia-gpu-required`, one or more
`--nvidia-gpu-expected-arch BLACKWELL` flags, and an optional exact
`--nvidia-gpu-expected-count`. The helper verifies NVIDIA NRAS signatures,
certificate chains, nonce binding, and the architecture policy. The c8s
command checks that the supplied GPU nonce equals the CPU report-data
transcript. It rejects empty or repeated signed device UEIDs. Raw bundle UUIDs
do not count as device identity. JSON output includes `gpu_verified`,
`nonce_binding_ok`, `gpu_device_count`, and `gpu_device_ueids`.

For an offline `attest-lb` check, save three values from the same live HTTPS
request: the response bundle, the challenge, and the observed TLS leaf DER or
PEM. Then run:

```bash
c8s verify --kind workload --mode attest-lb \
  --from-file bundle.json \
  --attestation-nonce <32-byte-unpadded-base64url> \
  --observed-serving-cert leaf.der -o json
```

The verifier recomputes the LB transcript, operator key-set commitment, mesh
proof, CPU TEE evidence, and exact serving-leaf digest. JSON output includes
`tls_binding_verified` and `serving_leaf_sha256`. A leaf fetched on another
connection is not a safe substitute because routing can select another LB.

The first implementation supports a public certificate supplied after CSR
issuance. ACME account state is part of the protected CDS state so an in-TEE
ACME client can use the same lifecycle without a later state-format change.

## Availability limits

This design can transfer state during a planned CDS update while the old CDS is
alive. It proves that at most one CDS accepts mutations. The frozen old CDS
keeps identical read and certificate service until the successor listens.
Activation makes the old CDS NotReady before the configured drain delay. The
Kata chart probes HTTPS `/readyz`; it does not use a TCP-only readiness probe.
Kubernetes cannot switch all existing endpoint connections in one atomic
operation. A request to a stale, retired endpoint can receive HTTP 503 during
the endpoint change. Thus, this design does not prove zero downtime.
It does not recover private state after the only CDS process and all TLS-LB
replicas are lost. c8s has no durable TEE-protected storage for this state.
That event requires a new key, a new certificate, and a full trust reset.
