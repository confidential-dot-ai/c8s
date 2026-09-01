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
7. The old CDS freezes all transferred state. It keeps read-only service.
8. The successor restores the snapshot and listens while it is NotReady and
   frozen.
9. Activation makes the old CDS NotReady. The old CDS stays frozen and serves
   reads during the endpoint drain delay.
10. The successor becomes mutable, but stays NotReady while it sends a bounded,
    idempotent confirmation through the selected direct network path.
11. An acknowledged confirmation retires the old CDS. If the result is
    ambiguous, the successor becomes Ready and stays active. The old CDS is
    either frozen or retired. It is never mutable after activation.

The predecessor owns the bounded drain timer after it authenticates activation.
A client disconnect cannot stop the drain. The same successor retries transport
errors, HTTP 429/5xx responses, and a lost success response within the bounded
confirmation period. It uses the direct
network path selected during the first handoff request. Kubernetes readiness
changes cannot remove that path. Activation and confirmation are idempotent.

If the successor stops before activation, the transfer lease expires and the
predecessor resumes. If the successor Pod is lost after activation but before
confirmation, automatic resume can create two mutable copies. Recovery therefore
needs an operator to remove the successor first. The operator can then send a
signed, transfer-bound `/handoff/abort` request to resume the predecessor. This
route is intentionally not automatic. Abort is rejected after confirmation.
A same-Pod restart can reuse its mesh identity and obtain the cached snapshot.
A full Pod replacement after confirmation needs a deliberate trust reset.

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

The CDS rolling handoff carries this state, the application-secret store, the
mesh CA, the active and overlapping EAR signing keys, and the sandbox ledger.
The old CDS uses one leadership gate to stop all mutations before it creates
the transfer snapshot. It also pauses EAR rotation and ledger writes. Challenge
creation, challenge use, and certificate issuance return a retryable error while
state is frozen. Challenge records are not transferred. Clients must request a
new challenge after takeover. The old CDS returns to active service if snapshot
validation or encryption fails before it commits a transfer response. The new
CDS restores the snapshot before it becomes Ready.

## Certificate flow

1. TLS-LB gets its named mesh identity from CDS.
2. TLS-LB gets the cluster TLS state from CDS.
3. TLS-LB derives the private key and writes a CSR to TEE memory.
4. An issuer signs the CSR. Kubernetes may carry the public certificate only.
5. TLS-LB verifies the chain, hostnames, and key match.
6. TLS-LB stores the public certificate state in CDS and reloads nginx.
7. `attest-lb` binds fresh evidence to the exact public leaf that nginx serves.

The tee-WebPKI helper runs as a regular sidecar. This lets the complete TLS-LB
Pod earn its exact workload identity before CDS releases the protected key. It
writes the public chain and signals nginx. Until a valid public chain exists,
nginx has no certificate and cannot bind successfully. The Pod stays NotReady.
No temporary certificate is created.

## Receipt evidence

The receipt endpoint can fetch the active operator public-key set from the
live CDS. It returns the PEM set and its canonical
`operatorauth.KeySetHash`. It binds that exact key-set hash into TDX report
data and the mesh identity proof. This hash commits to the complete framed key
set. It is not the SPKI fingerprint of one operator key.

A `cds-attest` sidecar can request local NVIDIA evidence. The local attestation
service derives the GPU and NVSwitch nonce from the same report-data transcript
as the CPU TDX evidence. This evidence covers every NVIDIA device visible to the
node. It does not prove which devices Kubernetes assigned to one pod. The
application must collect one receipt from each required GPU node. Its verifier
must validate each CPU and NVIDIA bundle and check the expected node-wide GPU
and NVSwitch sets. TLS-LB does not aggregate NVIDIA evidence.

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

Record `sha256sum target/release/attestation-cli`. Use
`--attestation-cli-sha256 <hex> --nvidia-gpu-user-nonce <hex>
--nvidia-gpu-required`, one or more `--nvidia-gpu-expected-arch BLACKWELL`
flags, and optional exact `--nvidia-gpu-expected-count` and
`--nvidia-switch-expected-count` values. The helper verifies NVIDIA NRAS
signatures, certificate chains, nonce binding, and raw architecture policy.
c8s also requires architecture from each signed `hwmodel` claim and compares
the signed device groups with the raw evidence groups. It rejects empty or
repeated signed device UEIDs. Raw bundle UUIDs do not count as device identity.
JSON output separates `gpu_device_*` and `switch_device_*`. It also reports the
verifier SHA-256 and the pinned attestation-rs commit.

The c8s chart does not create application inference workers. The application
chart must pass `--nvidia-gpu-evidence` only to each GPU-node receipt sidecar.
It must include a render test for this setting. Two sidecars on one node can
return the same node-wide device set. The application must not count this as
two independent device sets.

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

## Current evidence scope

The nonce-bound `attest-lb` response proves the TLS-LB replica that answered.
On node-CVM, NRI also serves a nonce-bound runtime inventory from each node. The
inventory includes the Kubernetes identity observed for each live container,
its digest, effective argv, bind-mount destinations and source classes,
environment names, and the exact active policy digest and version. Fresh TDX or
SNP evidence binds the nonce and the canonical inventory.

The local digest floor is cold-boot policy only. After the first authenticated
CDS pull, NRI removes it. `c8s install --resolve-digests` derives exact named
entries for every steady c8s Deployment, DaemonSet, and StatefulSet from the
same rendered chart and pinned OCI configs. NRI applies the active policy only
when every live Pod resolves to one named entry. Every node then reports the
same CDS canonical policy digest.

Application workload entries must also enumerate every webhook-injected c8s
helper. CDS does not hide helpers by digest or command prefix. An extra c8s
helper with attacker arguments prevents a named certificate and secret release.

Exact policy entry names can change during a release. An optional allowlist
`identity` gives old and new exact entries one stable mesh peer name. TLS-LB and
workload proxies pin this identity. Receipts keep the exact entry name, stable
identity, active allowlist version, and digest. Both entries must stay in the
active policy until old Pods drain.

The application still has to collect one runtime inventory proof from each
required node and include it in its public response. Tailscale control is
outside this chart. It is not proved unless it runs as a named attested workload
or its bytes are part of the measured guest image.

The allowlist can enforce argv, bind-mount destinations, and environment
variable names for named workloads. It does not yet bind capabilities,
privilege, user IDs, devices, seccomp, or all namespace settings. A verifier
must not interpret an image-and-command receipt as proof of those fields.

Runtime inventory does not yet bind capabilities, privilege, user IDs, devices,
seccomp, or all namespace settings. It reports mount destinations and source
classes, not ConfigMap or Secret contents. Tee-WebPKI therefore requires an
image-baked nginx configuration and rejects a control-plane ConfigMap for the
front door.

## Availability limits

This design can transfer state during a planned CDS update while the old CDS is
alive. It proves that at most one CDS accepts mutations. The frozen old CDS
keeps read-only service until it processes confirmation. Activation makes
the old CDS NotReady before the configured drain delay. The successor stays
NotReady during its bounded confirmation attempt. It then becomes Ready even
if the result is ambiguous. At that point, the old CDS is frozen or retired;
it cannot accept mutations. The Kata chart probes HTTPS `/readyz`;
it does not use a TCP-only readiness probe. The headless handoff Service keeps
the selected predecessor reachable during this change. Kubernetes cannot switch
all existing endpoint connections in one atomic operation. Certificate issuance
and other state-changing calls receive HTTP 503 while the old CDS is frozen.
Thus, this design does not prove zero downtime.

The nginx image remains in the static digest floor so TLS-LB can start before
CDS sends the full policy to NRI. That floor admits the image bytes, but it does
not release the protected TLS key. The exact named `c8s-tls-lb` workload policy
uses the same command and arguments as the chart. CDS requires that named match
before it issues a workload certificate or releases tee-WebPKI state. A changed
command can start during bootstrap, but it cannot get the protected key.
It does not recover private state after the only CDS process and all TLS-LB
replicas are lost. c8s has no durable TEE-protected storage for this state.
That event requires a new key, a new certificate, and a full trust reset.
