# RT-005 — CDS has no cluster-instance binding: any TDX platform (default) or any same-image TD (fully pinned) can mint any workload identity

**Status:** LIVE-VERIFIED on a purpose-built node-as-CVM cluster (2026-07-23):
a physically separate TDX TD that is **not a cluster node** obtained a genuine
c8s-Mesh-CA-signed leaf for the running victim workload's exact identity
(`DNS:c8s-echo.demo.svc`, issuer `CN = c8s Mesh CA` — byte-identical issuer
and SAN to the victim's own cert).
**Severity:** Critical (full mesh impersonation of any workload from outside
the cluster)
**Adversary:** anyone who can route to CDS's port and boot a TDX (or SEV-SNP)
VM — no cluster credentials, no host access, no k8s identity of any kind.

## Summary

CDS's `/attest` endpoint verifies *that* evidence is a genuine TEE quote and
that the CSR's SAN matches its DNS pattern — but **nothing binds issuance to
membership in this cluster**. Two compounding gaps:

1. **Default config: no measurement pin at all.** The chart ships
   `cds.measurements: []` ("Empty = no pinning (UNSAFE outside dev)"), and CDS
   then logs `--measurements empty: /attest accepts any TEE measurement`. The
   only remaining gates are quote validity (DCAP verification is a public
   good — any genuine quote from any TDX/SNP platform on earth verifies) and
   the SAN regex `^[a-z0-9-]+[.][a-z0-9-]+[.]svc$` (satisfied by every
   workload identity). So the chart-default CDS issues any workload's mesh
   identity to any TDX box that can reach it.
2. **Even fully pinned: measurements are image-level, not instance-level.**
   `--measurements` pins the *node image's* launch digest. But c8s's node
   image is built reproducibly by confidential-os-builder and its
   measurements are *published for verifiers*. MRTD covers TDVF; the RTMRs
   cover the published UKI (kernel/initrd/cmdline) — all fixed public values.
   An attacker who boots the same published image as their own TD presents a
   byte-identical measurement set. The pin distinguishes images, never
   instances, so it cannot tell a cluster node from a rogue clone.

RT-001 showed the kata-mode version (every kata guest shares MRTD, so a rogue
workload pod impersonates CDS). RT-005 is the node-mode version and it is
strictly worse: the attacker needs no pod, no namespace, no account — the
"workload" doesn't even have to exist in the cluster.

## Live reproduction (tdx-dev-host-1, 2026-07-23)

Setup: a TDX TD (`node-cvm-1`, 10.9.0.2) running k3s + `c8s install
--cvm-mode node --hardware-platform tdx` (chart defaults, so
`cds.measurements` empty — the state every install is in unless the operator
hand-supplies measurements). A demo workload (`cw-server`, `cw: echo`) held a
legitimate leaf for `c8s-echo.demo.svc`. CDS was exposed on NodePort 30443.

Attack: a **second, independent TD** (`node-cvm-2`, 10.9.0.3) — not a cluster
member, no kubeconfig, no k8s identity — ran only an attestation-api and the
public `c8s get-cert` client:

```
node-cvm-2$ c8s get-cert \
  --cds-url=https://10.9.0.2:30443 \
  --attestation-api-url=http://10.9.0.3:8400 \
  --san=c8s-echo.demo.svc \
  --out=/tmp/tls.crt --key-out=/tmp/tls.key --ca-out=/tmp/ca.pem \
  --renew-interval=0s

time=... level=INFO msg="certificate obtained"
```

Result (attacker box, TD2):

```
subject=          (empty)
issuer=CN = c8s Mesh CA
X509v3 Subject Alternative Name: critical
    DNS:c8s-echo.demo.svc
```

Victim box (cw-server pod, in-cluster):

```
issuer=CN = c8s Mesh CA
X509v3 Subject Alternative Name: critical
    DNS:c8s-echo.demo.svc
```

The two credentials are indistinguishable to any relying party doing
chain+SAN verification (`dualVerifyPeerCallback` — the documented default).
The attacker additionally received the mesh CA bundle, so it can also
*verify* mesh peers as if it were in-cluster. With network reachability to a
workload's mesh listener, this is full impersonation: intercept prompts,
requests, and model I/O intended for the victim, or serve forged responses
upstream of it.

The same flow from a pod *inside* the cluster works identically (verified on
the same cluster: an unannotated attacker pod obtained the same SAN from the
real CDS — the node-mode twin of RT-004, where per-node identity granularity
makes every pod indistinguishable at the TEE layer anyway).

## Why the current checks can't stop it

- **Quote validity** only proves "some genuine TEE somewhere" — DCAP
  verification accepts any Intel-signed quote with a valid PCK chain and
  non-revoked TCB.
- **Measurement pins** prove "some TD running *this public image*" — the
  image and its measurements are published precisely so verifiers can check
  them; reproducibility makes them cloneable by construction.
- **The SAN pattern** constrains shape, not ownership — every workload SAN
  fits.
- **Workload claims** (`workload_claims=true`) bind *container digests*, not
  cluster membership, and require the in-guest/baked broker that node mode
  does not universally deploy; they also can't help a SAN the attacker
  legitimately knows (it's just DNS).

What *would* distinguish TD2 from a cluster node is possession of something
provisioned at cluster-join time — and c8s already has that machinery: the
RTMR[3]-bound enrollment flow (`c8s get-kubeconfig` / `c8s cred-release`)
exists exactly to hand cluster secrets to attested nodes.

## Fix direction

1. **Bind issuance to cluster enrollment.** CDS should require, for any
   `/attest`, proof of a cluster-provisioned secret bound into the evidence —
   e.g. extend the existing RTMR[3] enrollment: at node-join, the operator
   injects a per-cluster nonce/secret that the node's attestation-api folds
   into RTMR[3] (already supported); CDS then requires the evidence's
   RTMR[3] to match the cluster's enrolled value set. A rogue same-image TD
   never receives the enrollment, so its RTMR[3] differs and issuance fails
   — regardless of MRTD/RTMR[0-2] equality.
2. **Fail closed on empty measurements.** Treat `cds.measurements: []` the
   way `--require-pulled-image-stamp` treats missing stamps: refuse `/attest`
   (or at minimum refuse non-`ratls-mesh` SANs) instead of warn-and-accept.
   The current default turns an "UNSAFE outside dev" footnote into the
   production posture of every install that doesn't hand-set measurements.
3. **Node-identity scoping for node-level SANs.** The
   `ratls-mesh-<node-ip>` subject is IP-asserted; enrollment binding (1)
   would make it attestable.

Until (1) lands, operators should treat network reachability of CDS's 8443
as equivalent to mesh membership: never expose it outside the cluster, and
do not treat the mesh CA as a workload-identity root for anything
authorization-shaped.

## Affected versions / config

- Chart default (`cds.measurements: []`): any c8s install that didn't pass
  `--measurements` — verified live on `--cvm-mode node`; the same empty-pin
  posture exists in pod mode (where RT-001 exploited the shared MRTD
  instead).
- With `--measurements` set: still exploitable by any same-image TD
  (image-level pin), though the bar rises from "any TDX box" to "boot the
  published node image".
