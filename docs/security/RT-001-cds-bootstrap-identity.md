# RT-001 — CDS bootstrap identity: workloads accept any TEE-attested peer as CDS, and the flat measurement list cannot separate CDS from co-measured workloads

**Status:** confirmed by code audit (dynamic PoC scaffolding in `test/redteam/fakecds/`)
**Severity:** Critical
**Adversary (in scope per `docs/THREAT_MODEL.md` §2):** host / hypervisor; pod-network attacker able to serve genuine TEE attestation
**Affected modes:** all chart modes; pod-as-CVM (kata) is the primary target since it is the mode that claims host-adversary resistance

## Summary

Every workload's certificate bootstrap (`get-cert`) accepts **any peer that
presents syntactically valid TEE attestation** as the Certificate Distribution
Service, then installs the CA bundle from the (attacker-controlled) issuance
response as its mesh root of trust. Two independent defects compose:

1. **`--cds-measurements` is never delivered to injected `get-cert`
   containers.** The flag exists (`internal/cmds/getcert/run.go:106`), and
   when empty `get-cert` merely warns and accepts *any* RA-TLS-attested CDS
   (`internal/cmds/getcert/run.go:169-175`). But neither injection path can
   ever set it:
   - the webhook's `Config` struct has no measurement field at all
     (`internal/webhook/pod_mutator.go:137-190`), and `certContainer` builds
     sidecar args without it (`internal/webhook/pod_mutator.go:788-800`);
   - the operator command has no such flag (`cmd/c8s/operator.go`);
   - the chart helper `c8s.getCertContainers` (used for tls-lb) renders no
     `--cds-measurements` arg (`internal/helmchart/c8s/templates/_helpers.tpl`).
   Only `ratls-mesh` receives the pin
   (`internal/helmchart/c8s/templates/ratls-mesh-daemonset.yaml:277`).

   The comment on `ratls.NewVerifyingHTTPClient` claims empty measurements
   "falls back to TOFU on the attestation extension"
   (`pkg/ratls/client.go:12-13`) — **no TOFU is implemented**; empty means
   accept-any, silently.

2. **Even where the pin *is* delivered (ratls-mesh), it cannot distinguish
   CDS from any workload.** The pin set is the flat `cds.measurements` list,
   which per `values.yaml` doubles as the `/attest` admission list — so every
   workload's launch digest must be in it. In pod-as-CVM every kata pod boots
   the same guest image and is therefore *co-measured* with CDS (container
   contents are not launch-measured). On TDX the pin is weaker still: for
   kata direct-kernel boot the MRTD covers the TDVF firmware only — kernel,
   initrd, and cmdline land in RTMRs, which `EvidencePolicy` explicitly does
   not pin (`pkg/attestationclient/verify.go:92-96`, `docs/THREAT_MODEL.md`
   §5). Any same-firmware TDX VM — including one with a fully
   attacker-controlled guest stack — matches the pin.

   `cdsclient`/`getcert` verify nothing else about the serving identity: no
   DNS SAN check, no config-claims pins
   (`pkg/ratls/cdsclient/client.go:98-126`; `VerifyPolicy` carries only
   `Measurements` + `AttestationApiURL`). The publicly readable operator-key
   and seed digests would not help either — an attacker CVM can bind the same
   public digests into its own claims.

## Attack

Adversary: the host (untrusted in pod-as-CVM mode), or any attacker who can
(a) produce genuine TEE evidence and (b) win the network path to the CDS
Service ClusterIP — both trivial for the host (it owns CNI/iptables/DNS), and
explicitly in-scope in the threat model ("pod-network attacker … can stand up
its own genuine TEE attestation and try to impersonate CDS / a mesh peer at
bootstrap", §2).

1. Attacker starts any TEE (TDX VM, or a kata pod running an allowlisted
   image) and runs `test/redteam/fakecds`: an HTTPS server presenting a
   self-signed RA-TLS certificate whose evidence binds its own key — genuine
   hardware-signed evidence, produced exactly like CDS's own self-provisioned
   serving cert.
2. Attacker redirects `c8s-cds.<ns>.svc:8443` to the fake (DNAT on the host,
   or a shadow EndpointSlice/Service in a namespace it controls, or DNS).
3. A victim workload pod starts. Its injected `get-cert` sidecar dials the
   CDS URL; the RA-TLS handshake verifies the attacker's genuine evidence
   against an **empty** measurement pin (defect 1) — handshake succeeds.
4. `get-cert` runs authenticate → attest; the fake signs the CSR with the
   attacker's own CA and returns `leaf || attacker-CA` PEM.
5. `get-cert` installs the attacker CA as the mesh trust root
   (`pkg/ratls/cdsclient/client.go:151-159`) and writes it to the shared cert
   volume. The workload and every peer that trusts its CA bundle now accept
   attacker-issued identities; the attacker also obtains a *legitimate* leaf
   from the real CDS (its co-measured TEE passes `/attest` — defect 2) and
   bridges both sides: transparent bidirectional MITM of the victim's entire
   RA-TLS mesh traffic.

Result: prompts, responses, model weights, and secrets of the victim workload
are plaintext to the attacker — the exact assets §1 of the threat model
prioritizes — in a deployment with `cds.measurements` **and**
`ratlsMesh.measurements` pinned, i.e. the recommended production posture.
The same substitution against `ratls-mesh`'s pinned CDS channel (defect 2)
yields the node's mesh identity and CA bundle.

## Why the documented mitigation does not cover this

`docs/THREAT_MODEL.md` §8 ("Measurement pinning defaults") describes CDS
impersonation only under *empty* `cds.measurements`/`ratlsMesh.measurements`
and prescribes pinning as the fix. Pinning cannot fix defect 1 (the pin never
reaches `get-cert` — there is no wiring to fix it *with*), and cannot fix
defect 2 (the pin set necessarily contains every co-measured workload; the
launch digest measures the guest image, not the container, and on TDX only
the firmware). The threat model itself recognizes the identical
co-measurement confusion for the policy-monitor refresh path ("the host can
boot its own CVM from the same guest image and pass 'attested' while serving
an attacker-chosen allowlist", §5) and fails that path closed — the CDS
bootstrap path, which carries the **root of trust**, was left open.

## Relation to existing work (checked 2026-07-23)

No open or merged PR covers this finding:

- **#111 (merged)** — `c8s install --measurements` pins the two *server-side*
  boundaries (`cds.measurements`, `ratlsMesh.measurements`) in one pass. Its
  own description scopes out the bootstrap clients: get-cert sidecars remain
  unpinned even after it. This finding is the missing third boundary.
- **#120 / #124 (open)** — enforce config-claims pins / re-verify embedded
  evidence on the RA-TLS *peer* fast path (`dualVerifyPeerCallback`). They
  harden mesh peer verification, not CDS-to-get-cert bootstrap identity.
- **#60 (open)** — binds browser PQ sessions to the LB's mesh identity
  (threat-model §5 Addressable). Orthogonal.
- **#104 (merged)** — makes issued leaves' embedded evidence re-verifiable;
  prerequisite for #124, not for this.
- The in-flight audit series (findings H-08, R-01, C-05, "plan PR 43" in PR
  bodies) has no item for get-cert measurement pinning or the flat-list
  identity conflation.

## Fix (this branch)

Immediate (closes defect 1 and narrows defect 2 to co-measured TEEs):

- Add `--cds-measurements` to the operator command and thread it through
  `controller.Options` → `webhook.Config` → injected `get-cert` args
  (comma-separated, same format as `ratls-mesh`).
- Render it in the chart (`operator.yaml`, and `c8s.getCertContainers` for
  tls-lb) from `cds.measurements`; log a loud warning at webhook registration
  when empty, matching `ratls-mesh`'s existing behavior.

Residual, requiring a design change (tracked, not in this branch): the flat
list fundamentally conflates "may call /attest" with "is CDS". Durable fix
options: (a) pin CDS's serving identity out of band at install time
(e.g. `c8s cds verify`-attested serving SPKI pinned into the fleet config,
rotated via the existing continuity rule); (b) issue CDS's serving cert from
an install-time operator root the bootstrap client can chain to before
trusting any CA bundle; (c) on TDX, pin RTMRs once the attestation-api
exposes them, and run CDS from a distinct, pinned guest configuration.
Until then the wired pin still has value: it excludes non-co-measured
attackers (the common pod-network case) from the get-cert path.

## Reproduction

`test/redteam/fakecds/` contains the fake CDS (genuine-TEE RA-TLS serving
cert, `/authenticate`, `/attest`, `/ca`) and a runbook for a local
k3s + c8s (kata-qemu-tdx) cluster on a TDX host: DNAT the CDS ClusterIP to
the fake, create a `confidential.ai/cw` workload, and observe its
`get-cert` sidecar accept the attacker CA bundle. The fake runs anywhere it
can present genuine TDX evidence; it needs no c8s credentials, no allowlist
entry, and no cluster RBAC.
