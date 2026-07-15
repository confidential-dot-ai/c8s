# 2026-07-15 — secret release with an adversarial control plane

Status: accepted safety gate; secure secret release remains deferred.

## Threat model

The Kubernetes API server, etcd, scheduler, and pod-spec author are
adversarial. They can read every ordinary Kubernetes Secret, replace
ConfigMaps, choose pod annotations and SAN requests, change container
arguments and mounts, and schedule privileged workloads. The attacker wants
an OpenBao credential or any workload secret released to an identity it
controls.

The current broker path has five control-plane-controlled inputs:

| Input | Current source | Consequence |
|---|---|---|
| Release rules | `releasePolicy` ConfigMap | The attacker grants its identity any path. |
| OpenBao token/AppRole secret ID | Kubernetes Secret | The attacker bypasses the broker and reads OpenBao directly. |
| Workload identity | CDS-issued DNS SAN selected from pod metadata | The attacker requests an allowed identity. |
| Broker image, arguments, and trust roots | Pod spec and mounted volumes | The attacker replaces or reconfigures the enforcement point. |
| LUKS device access | Privileged init container with `/dev` | On a shared node, the selected workload receives host-device access. |

A node quote does not fix these inputs. In node-as-CVM modes, all pods share
the measured node and are only kernel-isolated; the quote neither identifies a
particular workload nor commits to its runtime pod spec.

## Decision

1. `secretBroker.enabled=true` fails chart rendering by default. The only
   current escape hatch is `secretBroker.insecureTrustControlPlane=true`,
   explicitly limited to dev/test deployments where Kubernetes is inside the
   trust boundary.
2. The escape hatch is an operational acknowledgement, not a security
   control. A hostile control plane can change the value or deploy different
   resources, so it cannot make secret release safe.
3. RA-TLS caller and store verification require non-empty measurement
   allowlists. Development must select the explicit `ca` or external-store
   paths instead of silently accepting any TEE. The current TDX verifier drops
   measurement pins, so TDX remains unsupported for measurement-authorized
   secret release even when a list is present.
4. LUKS injection is disabled by default and requires `kata.enabled=true`.
   Admission additionally requires the pod to use the platform's confidential
   Kata class and rejects host namespaces. Node-as-CVM is not a per-workload
   boundary for a privileged `/dev` mount.
5. Node-as-CVM is not a break-glass secret-release path.

These chart and runtime safety rails protect honest operators. They
deliberately make the unsupported state unavailable instead of claiming they
can defend against the administrator that controls their deployment.

## Invariants

- No chart-supported deployment claims adversarial-control-plane secret
  release while authorization or reusable credential inputs remain ordinary
  Kubernetes objects.
- The chart and broker reject empty, blank, malformed, or non-SHA-384
  measurement lists instead of silently configuring “any valid TEE.” This does
  not close the separately documented TDX measurement-enforcement gap.
- No ordinary node-as-CVM, host-namespace, or non-confidential-runtime pod
  receives the LUKS init container's privileged host-device access.
- Documentation and tests distinguish functional dev/test coverage from a
  production confidentiality guarantee.

## Requirements to lift the gate

All load-bearing inputs must move outside Kubernetes trust and be bound in one
verifiable chain:

1. Generate a broker key inside an attested CVM and make OpenBao issue a
   short-lived, least-privilege credential only to that key. Kubernetes may
   carry ciphertext or a single-use wrapped response, never a reusable store
   credential.
2. Bind a signed, versioned release-policy digest, broker image digest,
   load-bearing arguments, trust roots, and the credential public key to
   measured `HOST_DATA`/initdata. Binding only one input leaves swap-restart
   attacks on the others.
3. Authorize composed evidence that binds the node or pod quote, enforced
   workload spec, workload identity, freshness nonce, and CSR/transport public
   key. A DNS SAN by itself is not attested identity. TDX evidence must expose
   and enforce its workload/launch measurement rather than dropping the pin.
4. Use a per-pod CVM, or add a pre-Kubernetes measured node enforcer that
   validates the full runtime spec (image, args, env, mounts, capabilities,
   devices, namespaces, and exec) before node-level evidence can authorize a
   workload.
5. Make OpenBao deny direct use of any obsolete or replayed bootstrap
   credential, and define credential rotation and revocation.

Kubernetes Secret encryption at rest, RBAC, immutable ConfigMaps, admission
webhooks, and node labels are useful operational hardening, but none is a
boundary against the control plane that administers them.
