# Integration tests

Two harnesses run in CI on plain GitHub-hosted runners (no TEE hardware), plus
live-cluster scripts that run on the metal lanes. This doc maps what each
covers and why the kind harness is shaped the way it is.

| Harness | Entrypoint | CI job | Subject |
| --- | --- | --- | --- |
| docker-compose | `make test-integration` | Integration | get-cert's RA-TLS flow against mock CDS + mock attestation-api, nginx serving the issued leaf |
| kind cluster | `make test-integration-cluster` | Integration (cluster) | the full node-mode control plane and workload path (below) |
| live-cluster scripts | `test/e2e/*.sh` | snp/tdx-metal-e2e | cw-label policy, mesh enforcement, CA handoff on real TEEs |

## The kind harness

`test/integration/cluster/run.sh` boots a single-node kind cluster, builds the
component images from the checkout, and runs the real `c8s install
--cvm-mode=node`. The TEE is substituted at exactly one point: **evidence
generation**. `test/mock-attestation` serves synthetic SNP reports (launch
digest all-zero) on the node IP :8400 — the address node-mode consumers dial
for the node-baked api — and an `attest-proxy` sidecar publishes it on the
hostPath unix socket the host plugin uses. Every component that delegates
verification to the attestation-api (get-cert, CDS, ratls-mesh, the NRI
plugin) works unchanged against it. The all-zero digest is pinned via
`--measurements`, so every RA-TLS hop is verified exactly as in production.

The NRI image-policy plugin runs for real: the harness renders the chart's
installer DaemonSet and applies it out-of-band (node mode does not render it —
production node images bake the plugin). The installer patches the node's
containerd config and restarts it, which kind survives. The install-time
allowlist floor is generated from the node containerd's image store, because
`policy.enforceExisting` checks already-running containers against it.

Two operator-facing commands verify evidence **in-process** with real hardware
cryptography, which synthetic evidence cannot pass: `c8s verify` and the `c8s
allowlist` CLI. Those stay on the metal lanes. The harness still exercises the
allowlist write path server-side: writes are signed with the production
`pkg/operatorauth` signer (`optoken/`) and CDS performs its full token
verification — only the client-side evidence check is skipped (curl `-k` over
a port-forward).

## Covered scenarios

- `c8s install` end-to-end: preflights, helm install, CRDs, RBAC,
  MutatingWebhookConfiguration, ValidatingAdmissionPolicies.
- Control-plane readiness: operator, CDS (RA-TLS serving cert via the mock
  api), tls-lb (mesh cert from CDS), ratls-mesh DaemonSet.
- NRI plugin: installer writes the binary + config, patches containerd,
  restarts it, registers, serves the admission inventory socket.
- Allowlist authorization: unsigned writes and wrong-key writes are 401; a
  write signed by the pinned operator key lands, is served, and deletes.
- Webhook injection: `confidential.ai/cw` pods gain the get-cert sidecar, the
  wait gate, and the cw label; the operator provisions the `c8s-<id>` headless
  Service.
- Workload identity: get-cert redeems a sandbox token from the NRI admission
  inventory, CDS calls the digests endpoint back, and the issued leaf carries
  the workload's in-cluster DNS SAN.
- Image admission, fail-closed: a non-allowlisted image is denied at
  container creation; a signed allowlist write flips the same pod to Running
  after the plugin's next pull.
- Admission rejections: cw label/annotation mismatch (webhook) and
  hostNetwork tenant pods (host-namespace policy).
- Mesh: a pod-IP dial to a cw workload is wrapped (the inbound counter
  moves); a dial from a mesh-excluded namespace hits the FORWARD guard and
  DROPs, and a Service-VIP dial is either dropped or mesh-wrapped — never
  plaintext — proven by the drop/wrap counters (rule ordering between
  kube-proxy and the mesh is not stable). Mirrors
  `test/e2e/mesh-cw-enforcement.sh`.
- tls-lb front door: HTTPS verified against the CDS mesh CA.
- Workload adoption: `c8s install --workload-ref` patches a running
  deployment, its rollout goes through injection, the status mirror reports
  `kubectl get cwl`, and tls-lb routes the front door to it over the mesh.
- `c8s uninstall`: release, webhook, and admission policies are removed.

## Deliberately out of scope

No TEE properties are asserted: hardware verification, measurements that mean
anything, kata guests, encrypted volumes (volumed needs device-mapper control
of the node kernel), `get-kubeconfig` (SNP-gated), CDS handoff (two CDS
replicas), and the `c8s allowlist`/`c8s verify` CLIs (in-process hardware
verification, above). The metal lanes (snp-metal-e2e, tdx-metal-e2e,
cvm-e2e) own those.

## Running it

```sh
make test-integration-cluster
```

Needs docker (or podman with `KIND_EXPERIMENTAL_PROVIDER=podman`), kind,
kubectl, helm, go, openssl, curl, python3. The kind node image is pinned by
digest in run.sh; bump it with the kind release. CI installs kind itself
(`.github/workflows/ci.yml`, pinned binary sha256).

### Failure notes

- A pod stuck `CreateContainerError` with `image not in allowlist` is the NRI
  plugin doing its job: the image's containerd store digest is missing from
  the floor. The floor is written from the node's image store before install,
  so an image first pulled *during* the run lands here — pre-pull it next to
  the other fixtures in run.sh.
- The mock-attestation deployment is `Recreate` on purpose: two hostNetwork
  pods cannot both bind :8400 on a single-node cluster.
