# c8s demo

This demo uses chart-managed CDS so the certificate bootstrap
path is self-contained. It is intended for review and demos, not as the final
production trust boundary.

## 1. Install c8s

This demo shows confidential-workload injection, not the public front door, so
it installs with tls-lb disabled. To also expose a workload through tls-lb, give
it an upstream instead (see [tls-lb upstream](operator.md#tls-lb-upstream)).

Generate `operator-pub.pem` and set `C8S_NODE_MEASUREMENT` from the trusted
node image manifest as described in the [quickstart](QUICKSTART.md). Label a
CDS node `role=cds`, or add `--single-node` for a one-node cluster.

```sh
c8s install --namespace c8s-system --cvm-mode=node --hardware-platform=sev-snp \
  --operator-keys operator-pub.pem --measurements "$C8S_NODE_MEASUREMENT" -f - <<'EOF'
tlsLb:
  enabled: false
EOF
```

`--cvm-mode` is required (`node`, `gke`, or `aks` — see
[install-flows.md](install-flows.md)), as is `--hardware-platform` (`sev-snp`
or `tdx`). `--operator-keys` points at a PEM bundle
of EC public keys authorizing `c8s allowlist` writes (or pass `--force` to
install with writes disabled).

## 2. Deploy an annotated workload

CRDs are advisory. This object is useful for status display and review:

```sh
kubectl apply -f samples/confidentialworkload.yaml
```

## 3. Deploy an annotated workload

The node image enforces the Restricted PodSecurity standard in every tenant
namespace, including namespaces hosting confidential workloads. In node mode,
`nri-image-policy` mounts the inventory socket directory read-only into credential
sidecars through NRI, below the Pod spec. The chart also enforces Restricted
controls and denies every tenant `hostPath` volume. Keep enforcement, warning,
and audit at Restricted:

```sh
kubectl create namespace demo
kubectl label namespace demo \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
kubectl -n demo apply -f samples/nginx-confidential-pod.yaml
```

The pod template annotation `confidential.ai/cw: demo-nginx` is the security
opt-in. The `ConfidentialWorkload` object is not required for injection.

## 3. Inspect the result

```sh
kubectl -n demo get pods
kubectl -n demo describe pod -l app=demo-nginx
```

Expected injected pieces:

- a native `c8s get-cert` sidecar and a `c8s-cert-wait` init gate;
- an in-memory `c8s-certs` volume;
- workload containers mounting `/etc/c8s/certs`;
- no injected credential Secret references.

## Reset

```sh
kubectl delete namespace demo
c8s uninstall
```
