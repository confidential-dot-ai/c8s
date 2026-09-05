# c8s demo

This demo uses chart-managed CDS so the certificate bootstrap
path is self-contained. It is intended for review and demos, not as the final
production trust boundary.

## 1. Install c8s

This demo shows confidential-workload injection, not the public front door, so
it installs with tls-lb disabled. To also expose a workload through tls-lb, give
it an upstream instead (see [tls-lb upstream](operator.md#tls-lb-upstream)).

```sh
c8s install --namespace c8s-system --cvm-mode=node --hardware-platform=sev-snp \
  --operator-keys operator-pub.pem -f - <<'EOF'
tlsLb:
  enabled: false
EOF
```

`--cvm-mode` is required (`pod`, `node`, `gke`, or `aks` — see
[install-flows.md](install-flows.md)), as is `--hardware-platform` (`sev-snp`
or `tdx`). `--operator-keys` points at a PEM bundle
of EC public keys authorizing `c8s allowlist` writes (or pass `--force` to
install with writes disabled).

## 2. Apply optional CRD object

CRDs are advisory. This object is useful for status display and review:

```sh
kubectl apply -f samples/confidentialworkload.yaml
```

## 3. Deploy an annotated workload

The node image enforces the restricted PodSecurity standard in every tenant
namespace. In node mode the injected sidecar mounts the node's inventory
socket as a hostPath, which restricted forbids, so a namespace that hosts
confidential workloads is opened by the operator. Only a credential allowed
to grant PodSecurity exemptions can set this label; tenants cannot. The chart
still enforces Restricted-equivalent pod security there and permits only the
webhook's exact read-only socket mount on its own sidecars. `warn` and `audit`
stay Restricted so the expected exception and any drift remain observable.

```sh
kubectl create namespace demo
kubectl label namespace demo \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
kubectl -n demo apply -f samples/nginx-confidential-pod.yaml
```

The pod template annotation `confidential.ai/cw: demo-nginx` is the security
opt-in. The `ConfidentialWorkload` object is not required for injection.

## 4. Inspect the result

```sh
kubectl -n demo get pods
kubectl -n demo describe pod -l app=demo-nginx
kubectl get cwl -A
```

Expected injected pieces:

- an init container and renewal sidecar running `c8s get-cert`;
- an in-memory `c8s-certs` volume;
- workload containers mounting `/etc/c8s/certs`;
- no injected credential Secret references.

## Reset

```sh
kubectl delete namespace demo
kubectl delete -f samples/confidentialworkload.yaml
c8s uninstall
```

`c8s uninstall` wraps `helm uninstall c8s -n c8s-system`; on a `--cvm-mode=pod`
install it also sweeps the kata runtime artifacts off the nodes (see
[`kata.md`](kata.md#uninstalling)).
