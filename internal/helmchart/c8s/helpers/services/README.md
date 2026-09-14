# Service and attestation helpers

Source: [templates/_services.tpl](../../templates/_services.tpl).
[All helpers](../README.md).

`c8s.attestationApiSocketPresent` is the one predicate for "a node-local
attestation socket exists": non-empty when `attestationApi.enabled` or
`node.bakedServices` is set. The helpers below branch on it.

`c8s.attestationApiURL` selects the endpoint available to its consumer:

| Values | Endpoint |
| --- | --- |
| `attestationApi.enabled=true` or `node.bakedServices=true` | Node-local `unix://<runtimeDir>/attestation-api.sock` |
| `attestationApi.enabled=false` and `node.bakedServices=false` (legacy bare-metal mode only) | Node-baked service, `http://$(HOST_IP):<port>` |

The chart-managed attestation API binds pod loopback. Its attest-proxy exposes
the node-local socket in `nriImagePolicy.hostPaths.runtimeDir`.
When either the chart API or baked services are enabled, the socket volume/mount
helpers expose the directory to chart components at its host path with a read-only mount and
`DirectoryOrCreate` hostPath. The webhook rebases the socket path for injected
get-cert sidecars, and nri-image-policy NRI-mounts the directory read-only into
those sidecars.

In legacy bare-metal CVM mode with both the chart API and baked services disabled, `c8s.attestationApiHostIPEnv`
renders the downward-API `HOST_IP` variable. Kubelet expands the placeholder
against each consumer's node. The operator forwards the URL to tenant sidecars
with the placeholder intact, so its own container must leave `HOST_IP` unset.
`c8s.attestationApiConfig` takes a dict with `root` and renders the API's TOML.

With `node.bakedServices=true`, the attester and proxy run as systemd services.
The operator obtains the signed leader endpoint and complete CDS identity policy
from `c8s-node-runtime`; workload sidecars retain NRI socket injection.

`c8s.cdsURL` builds the in-cluster CDS Service URL; `c8s.trustRootURL` delegates
to it. `c8s.nriCDSURL` uses `nriImagePolicy.cds.url` when supplied, otherwise
`https://127.0.0.1:<cds.service.nodePort>` for the host plugin.

`c8s.router.resolver` honors `router.nginx.resolver`. Otherwise `nriImagePolicy.distro=rke2`
selects `rke2-coredns-rke2-coredns.kube-system.svc.cluster.local`;
the default is `kube-dns.kube-system.svc.cluster.local`. Nginx must resolve this
name at startup.
