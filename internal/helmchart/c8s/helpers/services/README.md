# Service and attestation helpers

Source: [templates/_services.tpl](../../templates/_services.tpl).
[All helpers](../README.md).

`c8s.attestationApiURL` selects the endpoint available to its consumer:

| Values | Endpoint |
| --- | --- |
| `kata.enabled` | Guest loopback, `http://127.0.0.1:<port>` |
| Otherwise, `attestationApi.enabled` | Node-local `unix://<runtimeDir>/attestation-api.sock` |
| Otherwise | Node-baked service, `http://$(HOST_IP):<port>` |

The chart-managed attestation API binds pod loopback. Its attest-proxy exposes
the node-local socket in `nriImagePolicy.hostPaths.runtimeDir`.
`c8s.attestationApiHostSocket` selects this mode, and the socket volume/mount
helpers expose the directory at its host path with a read-only mount and
`DirectoryOrCreate` hostPath. The webhook rebases the socket path for injected
get-cert sidecars.

In node CVM mode with the chart API disabled, `c8s.attestationApiHostIPEnv`
renders the downward-API `HOST_IP` variable. Kubelet expands the placeholder
against each consumer's node. The operator forwards the URL to tenant sidecars
with the placeholder intact, so its own container must leave `HOST_IP` unset.
`c8s.attestationApiConfig` takes a dict with `root` and renders the API's TOML.

`c8s.cdsURL` builds the in-cluster CDS Service URL; `c8s.trustRootURL` delegates
to it. `c8s.nriCDSURL` uses `nriImagePolicy.cds.url` when supplied, otherwise
`https://127.0.0.1:<cds.service.nodePort>` for the host plugin.

`c8s.tlsLb.resolver` honors `tlsLb.nginx.resolver`. Otherwise either distro value
being `rke2` selects `rke2-coredns-rke2-coredns.kube-system.svc.cluster.local`;
the default is `kube-dns.kube-system.svc.cluster.local`. Nginx must resolve this
name at startup.
