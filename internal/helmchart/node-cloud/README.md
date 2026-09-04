# c8s-node-cloud

Node-as-CVM on cloud-managed confidential VM nodes (GKE, AKS): every node is
one confidential VM and all its pods share that one trust domain.
Single-tenant.

Installs the c8s operator, webhook, CDS trust root, ratls-mesh DaemonSet,
attestation-api DaemonSet, the NRI image-policy installer, and the tls-lb
front door. Evidence comes from the node's native TEE device (GKE) or the
Azure vTPM (`platform: az-snp | az-tdx`).

Key values: `platform` (snp | tdx | az-snp | az-tdx), `distro`,
`attestationApi.*`, `ratlsMesh.*`, `nriImagePolicy.*`, `cds.*`, `tlsLb.*`.
See docs/install-flows.md.

Install: `c8s install --cvm-mode=node-cloud` (`--evidence=vtpm` for AKS).
