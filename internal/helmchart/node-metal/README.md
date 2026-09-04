# c8s-node-metal

Node-as-CVM on self-managed bare-metal CVM nodes: every node is one
confidential VM (SEV-SNP or Intel TDX) running ordinary Kubernetes pods.
Single-tenant.

Same component set as c8s-node-cloud (operator, webhook, CDS, ratls-mesh,
attestation-api DaemonSet, NRI image-policy installer, tls-lb) with
bare-metal defaults (RKE2 distro, no provider namespace exemptions). Use this
chart when your CVM nodes run your own OS — for nodes booted from the c8s
node-guest-image use c8s-node-image instead, which renders far less.

Key values: `platform` (snp | tdx), `distro`, `attestationApi.*`,
`ratlsMesh.*`, `nriImagePolicy.*`, `cds.*`, `tlsLb.*`. See
docs/install-flows.md.

Install: `c8s install --cvm-mode=node-metal`.
