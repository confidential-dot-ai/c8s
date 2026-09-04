# c8s-node-image

Node-as-CVM on nodes booted from the c8s node-guest-image. The image bakes the
attestation-api and the NRI image-policy plugin (measured at build time), so
the chart installs only what the image cannot carry: the c8s operator,
webhook, CDS trust root, ratls-mesh DaemonSet, tls-lb — and a pins-only NRI
installer that writes this release's CDS measurements/RTMRs into the baked
plugin's config. Nodes are always RKE2 (distro implied, not a value).

Key values: `platform` (snp | tdx), `ratlsMesh.*`, `nriImagePolicy.*` (pins
installer + bootstrapAllowlist), `cds.*`, `tlsLb.*`. See
docs/install-flows.md and node-guest-image/README.md.

Install: `c8s install --cvm-mode=node-image`.
