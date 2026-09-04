# c8s-pod

Pod-as-CVM: every in-scope workload pod is a kata confidential VM (SEV-SNP or
Intel TDX) and the host is adversarial. Multi-tenant: each pod carries its own
launch digest.

Installs:

- the kata runtime (`kata-deploy`) and the confidential RuntimeClasses,
  enforced by the operator's mutating webhook (injects a kata RuntimeClass
  into in-scope pods) and a ValidatingAdmissionPolicy (rejects non-kata pods)
- the guest-image pullers (CPU and NVIDIA) staging the measured kata-guest-base
- the c8s operator, webhook, CDS trust root, and tls-lb front door — CDS and
  tls-lb run as kata CVMs themselves
- the NVIDIA sandbox device plugin

Host-side attestation, mesh routing, and image admission are not chart
resources here: they are baked into the measured guest image (attestation-api
on loopback, in-guest ratls-mesh, in-guest policy-monitor fed from CDS's
allowlist).

Key values: `platform` (snp | tdx), `kata.*`, `cds.*`, `tlsLb.*`, `webhook.*`,
`nriImagePolicy.bootstrapAllowlist` (the image floor the in-guest monitor
pulls from CDS). See docs/install-flows.md and docs/kata.md.

Install: `c8s install --cvm-mode=pod`.
