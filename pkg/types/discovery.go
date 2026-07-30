package types

import "encoding/json"

// DiscoveryDocument is the /v1/discovery preflight document the tls-lb serves
// (written by get-cert): the CDS-issued serving certificate plus the attestation
// evidence captured at issuance. It is the wire contract shared between the
// producer (get-cert) and consumers (c8s verify, c8s-verify-js).
type DiscoveryDocument struct {
	Version     string                `json:"version"`
	GeneratedAt string                `json:"generated_at"`
	PublicTLS   PublicTLSDiscovery    `json:"public_tls"`
	CDSTLS      CDSTLSDiscovery       `json:"cds_tls"`
	CDSIdentity *CDSIdentityDiscovery `json:"cds_identity,omitempty"`
	Attestation AttestationDiscovery  `json:"attestation"`
}

// CDSIdentityDiscovery carries CDS's OWN RA-TLS certificate — the trust root a
// client attests once and then caches.
//
// Not to be confused with CDSTLSDiscovery, which is the certificate CDS ISSUED
// to this workload. The distinction is the whole point of this field: cds_tls
// is a leaf whose SAN is the workload, signed by the mesh CA; cds_identity is
// CDS's self-signed certificate carrying its own TDX evidence and config-claims
// (mesh-CA digest, live-allowlist digest). Verifying cds_tls tells you nothing
// about who CDS is; verifying cds_identity is what authenticates the mesh CA
// that cds_tls chains to.
//
// It is republished by the workload that already verified it during issuance,
// so a client can complete the attest-once step without reaching CDS — CDS is
// typically cluster-internal and not routable from a browser. Republishing is
// safe because the certificate is self-authenticating: it carries hardware
// evidence binding its own public key and claims, so a tampered or forged
// copy fails verification at the client. It does NOT prove freshness: the
// certificate carries no client challenge, so an older genuine one substituted
// here still verifies until it expires. Clients must enforce the validity
// window (and refuse notBefore rollback where they cache) to bound that
// staleness — hardware evidence alone gives no replay immunity.
type CDSIdentityDiscovery struct {
	// CertificatePEM is CDS's self-signed RA-TLS certificate.
	CertificatePEM string `json:"certificate_pem"`
	// CertificateSHA256 is SHA-256 of its DER — the cache key. CDS re-issues
	// this certificate whenever the live allowlist changes, so a changed
	// fingerprint is precisely the signal to re-attest.
	CertificateSHA256 string `json:"certificate_sha256"`
	// ObservedAt is when the publishing workload verified it (RFC3339).
	// Informational only — it travels outside the certificate and outside any
	// signature, so it is trivially forgeable and MUST NOT be a trust input.
	// Freshness judgements come from the certificate's signed validity window.
	ObservedAt string `json:"observed_at,omitempty"`
}

// PublicTLSDiscovery describes the public-facing TLS identity (hostname + mode).
type PublicTLSDiscovery struct {
	Hostname string `json:"hostname"`
	Mode     string `json:"mode"`
}

// CDSTLSDiscovery carries the CDS-issued serving certificate and where it (and
// the mesh CA) are served.
type CDSTLSDiscovery struct {
	CertificatePEM    string `json:"certificate_pem"`
	CertificateSHA256 string `json:"certificate_sha256"`
	CertificateURL    string `json:"certificate_url,omitempty"`
	MeshCAURL         string `json:"mesh_ca_url,omitempty"`
}

// AttestationDiscovery carries the issuance challenge plus the platform-specific
// attestation evidence object, kept raw so it is forwarded verbatim to
// verification (SEV-SNP, TDX, …).
type AttestationDiscovery struct {
	Challenge string          `json:"challenge"`
	Platform  string          `json:"platform"`
	Evidence  json.RawMessage `json:"evidence"`
}
