package issuer

import (
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/teewebpki"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// CAProvisionConfig configures how CDS obtains its mesh CA at startup.
type CAProvisionConfig struct {
	// CommonName and Validity are used only when generating a fresh CA
	// (PeerURL empty).
	CommonName string
	Validity   time.Duration
	// Curve for a generated CA; nil defaults to P-384 (the mesh CA curve).
	Curve elliptic.Curve

	// PeerURL is a surviving CDS peer's https base URL. Empty means cold
	// start: generate a fresh self-signed CA. Non-empty means adopt the
	// peer's CA via /handoff, and fail closed if that does not succeed.
	PeerURL string
	// AttestationApiURL is the local attestation-api used to attest this
	// node's handoff signer key. Required when PeerURL is set.
	AttestationApiURL string
	// Measurements pins the peer's launch digest on both the RA-TLS serving
	// cert and the handoff issuer EAR. Required when PeerURL is set.
	Measurements []string
	// RTMRs pins the peer's TDX runtime measurement registers on the RA-TLS
	// adopt dial, as <index>=<sha384-hex> entries. On TDX the launch digest
	// covers TDVF firmware alone, so without these the dial trusts a peer
	// whose kernel and rootfs the host chose. SNP peers are unaffected;
	// optional.
	RTMRs []string
	// ExpectedIssuer is the EAR issuer claim required on the peer's handoff
	// EAR (the peer's --ear-issuer; "cds" by default).
	ExpectedIssuer string
	// Timeout bounds the adopt attempt. PullHandoff retries transient
	// failures until this elapses; a peer still unreachable at the deadline
	// is a fail-closed error, not a cue to self-generate.
	Timeout time.Duration
	// OperatorKeysHash is the canonical local operator-key policy committed
	// into both sides' handoff attestations.
	OperatorKeysHash string
	// ClusterIdentityCertFile and ClusterIdentityKeyFile hold the
	// predecessor-issued mesh identity of this successor. The files stay on
	// TEE memory. The request signs with this key and presents the same
	// identity on the mTLS connection.
	ClusterIdentityCertFile string
	ClusterIdentityKeyFile  string
	// RestoreAllowlist atomically installs the peer's encrypted allowlist
	// snapshot (floor and workloads) before CDS serves. Required when PeerURL is
	// set, so adoption cannot preserve the CA while resetting runtime policy.
	RestoreAllowlist func(version string, al *allowlist.Allowlist) error
	// RestoreTEEWebPKI installs protected cluster TLS state before CDS starts.
	// It is required only when the predecessor carries tee-webpki state.
	RestoreTEEWebPKI func(snapshot teewebpki.Snapshot) error
	// RestoreSecrets installs the complete encrypted application-secret
	// snapshot before the successor starts. When set, a missing snapshot is a
	// fatal downgrade because continuing would destroy live secret state.
	RestoreSecrets func(snapshot secrets.Snapshot) error
	// OnAdopt receives the activation function after every state restorer
	// succeeds. The caller starts the successor server before it invokes this.
	OnAdopt func(activate func(context.Context) error)
}

// caPuller adopts a CA from the configured peer. It is a seam so the
// generate/adopt/fail-closed policy can be tested without a live RA-TLS peer.
type caPuller func(ctx context.Context, cfg CAProvisionConfig, logger *slog.Logger) (*HandoffMaterial, error)

// ProvisionCA returns CDS's startup mesh CA and whether it was adopted from a
// peer, using the default RA-TLS puller. See provisionCA for the policy.
func ProvisionCA(ctx context.Context, cfg CAProvisionConfig, logger *slog.Logger) (ca *CA, adopted bool, err error) {
	return provisionCA(ctx, cfg, logger, adoptFromPeer)
}

// provisionCA implements the binary provisioning policy:
//
//   - PeerURL empty  -> generate a fresh self-signed CA (cold start / first
//     CDS). adopted=false.
//   - PeerURL set    -> adopt the peer's CA via pull. Any error (a denial, or
//     the peer unreachable within Timeout) is fatal: CDS must not mint a
//     divergent trust root when an operator has said a peer exists.
//
// It never silently falls back from a configured peer to a generated CA — that
// is the exact failure (a transient partition regenerating the trust root)
// this path exists to prevent.
func provisionCA(ctx context.Context, cfg CAProvisionConfig, logger *slog.Logger, pull caPuller) (*CA, bool, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.PeerURL == "" {
		curve := cfg.Curve
		if curve == nil {
			curve = elliptic.P384()
		}
		generated, err := NewCAWithCurve(cfg.CommonName, cfg.Validity, curve)
		if err != nil {
			return nil, false, err
		}
		return generated, false, nil
	}
	if cfg.RestoreAllowlist == nil {
		return nil, false, fmt.Errorf("adopting a CA requires an allowlist snapshot restorer")
	}
	if err := operatorauth.ValidateKeySetHash(cfg.OperatorKeysHash); err != nil {
		return nil, false, fmt.Errorf("adopting a CA requires an operator-key policy: %w", err)
	}

	material, err := pull(ctx, cfg, logger)
	if err != nil {
		return nil, false, fmt.Errorf("adopt mesh CA from peer %s (no fallback; if no peer survives, unset --handoff-peer-url to re-bootstrap deliberately): %w", cfg.PeerURL, err)
	}
	// Adoption carries a single self-signed root today; refuse chains or
	// rotation bundles rather than silently drop trust material.
	if material.ParentCert != nil || len(material.Bundle) > 1 {
		return nil, false, fmt.Errorf("peer %s handed off a chained or multi-cert CA (parent=%t, bundle=%d certs); adoption supports a single self-signed mesh CA", cfg.PeerURL, material.ParentCert != nil, len(material.Bundle))
	}
	floor := make(map[string]string, len(material.Allowlist))
	for d, img := range material.Allowlist {
		floor[d.String()] = img
	}
	snapshot := &allowlist.Allowlist{Schema: allowlist.Schema, Digests: floor, Workloads: material.Workloads}
	if err := cfg.RestoreAllowlist(material.AllowlistVersion, snapshot); err != nil {
		return nil, false, fmt.Errorf("restore allowlist snapshot from peer %s: %w", cfg.PeerURL, err)
	}
	if material.TEEWebPKI != nil {
		if cfg.RestoreTEEWebPKI == nil {
			return nil, false, fmt.Errorf("peer %s handed off tee-webpki state but no restorer is configured", cfg.PeerURL)
		}
		if err := cfg.RestoreTEEWebPKI(*material.TEEWebPKI); err != nil {
			return nil, false, fmt.Errorf("restore tee-webpki state from peer %s: %w", cfg.PeerURL, err)
		}
	}
	if cfg.RestoreSecrets != nil {
		if material.Secrets == nil {
			return nil, false, fmt.Errorf("peer %s handed off no application-secret state", cfg.PeerURL)
		}
		if err := cfg.RestoreSecrets(*material.Secrets); err != nil {
			return nil, false, fmt.Errorf("restore application-secret snapshot from peer %s: %w", cfg.PeerURL, err)
		}
	}
	if cfg.OnAdopt == nil {
		return nil, false, fmt.Errorf("adopting a CA requires an activation receiver")
	}
	cfg.OnAdopt(material.Activate)
	return &CA{Cert: material.CACert, Key: material.CAKey}, true, nil
}

// adoptFromPeer builds the requester client stack and pulls the peer's CA. It
// is the in-process twin of the `c8s cds request-handoff` command.
func adoptFromPeer(ctx context.Context, cfg CAProvisionConfig, logger *slog.Logger) (*HandoffMaterial, error) {
	if cfg.AttestationApiURL == "" {
		return nil, fmt.Errorf("attestation-api URL is required to adopt a CA")
	}
	pinned, err := ratls.ParseHexMeasurementsList(cfg.Measurements)
	if err != nil {
		return nil, fmt.Errorf("parse handoff measurements: %w", err)
	}
	if len(pinned) == 0 {
		return nil, fmt.Errorf("adopting a CA requires pinned peer measurements")
	}
	rtmrPins, err := ratls.ParseRTMRPins(cfg.RTMRs)
	if err != nil {
		return nil, fmt.Errorf("parse handoff RTMR pins: %w", err)
	}
	// The same digest set pins both channels; the EAR-side map is derived
	// from the validated digests so the two representations stay in sync.
	allowed := make(map[string]bool, len(pinned))
	for _, m := range pinned {
		allowed[hex.EncodeToString(m)] = true
	}

	identity, err := tls.LoadX509KeyPair(cfg.ClusterIdentityCertFile, cfg.ClusterIdentityKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load successor live-cluster identity: %w", err)
	}
	httpClient, err := handoffPeerClient(ratls.Pins{Measurements: pinned, RTMRs: rtmrPins}, cfg.AttestationApiURL, cfg.ClusterIdentityCertFile, cfg.ClusterIdentityKeyFile)
	if err != nil {
		return nil, err
	}

	// The JWKS cache must outlive the pull deadline (a kid-miss refresh can
	// run at its edge) but not the process: stop its refresher on return.
	provCtx, cancelProv := context.WithCancel(ctx)
	defer cancelProv()
	keyProvider, err := NewJWKSKeyProvider(provCtx, cfg.PeerURL+"/.well-known/jwks.json", time.Minute, httpClient, logger)
	if err != nil {
		return nil, fmt.Errorf("build peer JWKS key provider: %w", err)
	}

	pullCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	return PullHandoff(pullCtx, PullConfig{
		Deps: HandoffClientDeps{
			KeyProvider:         keyProvider,
			ExpectedIssuer:      cfg.ExpectedIssuer,
			AllowedMeasurements: allowed,
			OperatorKeysHash:    cfg.OperatorKeysHash,
			ClusterIdentity:     &identity,
		},
		Attest:            attestclient.NewClientWithHTTP(cfg.PeerURL, httpClient),
		PeerURL:           cfg.PeerURL,
		AttestationApiURL: cfg.AttestationApiURL,
		HTTPClient:        httpClient,
		Logger:            logger,
	})
}

// handoffPeerClient verifies the predecessor's RA-TLS identity and reloads
// the successor's mesh identity for each new TLS connection. get-cert first
// writes an unnamed leaf, then renews it with the matched-workload stamp after
// the CDS container starts. Reloading lets the pull retry cross that boundary
// without restarting the successor.
func handoffPeerClient(pins ratls.Pins, attestationAPIURL, certFile, keyFile string) (*http.Client, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("successor cluster identity certificate and key files are required")
	}
	client, err := ratls.NewVerifyingHTTPClient(pins, attestationAPIURL)
	if err != nil {
		return nil, err
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return nil, fmt.Errorf("RA-TLS client has no configurable TLS transport")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("reload successor live-cluster identity: %w", err)
		}
		return &cert, nil
	}
	client.Transport = transport
	return client, nil
}
