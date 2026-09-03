// Package cds implements the Certificate Distribution Service subcommand:
// the c8s trust root (attestation, EAR issuance, mesh CA, leaf signing).
package cds

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/verify"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const (
	defaultHTTPReadTimeout       = 10 * time.Second
	defaultHTTPReadHeaderTimeout = 5 * time.Second
	defaultHTTPWriteTimeout      = 10 * time.Second
	defaultHTTPIdleTimeout       = 20 * time.Second
	defaultHTTPMaxHeaderBytes    = 1 << 20
)

// NewCmd returns the cobra subcommand.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "cds",
		Short: "Run the Certificate Distribution Service (CDS)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRATLSPlatformFlag(cfg.ratlsPlatform); err != nil {
				return err
			}
			return run(cfg)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&cfg.host, "host", "0.0.0.0", "")
	flags.IntVarP(&cfg.port, "port", "p", 8443, "")
	flags.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")

	flags.StringVar(&cfg.attestationApiURL, "attestation-api-url", "", "URL of the attestation-api service")
	flags.StringVar(&cfg.caCommonName, "ca-common-name", issuer.DefaultCACommonName, "common name for the in-memory generated mesh CA")
	flags.DurationVar(&cfg.caCertValidity, "ca-cert-validity", 8760*time.Hour, "validity period of the in-memory mesh CA certificate")
	flags.StringSliceVar(&cfg.measurements, "measurements", nil, "SHA-384 hex launch measurements allowed to call /attest (empty = no pinning, UNSAFE)")
	flags.StringVar(&cfg.measurementsConfig, "measurements-config", "", "path to a measurements config listing the VM images this cluster runs, each matched as a whole image (launch digest plus, on TDX, that image's registers). Every listed image may call /attest; the same file pins CDS itself for the components that dial it, so any listed image may serve as CDS. Cannot be combined with --measurements or --rtmrs")
	flags.StringSliceVar(&cfg.rtmrs, "rtmrs", nil, "TDX RTMR pins <index>=<sha384-hex> required of TDX callers on /attest and /attest-key (repeatable; RTMR[1] pins the guest kernel, RTMR[2] the command line carrying the dm-verity root hash). SNP evidence is unaffected. Empty = no RTMR pinning: on TDX the reference values then cover TDVF firmware only, UNSAFE")

	flags.StringVar(&cfg.earIssuerName, "ear-issuer", "cds", "")
	flags.StringVar(&cfg.expectedIssuer, "expected-issuer", "", "EAR JWT issuer claim required on /sign-csr (empty disables)")
	flags.Int64Var(&cfg.jwtClockSkew, "jwt-clock-skew", 30, "EAR JWT exp/nbf/iat clock skew tolerance in seconds")
	flags.DurationVar(&cfg.maxTTL, "max-ttl", 24*time.Hour, "upper bound on /sign-csr leaf TTL")
	flags.DurationVar(&cfg.certTTL, "cert-ttl", 24*time.Hour, "")
	flags.DurationVar(&cfg.namedCertTTL, "named-cert-ttl", issuer.MaxNamedLeafTTL, "upper bound on the TTL of a leaf carrying a matched-workload stamp — the documented stale-identity bound for a named leaf (never applied to membership-only leaves). Must be positive and may only shorten the built-in ceiling, never raise it")
	flags.DurationVar(&cfg.challengeTTL, "challenge-ttl", 60*time.Second, "")
	flags.DurationVar(&cfg.requestTimeout, "request-timeout", 5*time.Second, "per-request /attest timeout (0 disables)")
	flags.Int64Var(&cfg.maxRequestSize, "max-request-size", 65536, "max request body bytes on write endpoints")
	flags.DurationVar(&cfg.readTimeout, "read-timeout", defaultHTTPReadTimeout, "HTTP server read timeout")
	flags.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", defaultHTTPReadHeaderTimeout, "HTTP server read-header timeout")
	flags.DurationVar(&cfg.writeTimeout, "write-timeout", defaultHTTPWriteTimeout, "HTTP server write timeout")
	flags.DurationVar(&cfg.idleTimeout, "idle-timeout", defaultHTTPIdleTimeout, "HTTP server idle timeout")
	flags.IntVar(&cfg.maxHeaderBytes, "max-header-bytes", defaultHTTPMaxHeaderBytes, "maximum HTTP request header bytes")

	flags.BoolVar(&cfg.sanValidation, "san-validation", true, "require CSR IP SANs to equal the request source IP (false rejects CSRs carrying IP SANs)")
	flags.StringSliceVar(&cfg.dnsSANPatterns, "dns-san-pattern", nil, "regex a CSR's DNS SANs may match in full; repeatable, and a SAN passes if it matches any one. The chart always supplies the in-cluster Service DNS pattern and appends a public hostname when tls-lb fronts a routed domain. A CSR carrying DNS SANs is rejected when none are set.")
	flags.StringVar(&cfg.allowedCNPattern, "allowed-cn-pattern", "", "regex the CSR Subject CN must match in full (empty disables)")
	flags.DurationVar(&cfg.readinessInterval, "readiness-interval", 10*time.Second, "")
	flags.DurationVar(&cfg.minCAValidity, "min-ca-validity", time.Hour, "/readyz fails when the loaded mesh CA has less than this remaining lifetime")
	flags.StringVar(&cfg.allowlistDB, "allowlist-db", "", "Path to the allowlist SQLite database")
	flags.BoolVar(&cfg.allowlistPersistent, "allowlist-persistent", false, "whether --allowlist-db is on durable storage; false makes CDS warn at startup that operator-added digests and the mesh CA do not survive a restart")
	flags.StringSliceVar(&cfg.inventoryCIDRs, "sandbox-inventory-cidr", nil, "CIDR(s) holding the node addresses CDS may dial for a sandbox's admission inventory (repeatable). It is what stops a workload pointing the callback at its own pod IP and answering as the inventory (docs/ratls.md). Unset, CDS derives one host route per node from the live node list and refuses sandbox tokens until that syncs")
	flags.StringVar(&cfg.allowlistSeed, "allowlist-seed", "", "Path to a c8s.allowlist/v1 document (digests map and workload entries) seeded into the store at startup before serving; missing digests and entries are added, existing ones are left untouched (empty disables seeding)")
	flags.StringVar(&cfg.operatorKeys, "operator-keys", "", "Path to a PEM bundle of pinned operator EC public keys; /allowlist writes (POST/PUT/DELETE) require an operator token signed by one of them (empty = writes disabled, reads still served)")
	flags.BoolVar(&cfg.staticAllowlist, "static-allowlist", false, "serve the static allowlist a node measured into RTMR[3] at boot. Requires --ratls-platform=tdx, a --measurements-config with one entry pinning RTMR[1], RTMR[2] and RTMR[3], --allowlist-seed=<policy-dir>/static-allowlist.json and a unix:// --attestation-api-url; refuses --operator-keys and --allowlist-persistent. At start <policy-dir>/mode must read static, the members must match <policy-dir>/digest, and this pod's own evidence must match the entry, or CDS exits")
	flags.StringVar(&cfg.policyDir, "policy-dir", policybundle.DefaultPolicyDir, "directory c8s-policy-measure publishes the boot's policy mode, bundle digest and bundle members in (read under --static-allowlist)")

	flags.Float64Var(&cfg.rateLimit, "rate-limit", 10, "max requests per second per source IP on attestation endpoints")
	flags.IntVar(&cfg.rateBurst, "rate-burst", 20, "max burst size per source IP")
	flags.IntVar(&cfg.rateLimiterMax, "rate-limiter-max-entries", 10000, "max entries in the per-IP rate limiter; once full, a new source is refused until entries idle out")
	flags.DurationVar(&cfg.rateLimiterEvictInterval, "rate-limiter-evict-interval", time.Minute, "interval for per-IP rate limiter eviction sweep")
	flags.DurationVar(&cfg.rateLimiterIdleTimeout, "rate-limiter-idle-timeout", 5*time.Minute, "idle duration before a per-IP rate limiter entry is evicted")

	flags.IntVar(&cfg.secretsMaxPaths, "secrets-max-paths", 1024, "max distinct secret paths held in memory across every workload")
	flags.IntVar(&cfg.secretsMaxPathsPerWorkload, "secrets-max-paths-per-workload", secrets.DefaultMaxPathsPerHolder, "max secret paths one allowlist entry may hold")
	flags.IntVar(&cfg.secretsMaxValueBytes, "secrets-max-value-bytes", 4096, "max bytes in one secret value")
	flags.IntVar(&cfg.sandboxLedgerMax, "sandbox-ledger-max-entries", 10000, "max sandbox-to-inventory bindings held in memory")

	flags.DurationVar(&cfg.rotationInterval, "token-signer-rotation-interval", 720*time.Hour, "EAR signing key rotation interval (0 disables)")
	flags.DurationVar(&cfg.rotationOverlap, "token-signer-overlap", 25*time.Hour, "how long a retired EAR key stays in JWKS")
	flags.Float64Var(&cfg.rotationJitter, "token-signer-rotation-jitter", 0.1, "")

	flags.StringVar(&cfg.ratlsPlatform, "ratls-platform", "", "TEE platform for the RA-TLS serving cert (REQUIRED): sev-snp or tdx (snp/az-snp/gcp-snp and az-tdx/gcp-tdx aliases are normalized)")
	flags.DurationVar(&cfg.ratlsCertTTL, "ratls-cert-ttl", 24*time.Hour, "")

	_ = cmd.MarkFlagRequired("ratls-platform")
	_ = cmd.MarkFlagRequired("attestation-api-url")
	_ = cmd.MarkFlagRequired("allowlist-db")

	// `c8s cds verify` — a shorthand for `c8s verify --kind cds`, sharing the
	// same implementation. Running CDS (the server) stays `c8s cds`.
	//
	// Mode is intentionally left at auto: resolveMode derives it from --kind
	// (cds → ratls-cert, lb → discovery), so `c8s cds verify --kind lb` targets
	// the LB's discovery doc. Presetting Mode: "ratls-cert" here would shadow
	// that and make --kind lb dial for the embedded RA-TLS extension the LB
	// front door never serves.
	cmd.AddCommand(verify.NewCmd(verify.Defaults{
		Use:         "verify [target]",
		Short:       "Verify a CDS endpoint's TEE attestation",
		Kind:        "cds",
		DefaultPort: 8443,
	}))

	return cmd
}

type config struct {
	host                string
	port                int
	logLevel            string
	attestationApiURL   string
	caCommonName        string
	caCertValidity      time.Duration
	measurements        []string
	measurementsConfig  string
	rtmrs               []string
	earIssuerName       string
	expectedIssuer      string
	jwtClockSkew        int64
	maxTTL              time.Duration
	certTTL             time.Duration
	namedCertTTL        time.Duration
	challengeTTL        time.Duration
	requestTimeout      time.Duration
	maxRequestSize      int64
	readTimeout         time.Duration
	readHeaderTimeout   time.Duration
	writeTimeout        time.Duration
	idleTimeout         time.Duration
	maxHeaderBytes      int
	sanValidation       bool
	dnsSANPatterns      []string
	allowedCNPattern    string
	readinessInterval   time.Duration
	minCAValidity       time.Duration
	allowlistDB         string
	allowlistPersistent bool
	allowlistSeed       string
	inventoryCIDRs      []string
	operatorKeys        string
	rotationInterval    time.Duration
	rotationOverlap     time.Duration
	rotationJitter      float64
	ratlsPlatform       string
	ratlsCertTTL        time.Duration
	staticAllowlist     bool
	policyDir           string

	rateLimit                float64
	rateBurst                int
	rateLimiterMax           int
	rateLimiterEvictInterval time.Duration
	rateLimiterIdleTimeout   time.Duration

	secretsMaxPaths            int
	secretsMaxPathsPerWorkload int
	secretsMaxValueBytes       int
	sandboxLedgerMax           int
}

// validateRATLSPlatformFlag rejects the CLI paths to a TLS-less CDS: the
// empty-platform plain-HTTP mode stays reachable only for tests constructing
// Config directly.
func validateRATLSPlatformFlag(v string) error {
	norm := ratls.NormalizePlatform(v)
	if norm == "" {
		return fmt.Errorf("--ratls-platform must not be empty (RA-TLS is mandatory; tests construct Config directly)")
	}
	if err := ratls.ValidatePlatform(norm); err != nil {
		return fmt.Errorf("--ratls-platform: %w", err)
	}
	return nil
}
