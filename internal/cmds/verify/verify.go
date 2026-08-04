package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// Exit codes. These are a stable contract for CI: a wrong measurement (2) is
// distinguishable from an unreachable endpoint (3).
const (
	exitVerified   = 0
	exitUsage      = 1
	exitFailed     = 2 // evidence obtained, but verification/policy failed
	exitNoEvidence = 3 // could not obtain evidence (connect/parse/file)
)

// connectError marks a failure to obtain evidence or verification collateral
// (vs. a verification verdict), so the orchestration can map it to exit code 3.
type connectError struct{ err error }

func (e *connectError) Error() string { return e.err.Error() }
func (e *connectError) Unwrap() error { return e.err }

func isConnectError(err error) bool {
	var ce *connectError
	return errors.As(err, &ce)
}

// securityError marks a response that was reachable and well-formed but failed a
// security check (e.g. the attestation endpoint did not echo our nonce). Unlike
// a connectError it must NOT be swallowed by auto-mode's fall-through to the
// serving cert — a wrong nonce can signal replay or an active MITM.
type securityError struct{ err error }

func (e *securityError) Error() string { return e.err.Error() }
func (e *securityError) Unwrap() error { return e.err }

func isSecurityError(err error) bool {
	var se *securityError
	return errors.As(err, &se)
}

// Defaults preset a command's target shape so `c8s cds verify` is a thin
// shorthand for `c8s verify` with CDS conventions, sharing one implementation.
type Defaults struct {
	// Use is the command's name ("verify").
	Use string
	// Short is the one-line help.
	Short string
	// Kind preselects the component (cds|lb|workload|auto).
	Kind string
	// Mode preselects the evidence mode (auto|ratls-cert|discovery|attest-pq).
	Mode string
	// DefaultPort is the port assumed when the target omits one (0 = by kind).
	DefaultPort int
}

type config struct {
	url           string
	kind          string
	mode          string
	server        string
	timeout       time.Duration
	fromFile      string
	discoveryPath string

	measurements     []string
	measurementsFile string
	imageManifest    string
	expectedRTMR3Hex string
	operatorKeys     string
	sandboxID        string
	workload         string
	allowlistFile    string
	meshCA           string
	allowDebug       bool
	minTCBBootloader uint
	minTCBTEE        uint
	minTCBSNP        uint
	minTCBMicrocode  uint
	expectedRDHex    string

	output       string
	showEvidence bool

	defaults Defaults
}

// NewCmd builds the verify command. The same constructor backs both the generic
// `c8s verify` and the `c8s cds verify` shorthand; d only changes defaults.
func NewCmd(d Defaults) *cobra.Command {
	cfg := config{defaults: d}
	use := d.Use
	if use == "" {
		use = "verify [target]"
	}
	short := d.Short
	if short == "" {
		short = "Verify a c8s component's TEE attestation"
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: short + `.

Fetches a component's TEE attestation evidence (AMD SEV-SNP or Intel TDX) and
verifies it against the hardware signature chain plus a measurement / TCB /
policy, then reports the verdict.

Verification runs in-process using attestation-go — the Go port of the
attestation-rs engine the cluster runs. It auto-detects the platform and AMD
product — including Zen4c (Siena/Bergamo), which stock go-sev-guest cannot — so
the product line never has to be supplied by hand, and it fetches the VCEK for a
bare report from AMD KDS (bounded by --timeout), so the machine running it needs
outbound HTTPS to kdsintf.amd.com (no container runtime required).

Evidence sources:
  https://host:port      GET the discovery endpoint (/v1/discovery — cert +
                         evidence with the VCEK inline), or, in --mode ratls-cert,
                         dial the RA-TLS serving cert (bare report; the VCEK is
                         fetched from AMD KDS). Default mode: cds → ratls-cert,
                         lb → discovery, auto → discovery then serving cert.
  --from-file FILE       verify a saved PEM cert or attestation-response JSON.

  c8s cds verify https://cds.example.com:8443 --measurements <sha384-hex>
  c8s verify https://lb.example.com:443 --kind lb --measurements <sha384-hex>

Exit codes: 0 verified · 1 usage · 2 verification/policy failed · 3 evidence
unavailable (unreachable / unparseable).`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				cfg.url = args[0]
			}
			os.Exit(run(cmd.Context(), cfg, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&cfg.url, "url", "", "target URL or host:port (alternative to the positional argument)")
	f.StringVar(&cfg.kind, "kind", orDefault(d.Kind, "auto"), "component being verified: cds, lb, workload, or auto")
	f.StringVar(&cfg.mode, "mode", orDefault(d.Mode, "auto"), "evidence mode: auto, ratls-cert, discovery, or attest-pq")
	f.StringVar(&cfg.discoveryPath, "discovery-path", defaultDiscoveryPath, "path of the LB discovery document (discovery mode)")
	f.StringVar(&cfg.server, "server-name", "", "TLS SNI server name (for port-forward / routed domains)")
	f.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "per-attempt timeout (evidence fetch and AMD KDS collateral fetch)")
	f.StringVar(&cfg.fromFile, "from-file", "", "verify evidence from a saved PEM certificate or attestation-response JSON instead of dialing")

	f.StringSliceVar(&cfg.measurements, "measurements", nil, "allowed SHA-384 hex launch measurement(s) (repeatable / comma-separated); empty = no pinning (UNSAFE). On TDX this pins MRTD only, which covers just the TDVF firmware — use --image-manifest to pin the whole guest image")
	f.StringVar(&cfg.measurementsFile, "measurements-file", "", "file of allowed launch measurements, one hex digest per line")
	f.StringVar(&cfg.imageManifest, "image-manifest", "", "build-artifact manifest of the expected TDX guest image (JSON object with mrtd, rtmr1, rtmr2, each 96 lowercase hex chars, published with the image build); its MRTD joins the --measurements allowlist and RTMR[1]/RTMR[2] are pinned exactly, so the guest kernel and rootfs are verified rather than only the firmware. TDX evidence only — with SNP evidence this is a policy error")
	f.StringVar(&cfg.expectedRTMR3Hex, "expected-rtmr3", "", "expected TDX RTMR[3] as 96 hex chars — pins the runtime measurement register, i.e. the ordered operator-key/workload-event chain extended after boot (pkg/runtimemeasure). This is a deployment property, NOT a cluster identity, and cannot replace an image pin. TDX evidence only — with SNP evidence this is a policy error")
	f.StringVar(&cfg.operatorKeys, "operator-keys", "", "PEM bundle of expected operator public keys; verification fails unless the key set the attested target serves at /operator-keys matches it (kind=cds targets)")
	f.StringVar(&cfg.sandboxID, "sandbox-id", "", "expected CRI pod sandbox ID on the target's leaf; requires --mesh-ca, since CDS's signature on the leaf is what vouches for the ID (docs/ratls.md)")
	f.StringVar(&cfg.workload, "workload", "", "expected matched-workload name on the target's leaf; requires --mesh-ca, since CDS's signature on the leaf is what vouches for the stamp (docs/ratls.md)")
	f.StringVar(&cfg.allowlistFile, "allowlist", "", "file holding the exact canonical allowlist bytes (as served by GET /allowlist); the leaf's stamped policy digest must equal SHA-256 of these bytes and the stamped name must resolve in the document. Requires --mesh-ca")
	f.StringVar(&cfg.meshCA, "mesh-ca", "", "PEM bundle of the CDS mesh CA; when set, the target's leaf must chain to it, which is what authenticates the reported sandbox ID")
	f.BoolVar(&cfg.allowDebug, "allow-debug", false, "accept debug-enabled guests")
	f.UintVar(&cfg.minTCBBootloader, "min-tcb-bootloader", 0, "minimum bootloader TCB component")
	f.UintVar(&cfg.minTCBTEE, "min-tcb-tee", 0, "minimum TEE TCB component")
	f.UintVar(&cfg.minTCBSNP, "min-tcb-snp", 0, "minimum SNP firmware TCB component")
	f.UintVar(&cfg.minTCBMicrocode, "min-tcb-microcode", 0, "minimum microcode TCB component")
	f.StringVar(&cfg.expectedRDHex, "expected-report-data", "", "hex REPORTDATA / TPM-nonce anchor override for bare evidence files (1–64 bytes, exactly as bound by the producer)")

	f.StringVarP(&cfg.output, "output", "o", "text", "output format: text or json")
	f.BoolVar(&cfg.showEvidence, "show-evidence", false, "print the raw report fields")

	return cmd
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// run performs the whole verification and renders the result, returning the
// process exit code. It is the unit-testable core (no os.Exit inside).
func run(ctx context.Context, cfg config, out, errOut io.Writer) int {
	// No mode alias: the retired "attestation-endpoint" name (and anything
	// else unknown) is a usage error, not a silent fall-through to auto.
	switch cfg.mode {
	case "", "auto", "ratls-cert", "discovery", "attest-pq":
	default:
		fmt.Fprintf(errOut, "error: unknown --mode %q (valid modes: auto, ratls-cert, discovery, attest-pq)\n", cfg.mode)
		return exitUsage
	}

	policy, err := buildPolicy(cfg)
	if err != nil {
		fmt.Fprintf(errOut, "error: %v\n", err)
		return exitUsage
	}

	if cfg.url == "" && cfg.fromFile == "" {
		fmt.Fprintf(errOut, "error: no target: pass a component's discovery URL / host:port (or --from-file)\n")
		return exitUsage
	}

	// Verify in-process with attestation-go — the Go port of the engine the
	// cluster runs. It auto-detects the platform and AMD product (incl. Siena)
	// and fetches the VCEK from AMD KDS itself, so a bare RA-TLS report, a
	// discovery doc, and an endpoint response all verify through one path.
	var overrideERD []byte
	if cfg.expectedRDHex != "" {
		erd, perr := parseExpectedReportData(cfg.expectedRDHex)
		if perr != nil {
			fmt.Fprintf(errOut, "error: %v\n", perr)
			return exitUsage
		}
		overrideERD = erd
	}
	ev, err := gatherEvidence(ctx, cfg, overrideERD)
	if err != nil {
		fmt.Fprintf(errOut, "error: could not obtain evidence: %v\n", err)
		return exitNoEvidence
	}
	return verifyEvidence(ctx, cfg, policy, ev, gatherOperatorKeys(ctx, cfg, ev), out, errOut)
}

// operatorKeysReport is the pinned-operator-key section of the verdict. Keys
// authorize allowlist writes on CDS. The list is CDS-reported config, fetched
// over the attested serving cert; --operator-keys turns it into a check.
type operatorKeysReport struct {
	fingerprints []string
	digest       []byte // KeySetDigest of the served list (nil when not fetched)
	note         string // non-empty when keys are absent/unavailable, explains why
	fetchErr     error  // non-nil when the fetch was attempted and failed
}

// gatherOperatorKeys fetches the CDS-pinned operator key fingerprints for
// kind=cds network targets. For any other kind (including the default auto)
// the fetch is skipped, and the skip is announced via a note so the rendered
// verdict never silently omits it. The fetch is bound to the attested serving
// cert (see fetchOperatorKeyFingerprints). A failed fetch degrades to a note,
// but records fetchErr so applySandboxPolicy can fail the verdict when
// --operator-keys asked for a check: an endpoint erroring on /operator-keys
// must not dodge it.
func gatherOperatorKeys(ctx context.Context, cfg config, ev *evidence) operatorKeysReport {
	if cfg.kind != "cds" {
		return operatorKeysReport{note: "operator-keys cross-check skipped: target kind is not cds (use --kind cds to enable)"}
	}
	if cfg.url == "" {
		return operatorKeysReport{}
	}
	if ev.certSHA256 == "" {
		return operatorKeysReport{note: "not fetched (no serving cert to bind to)"}
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return operatorKeysReport{note: "not fetched: " + err.Error()}
	}
	fps, digest, note, err := fetchOperatorKeyFingerprints(ctx, baseURL, cfg.server, ev.certSHA256, cfg.timeout)
	if err != nil {
		return operatorKeysReport{note: "not fetched: " + err.Error(), fetchErr: err}
	}
	return operatorKeysReport{fingerprints: fps, digest: digest, note: note}
}

// verifyEvidence verifies already-gathered evidence (from any source/mode)
// in-process with attestation-go (the Go port of the attestation-rs engine the
// cluster runs), which auto-detects the product and fetches the VCEK from KDS
// when it is not shipped inline — so a bare RA-TLS report and a discovery doc
// both work — then renders the verdict. The verification attempt (including the
// KDS fetch) is bounded by --timeout; an unobtainable-collateral failure is
// exit 3, not a verification verdict.
func verifyEvidence(ctx context.Context, cfg config, policy *ratls.VerifyPolicy, ev *evidence, opKeys operatorKeysReport, out, errOut io.Writer) int {
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}
	result, verr := verifyInProcess(ctx, ev, policy, minTCBFromCfg(cfg))
	if isConnectError(verr) {
		fmt.Fprintf(errOut, "error: could not fetch verification collateral: %v\n", verr)
		return exitNoEvidence
	}
	oc := newOutcome(cfg, ev, result, verr, policy)
	oc.OperatorKeys = opKeys.fingerprints
	oc.OperatorKeysNote = opKeys.note
	applySandboxPolicy(&oc, cfg, ev, opKeys)
	applyWorkloadPolicy(&oc, cfg, ev)
	render(cfg, oc, out)
	if !oc.Verified {
		return exitFailed
	}
	return exitVerified
}

// buildPolicy parses the measurement allowlist and validates TCB bounds. The
// launch-measurement pin and min-TCB are enforced on the verifier verdict
// (newOutcome / verifyInProcess); only Measurements and AllowDebug are read
// downstream.
func buildPolicy(cfg config) (*ratls.VerifyPolicy, error) {
	// Each TCB component is a single byte; reject >255 rather than silently
	// truncating it (byte(256)==0 would weaken the policy without warning).
	for name, v := range map[string]uint{
		"--min-tcb-bootloader": cfg.minTCBBootloader,
		"--min-tcb-tee":        cfg.minTCBTEE,
		"--min-tcb-snp":        cfg.minTCBSNP,
		"--min-tcb-microcode":  cfg.minTCBMicrocode,
	} {
		if v > 255 {
			return nil, fmt.Errorf("%s is %d, must be 0-255", name, v)
		}
	}

	hexes := append([]string{}, cfg.measurements...)
	if cfg.measurementsFile != "" {
		data, err := os.ReadFile(cfg.measurementsFile)
		if err != nil {
			return nil, fmt.Errorf("read --measurements-file: %w", err)
		}
		hexes = append(hexes, strings.Split(string(data), "\n")...)
	}
	measurements, err := ratls.ParseHexMeasurementsList(hexes)
	if err != nil {
		return nil, err
	}

	// --image-manifest carries MRTD in the same tuple as RTMR[1]/[2]; the MRTD
	// joins the measurement allowlist here so the three cannot drift apart,
	// while the RTMR pins are enforced on the verdict (newOutcome).
	pins, err := resolveRTMRPins(cfg)
	if err != nil {
		return nil, err
	}
	if pins.image != nil {
		measurements = append(measurements, pins.image.MRTD[:])
	}

	if _, err := expectedOperatorKeysDigest(cfg); err != nil {
		return nil, err
	}

	if cfg.meshCA != "" {
		if _, err := meshCAPool(cfg.meshCA); err != nil {
			return nil, err
		}
	}

	if cfg.sandboxID != "" {
		if err := ratls.ValidateSandboxID(cfg.sandboxID); err != nil {
			return nil, fmt.Errorf("--sandbox-id: %w", err)
		}
		if cfg.meshCA == "" {
			// The ID lives in the leaf's signed area, not in REPORTDATA, so
			// only the mesh CA signature authenticates it. Pinning without
			// checking that signature would pin a string the presenter chose.
			return nil, fmt.Errorf("--sandbox-id requires --mesh-ca: the sandbox ID is vouched by CDS's signature on the leaf, not by the hardware evidence")
		}
	}

	// The matched-workload stamp is CA-vouched exactly like the sandbox ID, so
	// both workload-policy flags demand the chain check that authenticates it.
	if cfg.workload != "" {
		if !pkgallowlist.ValidWorkloadName(cfg.workload) {
			return nil, fmt.Errorf("--workload: %q is not a valid workload entry name (1..%d bytes, [A-Za-z0-9][A-Za-z0-9._-]*)", cfg.workload, pkgallowlist.MaxWorkloadNameLen)
		}
		if cfg.meshCA == "" {
			return nil, fmt.Errorf("--workload requires --mesh-ca: the matched workload is vouched by CDS's signature on the leaf, not by the hardware evidence")
		}
	}
	if cfg.allowlistFile != "" {
		if cfg.meshCA == "" {
			return nil, fmt.Errorf("--allowlist requires --mesh-ca: the stamped policy digest is vouched by CDS's signature on the leaf, not by the hardware evidence")
		}
		if _, _, err := heldAllowlist(cfg.allowlistFile); err != nil {
			return nil, err
		}
	}

	return &ratls.VerifyPolicy{
		Measurements: measurements,
		AllowDebug:   cfg.allowDebug,
	}, nil
}

// rtmrPins are the TDX runtime-register pins resolved from the flags: the
// image tuple (--image-manifest; MRTD is folded into the measurement
// allowlist, RTMR[1]/[2] compare exactly) and the optional runtime-register
// pin (--expected-rtmr3). Any non-nil pin against non-TDX evidence is a
// policy error, never an ignored option.
type rtmrPins struct {
	image *runtimemeasure.ImagePins
	rtmr3 []byte
}

func (p rtmrPins) any() bool { return p.image != nil || p.rtmr3 != nil }

// resolveRTMRPins parses --image-manifest and --expected-rtmr3. Called from
// buildPolicy (so a bad flag is a usage error) and again at verdict time; a
// failure there fails the verdict closed.
func resolveRTMRPins(cfg config) (rtmrPins, error) {
	var pins rtmrPins
	if cfg.imageManifest != "" {
		img, err := runtimemeasure.LoadImageManifest(cfg.imageManifest)
		if err != nil {
			return rtmrPins{}, fmt.Errorf("--image-manifest: %w", err)
		}
		pins.image = &img
	}
	if cfg.expectedRTMR3Hex != "" {
		b, err := hex.DecodeString(strings.TrimSpace(cfg.expectedRTMR3Hex))
		if err != nil {
			return rtmrPins{}, fmt.Errorf("--expected-rtmr3 is not hex: %w", err)
		}
		if len(b) != runtimemeasure.Size {
			return rtmrPins{}, fmt.Errorf("--expected-rtmr3 is %d bytes, want %d (%d hex chars)",
				len(b), runtimemeasure.Size, runtimemeasure.Size*2)
		}
		pins.rtmr3 = b
	}
	return pins, nil
}

// expectedOperatorKeysDigest is the KeySetDigest of the --operator-keys bundle,
// or nil when the flag is unset.
func expectedOperatorKeysDigest(cfg config) ([]byte, error) {
	if cfg.operatorKeys == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(cfg.operatorKeys)
	if err != nil {
		return nil, fmt.Errorf("read --operator-keys: %w", err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("--operator-keys: %w", err)
	}
	return operatorauth.KeySetDigest(keys)
}

// heldAllowlist loads the --allowlist file: the exact bytes (which are what
// gets hashed — no reserialization, per the canonical-bytes rule) and the
// parsed document the stamped name resolves against.
func heldAllowlist(path string) ([]byte, *pkgallowlist.Allowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read --allowlist: %w", err)
	}
	doc, err := pkgallowlist.ParseServedJSON(data)
	if err != nil {
		return nil, nil, fmt.Errorf("--allowlist: %w", err)
	}
	return data, doc, nil
}

// meshCAPool loads the mesh CA bundle used to authenticate a leaf's sandbox ID.
func meshCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --mesh-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("--mesh-ca %s contains no PEM certificates", path)
	}
	return pool, nil
}

func gatherEvidence(ctx context.Context, cfg config, overrideERD []byte) (*evidence, error) {
	if cfg.fromFile != "" {
		data, err := os.ReadFile(cfg.fromFile)
		if err != nil {
			return nil, err
		}
		return gatherFromFile(data, overrideERD, "file "+cfg.fromFile)
	}
	if cfg.url == "" {
		return nil, fmt.Errorf("no target: pass a host:port / URL argument or --from-file")
	}

	dialAddr, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return nil, err
	}

	switch resolveMode(cfg) {
	case "ratls-cert":
		return gatherFromRATLSCert(ctx, dialAddr, cfg.server, cfg.timeout)
	case "discovery":
		return gatherFromDiscovery(ctx, baseURL, cfg.discoveryPath, cfg.server, cfg.timeout)
	case "attest-pq":
		return gatherFromEndpoint(ctx, baseURL, cfg.server, cfg.timeout)
	default: // auto: try the LB discovery doc (what the chart serves), then the
		// serving cert. Don't fall back on a security error — surface it.
		ev, err := gatherFromDiscovery(ctx, baseURL, cfg.discoveryPath, cfg.server, cfg.timeout)
		if err != nil && !isSecurityError(err) {
			return gatherFromRATLSCert(ctx, dialAddr, cfg.server, cfg.timeout)
		}
		return ev, err
	}
}

// resolveMode maps mode+kind to a concrete evidence mode.
func resolveMode(cfg config) string {
	if cfg.mode != "" && cfg.mode != "auto" {
		return cfg.mode
	}
	switch cfg.kind {
	case "lb":
		return "discovery"
	case "cds", "workload":
		return "ratls-cert"
	default: // auto (or unknown kind): let gatherEvidence try the LB discovery
		// doc, then the RA-TLS serving cert, so a bare target with no --kind is
		// detected either way. Returning a concrete mode here would defeat that.
		return "auto"
	}
}

func defaultPort(cfg config) int {
	if cfg.defaults.DefaultPort != 0 {
		return cfg.defaults.DefaultPort
	}
	switch cfg.kind {
	case "cds":
		return 8443
	default:
		return 443
	}
}

// normalizeTarget turns a URL or host[:port] into (dialAddr, baseURL).
// IPv6 literals are handled via net.JoinHostPort so they are bracketed correctly.
func normalizeTarget(raw string, port int) (dialAddr, baseURL string, err error) {
	defPort := strconv.Itoa(port)
	if strings.Contains(raw, "://") {
		u, perr := url.Parse(raw)
		if perr != nil {
			return "", "", fmt.Errorf("parse url %q: %w", raw, perr)
		}
		host := u.Hostname()
		if host == "" {
			return "", "", fmt.Errorf("url %q has no host", raw)
		}
		p := u.Port()
		if p == "" {
			p = defPort
		}
		dialAddr = net.JoinHostPort(host, p)
		return dialAddr, u.Scheme + "://" + dialAddr, nil
	}
	// SplitHostPort distinguishes "host:port" from a bare IPv6 literal (which has
	// colons but no port); on failure we treat raw as a host needing defPort.
	if host, p, splitErr := net.SplitHostPort(raw); splitErr == nil {
		dialAddr = net.JoinHostPort(host, p)
	} else {
		dialAddr = net.JoinHostPort(raw, defPort)
	}
	return dialAddr, "https://" + dialAddr, nil
}

// Outcome is the JSON-serializable verdict.
type Outcome struct {
	Verified    bool      `json:"verified"`
	VerifiedAt  time.Time `json:"verified_at"`
	Backend     string    `json:"backend"`
	Source      string    `json:"source"`
	Fresh       bool      `json:"fresh"`
	Binding     string    `json:"binding"`
	Platform    string    `json:"platform,omitempty"`
	Measurement string    `json:"measurement,omitempty"`
	ReportData  string    `json:"report_data,omitempty"`
	Debug       bool      `json:"debug,omitempty"`
	SMT         bool      `json:"smt,omitempty"`
	CurrentTCB  string    `json:"current_tcb,omitempty"`
	CertSHA256  string    `json:"cert_sha256,omitempty"`
	Pinned      bool      `json:"measurement_pinned"`
	Error       string    `json:"error,omitempty"`

	// RTMRsPinned lists the TDX runtime measurement registers this verdict
	// enforced, as "<index>:<hex>". On TDX the --measurements pin covers only
	// MRTD (the TDVF firmware): without RTMR[1]/[2] the guest kernel and
	// rootfs are unverified, and without RTMR[3] the runtime chain is. A
	// verdict that proves neither must not look like one that proves both.
	RTMRsPinned []string `json:"rtmrs_pinned,omitempty"`

	// Warnings are policy gaps in an otherwise passing verdict — verified
	// true, but with named limits a relying party should read.
	Warnings []string `json:"warnings,omitempty"`

	// CertBody says what authenticates the leaf certificate's body fields
	// (subject/serial/validity): the leaf's own attested key when
	// self-signed, or a CA chain — which is unauthenticated until --mesh-ca
	// pins it. Validity (NotBefore with a bounded skew, NotAfter) is enforced
	// on every cert-sourced path before this verdict is produced.
	CertBody string `json:"cert_body,omitempty"`

	// OperatorKeys are hex SHA-256 fingerprints (of the PKIX/SPKI DER) of the
	// operator public keys the target pins for allowlist writes (served list,
	// kind=cds only), fetched over the attested serving cert.
	OperatorKeys     []string `json:"operator_keys,omitempty"`
	OperatorKeysNote string   `json:"operator_keys_note,omitempty"`

	// SandboxID is the CRI pod sandbox the leaf names, and SandboxIDNote says
	// what authenticates it. CDS stamps the ID into the leaf's signed area
	// after verifying the inventory-signed sandbox token, so it is vouched by
	// the mesh CA — not bound into REPORTDATA like the rest of this verdict.
	// Without --mesh-ca it is reported unverified.
	SandboxID     string `json:"sandbox_id,omitempty"`
	SandboxIDNote string `json:"sandbox_id_note,omitempty"`

	// Workload is the allowlist entry the leaf's matched-workload stamp names,
	// with the allowlist version and policy digest it was decided under.
	// CA-vouched like the sandbox ID; WorkloadNote carries the §8 verdict
	// (workload_verified, or why it is only reported). Failures land in Error
	// with the same taxonomy (workload_absent, workload_malformed,
	// workload_name_mismatch, allowlist_digest_mismatch, workload_unresolved).
	Workload                 string `json:"workload,omitempty"`
	WorkloadAllowlistVersion string `json:"workload_allowlist_version,omitempty"`
	WorkloadAllowlistDigest  string `json:"workload_allowlist_digest,omitempty"`
	WorkloadNote             string `json:"workload_note,omitempty"`
}

// applySandboxPolicy surfaces the leaf's sandbox ID and enforces --sandbox-id /
// --operator-keys. It only ever demotes Verified — nothing here can rescue a
// failed hardware verification (docs/ratls.md).
func applySandboxPolicy(oc *Outcome, cfg config, ev *evidence, opKeys operatorKeysReport) {
	fail := func(format string, args ...any) {
		oc.Verified = false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf(format, args...)
		}
	}
	if ev.sandboxErr != nil {
		fail("sandbox-ID extension unparseable (newer target than this CLI?): %v", ev.sandboxErr)
		return
	}

	// The chain check runs before the ID is reported, so the note can never
	// claim "verified" for a check that then failed.
	if cfg.meshCA != "" {
		if ev.leaf == nil {
			fail("--mesh-ca needs the target's leaf certificate (this evidence source carries none — use a cert, discovery, or attest-pq target)")
			return
		}
		pool, err := meshCAPool(cfg.meshCA)
		if err != nil {
			fail("%v", err)
			return
		}
		if _, err := ev.leaf.Verify(x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			fail("leaf does not chain to the --mesh-ca bundle: %v", err)
			return
		}
	}

	// Report the ID only once the hardware evidence verified, and always say
	// what stands behind it: an unqualified "sandbox: X" would read as
	// attested, which it is not.
	if oc.Verified && ev.sandboxID != "" {
		oc.SandboxID = ev.sandboxID
		if cfg.meshCA == "" {
			oc.SandboxIDNote = "not verified: CDS's signature on the leaf vouches for this ID; pass --mesh-ca to check it"
		} else {
			oc.SandboxIDNote = "verified: the leaf chains to the supplied mesh CA"
		}
	}
	if cfg.sandboxID != "" {
		if ev.leaf == nil {
			fail("--sandbox-id needs the target's leaf certificate (this evidence source carries none — use a cert, discovery, or attest-pq target)")
			return
		}
		// One implementation of the pin, shared with the mesh's CA path — and
		// reached only after the chain check above, which is what authenticates
		// the ID.
		if err := ratls.CheckSandboxPin(ev.leaf, cfg.sandboxID); err != nil {
			fail("%v", err)
		}
	}

	// The served key list is authenticated by being fetched over the attested
	// serving cert. A failed fetch fails closed when the operator asked for the
	// check (a 404 is not an error — it maps to the empty-set digest in
	// fetchOperatorKeyFingerprints).
	expected, err := expectedOperatorKeysDigest(cfg)
	if err != nil {
		fail("%v", err)
		return
	}
	if len(expected) == 0 {
		return
	}
	if opKeys.fetchErr != nil {
		fail("could not fetch /operator-keys to check it against --operator-keys: %v", opKeys.fetchErr)
		return
	}
	if opKeys.digest == nil {
		// Never fetched (wrong --kind, or a --from-file target). Say that,
		// rather than comparing against an empty digest and reporting a
		// mismatch the operator cannot act on.
		fail("--operator-keys cannot be checked: %s", opKeys.note)
		return
	}
	if !bytes.Equal(opKeys.digest, expected) {
		fail("served /operator-keys digest %x does not match the --operator-keys set (%x)", opKeys.digest, expected)
	}
}

// applyWorkloadPolicy surfaces the leaf's matched-workload stamp and enforces
// --workload / --allowlist, mirroring applySandboxPolicy's ordering: an
// unparseable stamp fails closed; the mesh-CA chain check (applySandboxPolicy,
// which always runs first) authenticates the stamp before anything from it is
// reported or compared; the pins only ever demote Verified.
func applyWorkloadPolicy(oc *Outcome, cfg config, ev *evidence) {
	fail := func(format string, args ...any) {
		oc.Verified = false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf(format, args...)
		}
	}
	if ev.workloadErr != nil {
		fail("workload_malformed: matched-workload extension unparseable or duplicated (newer target than this CLI?): %v", ev.workloadErr)
		return
	}

	// Report the stamp only once the hardware evidence (and, with --mesh-ca,
	// the chain) verified, and always say what stands behind it.
	if oc.Verified && ev.workload != nil {
		oc.Workload = ev.workload.Name
		oc.WorkloadAllowlistVersion = ev.workload.AllowlistVersion
		oc.WorkloadAllowlistDigest = hex.EncodeToString(ev.workload.AllowlistDigest)
		if cfg.meshCA == "" {
			oc.WorkloadNote = "not verified: CDS's signature on the leaf vouches for this name; pass --mesh-ca to check it"
		} else {
			oc.WorkloadNote = "ca-vouched: the leaf chains to the supplied mesh CA"
		}
	}

	if cfg.workload == "" && cfg.allowlistFile == "" {
		return
	}
	if ev.leaf == nil {
		fail("--workload/--allowlist need the target's leaf certificate (this evidence source carries none — use a cert, discovery, or attest-pq target)")
		return
	}
	if ev.workload == nil {
		fail("workload_absent: a workload policy is pinned but the leaf carries no matched-workload extension")
		return
	}
	if cfg.workload != "" && ev.workload.Name != cfg.workload {
		fail("workload_name_mismatch: leaf matched workload %q does not match pinned %q", ev.workload.Name, cfg.workload)
		return
	}
	if cfg.allowlistFile != "" {
		held, doc, err := heldAllowlist(cfg.allowlistFile)
		if err != nil {
			fail("%v", err)
			return
		}
		digest := sha256.Sum256(held)
		if !bytes.Equal(digest[:], ev.workload.AllowlistDigest) {
			fail("allowlist_digest_mismatch: stamped policy digest %x does not match SHA-256 %x of the held --allowlist bytes", ev.workload.AllowlistDigest, digest[:])
			return
		}
		if _, ok := doc.Workloads[ev.workload.Name]; !ok {
			fail("workload_unresolved: stamped name %q does not resolve in the held allowlist document", ev.workload.Name)
			return
		}
	}
	if oc.Verified {
		oc.WorkloadNote = "workload_verified: the leaf chains to the supplied mesh CA and the stamp satisfies the pinned policy"
	}
}

// newOutcome maps a verifier verdict to the shared Outcome. The verifier proves
// the AMD chain, REPORTDATA binding, debug, and min-TCB; the launch-measurement
// allowlist (--measurements) and the TDX runtime-register pins have no
// verifier-side input, so they are enforced here on the signature-verified
// claims and fail closed.
func newOutcome(cfg config, ev *evidence, result *teetypes.VerificationResult, verr error, policy *ratls.VerifyPolicy) Outcome {
	pinned := len(policy.Measurements) > 0
	oc := Outcome{
		Backend:    "attestation-go",
		VerifiedAt: time.Now().UTC(),
		Source:     ev.source,
		Fresh:      ev.fresh,
		Binding:    ev.bindingNote,
		CertSHA256: ev.certSHA256,
		Pinned:     pinned,
	}
	if ev.leaf != nil {
		oc.CertBody = describeCertBody(cfg, ev)
	}
	if verr != nil {
		oc.Error = verr.Error()
		return oc
	}
	// Prefer the platform the verifier reported; fall back to what we sent.
	oc.Platform = string(result.Platform)
	if oc.Platform == "" {
		oc.Platform = ev.platform
	}
	oc.Measurement = result.Claims.LaunchDigest
	oc.CurrentTCB = formatTCB(result.Claims.TCB)

	if pinned {
		mb, err := hex.DecodeString(result.Claims.LaunchDigest)
		if err != nil || len(mb) == 0 {
			oc.Error = fmt.Sprintf("cannot enforce --measurements: launch_digest is missing or malformed (%q)", result.Claims.LaunchDigest)
			return oc
		}
		if !ratls.MeasurementAllowed(mb, policy.Measurements) {
			oc.Error = "launch measurement not in --measurements allowlist"
			return oc
		}
	}
	if !applyRTMRPins(&oc, cfg, result) {
		return oc
	}
	oc.Verified = true

	// A passing TDX verdict with a launch-measurement pin but no image tuple
	// says less than it looks like: MRTD covers only the TDVF firmware.
	if oc.Platform == string(teetypes.PlatformTDX) && pinned && cfg.imageManifest == "" {
		oc.Warnings = append(oc.Warnings,
			"TDX measurement pin covers MRTD only — MRTD measures the TDVF firmware, so the guest kernel and rootfs are UNMEASURED by this policy; pass --image-manifest to pin the full image tuple")
	}
	return oc
}

// applyRTMRPins enforces the --image-manifest RTMR[1]/[2] and --expected-rtmr3
// pins on the verified claims, recording what was enforced in RTMRsPinned.
// Returns false (with oc.Error set) on any failure: a pin against non-TDX
// evidence, an absent or malformed claim, or a mismatch — never an ignored
// option.
func applyRTMRPins(oc *Outcome, cfg config, result *teetypes.VerificationResult) bool {
	pins, err := resolveRTMRPins(cfg)
	if err != nil {
		oc.Error = err.Error()
		return false
	}
	if !pins.any() {
		return true
	}
	if oc.Platform != string(teetypes.PlatformTDX) {
		oc.Error = fmt.Sprintf("an RTMR pin (--image-manifest / --expected-rtmr3) is set but the evidence platform is %q: runtime measurement registers exist only on TDX, so this policy cannot be enforced against %q evidence", oc.Platform, oc.Platform)
		return false
	}

	check := func(idx int, meaning string, want []byte) bool {
		key := fmt.Sprintf("rtmr_%d", idx)
		got, _ := result.Claims.PlatformData[key].(string)
		got = strings.ToLower(strings.TrimSpace(got))
		if got == "" {
			oc.Error = fmt.Sprintf("cannot enforce the RTMR[%d] pin: the verified claims carry no %s", idx, key)
			return false
		}
		gb, err := hex.DecodeString(got)
		if err != nil || len(gb) != runtimemeasure.Size {
			oc.Error = fmt.Sprintf("cannot enforce the RTMR[%d] pin: %s claim is malformed (%q)", idx, key, got)
			return false
		}
		if !bytes.Equal(gb, want) {
			oc.Error = fmt.Sprintf("RTMR[%d] (%s) is %s, expected %s", idx, meaning, got, hex.EncodeToString(want))
			return false
		}
		oc.RTMRsPinned = append(oc.RTMRsPinned, fmt.Sprintf("%d:%s", idx, hex.EncodeToString(want)))
		return true
	}
	if pins.image != nil {
		if !check(1, "guest kernel", pins.image.RTMR1[:]) || !check(2, "guest rootfs", pins.image.RTMR2[:]) {
			return false
		}
	}
	if pins.rtmr3 != nil && !check(3, "runtime operator-key/workload chain", pins.rtmr3) {
		return false
	}
	return true
}

// describeCertBody says what stands behind the leaf's body fields. Validity
// itself was already enforced when the evidence was gathered
// (authenticateLeafBody), so this only reports the authentication class.
func describeCertBody(cfg config, ev *evidence) string {
	switch {
	case ev.leafSelfIssued:
		return "self-signed: body authenticated by the certificate's own attested key; validity enforced (NotBefore skew ≤" + certutil.LeafValiditySkew.String() + ")"
	case cfg.meshCA != "":
		return "CA-signed: body authenticated by the --mesh-ca chain check; validity enforced"
	case ev.leafChainVerified:
		return "CA-signed: body authenticated by the transcript-committed issuing CA (chain verified); validity enforced"
	default:
		return "CA-signed: body fields are CA-vouched and UNAUTHENTICATED without a CA pin — pass --mesh-ca to check the chain; validity enforced"
	}
}

// minTCBFromCfg builds the verifier's min-TCB floor from the --min-tcb-* flags,
// or nil when none are set. buildPolicy already range-checked them (≤255).
func minTCBFromCfg(cfg config) *teetypes.SnpTcb {
	if cfg.minTCBBootloader == 0 && cfg.minTCBTEE == 0 && cfg.minTCBSNP == 0 && cfg.minTCBMicrocode == 0 {
		return nil
	}
	return &teetypes.SnpTcb{
		Bootloader: byte(cfg.minTCBBootloader),
		Tee:        byte(cfg.minTCBTEE),
		Snp:        byte(cfg.minTCBSNP),
		Microcode:  byte(cfg.minTCBMicrocode),
	}
}

// formatTCB renders the verified TCB for display: SNP shows its components, TDX
// the raw SVN. Returns "" when the verifier reported no TCB.
func formatTCB(tcb teetypes.TcbInfo) string {
	deref := func(p *uint8) uint8 {
		if p == nil {
			return 0
		}
		return *p
	}
	switch tcb.Type {
	case "Snp":
		s := fmt.Sprintf("bootloader=%d tee=%d snp=%d microcode=%d",
			deref(tcb.Bootloader), deref(tcb.Tee), deref(tcb.Snp), deref(tcb.Microcode))
		if tcb.FMC != nil {
			s += fmt.Sprintf(" fmc=%d", *tcb.FMC)
		}
		return s
	case "Tdx":
		if len(tcb.TCBSvn) > 0 {
			return "svn=" + hex.EncodeToString(tcb.TCBSvn)
		}
	}
	return ""
}

func render(cfg config, oc Outcome, out io.Writer) {
	if cfg.output == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(oc)
		return
	}
	renderText(cfg, oc, out)
}

func renderText(cfg config, oc Outcome, out io.Writer) {
	if oc.Verified {
		fmt.Fprintf(out, "✓ VERIFIED  (%s backend)\n", oc.Backend)
	} else {
		fmt.Fprintf(out, "✗ NOT VERIFIED  (%s backend)\n", oc.Backend)
	}
	fmt.Fprintf(out, "  source:       %s\n", oc.Source)
	fmt.Fprintf(out, "  verified at:  %s\n", oc.VerifiedAt.Format(time.RFC3339))
	if oc.Error != "" {
		fmt.Fprintf(out, "  reason:       %s\n", oc.Error)
		return
	}
	fmt.Fprintf(out, "  platform:     %s\n", oc.Platform)
	fmt.Fprintf(out, "  measurement:  %s\n", oc.Measurement)
	for _, p := range oc.RTMRsPinned {
		idx, hexVal, _ := strings.Cut(p, ":")
		fmt.Fprintf(out, "  RTMR[%s]:      %s (matched)\n", idx, hexVal)
	}
	fmt.Fprintf(out, "  TCB:          %s   debug=%t smt=%t\n", oc.CurrentTCB, oc.Debug, oc.SMT)
	if oc.CertSHA256 != "" {
		fmt.Fprintf(out, "  cert sha256:  %s\n", oc.CertSHA256)
	}
	if oc.CertBody != "" {
		fmt.Fprintf(out, "  cert body:    %s\n", oc.CertBody)
	}
	fmt.Fprintf(out, "  binding:      %s\n", oc.Binding)
	for _, w := range oc.Warnings {
		fmt.Fprintf(out, "  WARNING:      %s\n", w)
	}
	if oc.SandboxID != "" {
		fmt.Fprintf(out, "  sandbox id:   %s\n", oc.SandboxID)
		fmt.Fprintf(out, "                %s\n", oc.SandboxIDNote)
	}
	if oc.Workload != "" {
		fmt.Fprintf(out, "  workload:     %s  (allowlist version %s, digest %s)\n", oc.Workload, oc.WorkloadAllowlistVersion, oc.WorkloadAllowlistDigest)
		fmt.Fprintf(out, "                %s\n", oc.WorkloadNote)
	}
	if len(oc.OperatorKeys) > 0 {
		label := "operator keys (allowlist writes; CDS-reported config, NOT covered by the measurement):"
		fmt.Fprintf(out, "  %s\n", label)
		for _, fp := range oc.OperatorKeys {
			fmt.Fprintf(out, "    sha256:%s\n", fp)
		}
	} else if oc.OperatorKeysNote != "" {
		fmt.Fprintf(out, "  operator keys: %s\n", oc.OperatorKeysNote)
	}
	if !oc.Fresh {
		fmt.Fprintf(out, "  note:         freshness NOT proven (no per-request nonce bound)\n")
	}
	if !oc.Pinned {
		fmt.Fprintf(out, "  WARNING:      no --measurements pinned — any genuine TEE is accepted (UNSAFE for production)\n")
	}
	if cfg.showEvidence {
		fmt.Fprintf(out, "  report_data:  %s\n", oc.ReportData)
	}
}
