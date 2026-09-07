// Package launchvalues implements `c8s launch-values render`: the node-build
// half of Phase 0b's signed launch-time values (see the credential-release
// design). c8s-chart-values.sh (node-guest-image) calls this to turn an
// optional opkeydata `values.yaml` fragment into the `valuesContent` it
// writes into the boot HelmChartConfig, on top of the boot-derived keys
// (cds.operatorKeys, cds/ratlsMesh measurements and rtmrs) that fragment can
// never override.
//
// Trust chain: the operator key is loaded through
// credrelease.LoadMeasuredOperatorKey, the same launch-bound key
// cred-release.service trusts — a host that substitutes the pubkey file
// fails here exactly as it fails there. The fragment's signature must verify
// under that key, its `measurement` field must equal this guest's own launch
// measurement (replay bound to the image that is running), and every leaf
// path under its `values` subtree must be on an explicit allowlist. Anything
// else is a fail-closed error: there is no partial or best-effort render.
package launchvalues

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// DefaultOperatorPubkeyPath mirrors credrelease's own default — documentation
// and a preflight existence check for --operator-pubkey, since
// credrelease.LoadMeasuredOperatorKey is the sole reader of the real path
// (it does not take one as a parameter): the same file it measures is the
// only one this command can trust either.
const DefaultOperatorPubkeyPath = "/etc/confai/operator-pubkey"

// DefaultAttestationAPIURL is the local attestation-api base URL, same
// default as credrelease and c8s-chart-values.sh.
const DefaultAttestationAPIURL = "http://127.0.0.1:8400"

// loadMeasuredOperatorKeyFunc matches credrelease.LoadMeasuredOperatorKey's
// signature. A package var, not a direct call, so tests can fake attestation
// without a real TDX/SNP guest.
type loadMeasuredOperatorKeyFunc func(ctx context.Context, platform, attestationAPIURL string) ([]byte, error)

// loadMeasuredOperatorKey defaults to the real, launch-bound loader.
var loadMeasuredOperatorKey loadMeasuredOperatorKeyFunc = credrelease.LoadMeasuredOperatorKey

// Config is the input to Render.
type Config struct {
	// Platform is the TEE platform, already normalized via
	// ratls.NormalizePlatform to what LoadMeasuredOperatorKey expects
	// ("tdx" or "sev-snp").
	Platform string
	// AttestationAPIURL is the local attestation-api base URL (SNP self-verify).
	AttestationAPIURL string
	// OperatorPubkeyPath gates whether Render attempts to load an operator
	// key at all: absent means the VM was launched without --operator-key
	// (a non-operator boot), and Render emits the boot-derived tree with no
	// cds.operatorKeys, the same as a live `c8s install` with no
	// --operator-keys. It is NOT where the trusted key comes from —
	// LoadMeasuredOperatorKey owns that read from its own fixed path, the
	// same file this defaults to.
	OperatorPubkeyPath string
	// FragmentPath is the opkeydata values.yaml fragment. Empty means no
	// fragment: Render emits the boot-derived tree alone.
	FragmentPath string
	// SignaturePath is the fragment's detached signature
	// (c8s keys sign-values' output). Required whenever FragmentPath is set.
	SignaturePath string
	// OwnMeasurementHex is this guest's own launch measurement (TDX: MRTD;
	// SNP: the verified launch_digest), hex-encoded — the same value
	// c8s-chart-values.sh resolves into $MEASUREMENT.
	OwnMeasurementHex string
	// RTMRs pins TDX runtime measurement registers as "<index>=<hex>"
	// entries (see c8s install --rtmrs). Empty on SNP.
	RTMRs []string
}

// fragment is the opkeydata values.yaml wire shape: exactly two top-level
// keys.
type fragment struct {
	Measurement string         `yaml:"measurement"`
	Values      map[string]any `yaml:"values"`
}

// Render validates cfg and returns the merged values tree as YAML — what
// c8s-chart-values.sh writes as spec.valuesContent of the boot
// HelmChartConfig. Fails closed: any error means the caller must not render
// a HelmChartConfig at all (RequiredBy=rke2-server.service on the calling
// unit means the boot blocks rather than starts unpinned).
func Render(ctx context.Context, cfg Config) (string, error) {
	platform := ratls.NormalizePlatform(cfg.Platform)
	if err := ratls.ValidatePlatform(platform); err != nil {
		return "", fmt.Errorf("--platform: %w", err)
	}
	ownMeasurement, err := ratls.ParseHexMeasurementsList([]string{cfg.OwnMeasurementHex})
	if err != nil {
		return "", fmt.Errorf("--own-measurement: %w", err)
	}
	if len(ownMeasurement) != 1 {
		return "", fmt.Errorf("--own-measurement is required")
	}
	ownHex := strings.ToLower(strings.TrimSpace(cfg.OwnMeasurementHex))

	rtmrs, err := ratls.ParseRTMRPins(cfg.RTMRs)
	if err != nil {
		return "", fmt.Errorf("--rtmrs: %w", err)
	}

	pubkeyPath := cfg.OperatorPubkeyPath
	if pubkeyPath == "" {
		pubkeyPath = DefaultOperatorPubkeyPath
	}
	// Absence is not an error here: it means this VM was launched without an
	// operator key (no opkeydata disk), same as the shell script's prior
	// behavior of omitting cds.operatorKeys entirely. A fragment cannot be
	// trusted without a key to verify it against, so one present in that
	// case fails closed below rather than being silently skipped.
	_, statErr := os.Stat(pubkeyPath)
	haveOperatorKey := statErr == nil

	if !haveOperatorKey {
		if cfg.FragmentPath != "" {
			return "", fmt.Errorf("--fragment %s given but no operator pubkey at %s — a fragment cannot be trusted without a key to verify it against", cfg.FragmentPath, pubkeyPath)
		}
		boot := bootDerivedValues(nil, ownHex, rtmrs)
		out, err := yaml.Marshal(boot)
		if err != nil {
			return "", fmt.Errorf("marshal boot-derived values: %w", err)
		}
		return string(out), nil
	}

	attestationAPIURL := cfg.AttestationAPIURL
	if attestationAPIURL == "" {
		attestationAPIURL = DefaultAttestationAPIURL
	}
	operatorPub, err := loadMeasuredOperatorKey(ctx, platform, attestationAPIURL)
	if err != nil {
		return "", fmt.Errorf("load measured operator key: %w", err)
	}
	operatorKeys, err := operatorauth.ParsePublicKeysPEM(operatorPub)
	if err != nil {
		return "", fmt.Errorf("operator pubkey: %w", err)
	}

	boot := bootDerivedValues(operatorPub, ownHex, rtmrs)

	if cfg.FragmentPath == "" {
		out, err := yaml.Marshal(boot)
		if err != nil {
			return "", fmt.Errorf("marshal boot-derived values: %w", err)
		}
		return string(out), nil
	}

	if cfg.SignaturePath == "" {
		return "", fmt.Errorf("--fragment %s requires --signature (a fragment without a signature fails the boot)", cfg.FragmentPath)
	}
	frag, err := verifiedFragment(cfg.FragmentPath, cfg.SignaturePath, operatorKeys)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(strings.TrimSpace(frag.Measurement), ownHex) {
		return "", fmt.Errorf("fragment measurement %q does not match this guest's own measurement %q — the fragment was signed for a different launch", frag.Measurement, ownHex)
	}
	if err := checkAllowlist(frag.Values); err != nil {
		return "", err
	}

	// Boot-derived keys win regardless of the allowlist: merge them over the
	// fragment, so precedence does not depend on the list staying complete.
	merged := frag.Values
	deepMerge(merged, boot)

	out, err := yaml.Marshal(merged)
	if err != nil {
		return "", fmt.Errorf("marshal merged values: %w", err)
	}
	return string(out), nil
}

// verifiedFragment reads, signature-verifies and YAML-parses the fragment.
// The signature is checked over the raw file bytes before any parsing, the
// same order c8s keys sign-values signs in.
func verifiedFragment(fragmentPath, signaturePath string, operatorKeys []*ecdsa.PublicKey) (*fragment, error) {
	data, err := os.ReadFile(fragmentPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", fragmentPath, err)
	}
	sigLine, err := os.ReadFile(signaturePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", signaturePath, err)
	}
	if err := verifySignature(data, sigLine, operatorKeys); err != nil {
		return nil, fmt.Errorf("%s: signature invalid: %w", fragmentPath, err)
	}

	var strict map[string]any
	if err := yaml.Unmarshal(data, &strict); err != nil {
		return nil, fmt.Errorf("%s: parse YAML: %w", fragmentPath, err)
	}
	for k := range strict {
		if k != "measurement" && k != "values" {
			return nil, fmt.Errorf("%s: unexpected top-level key %q (only measurement and values are allowed)", fragmentPath, k)
		}
	}

	var frag fragment
	if err := yaml.Unmarshal(data, &frag); err != nil {
		return nil, fmt.Errorf("%s: parse YAML: %w", fragmentPath, err)
	}
	if strings.TrimSpace(frag.Measurement) == "" {
		return nil, fmt.Errorf("%s: missing top-level 'measurement'", fragmentPath)
	}
	if frag.Values == nil {
		frag.Values = map[string]any{}
	}
	return &frag, nil
}

// verifySignature parses sigLine (base64 ASN.1 DER, one line — c8s
// keys sign-values' output) and checks it against sha256(data) under any one
// of operatorKeys, mirroring operatorauth.Verifier.Authorize's "try each
// pinned key" shape.
func verifySignature(data, sigLine []byte, operatorKeys []*ecdsa.PublicKey) error {
	line := strings.TrimSpace(string(sigLine))
	der, err := decodeSignatureLine(line)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	for _, pub := range operatorKeys {
		if ecdsa.VerifyASN1(pub, digest[:], der) {
			return nil
		}
	}
	return fmt.Errorf("does not verify under the measured operator key")
}
