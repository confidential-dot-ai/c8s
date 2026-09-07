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
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// DefaultAttestationAPIURL is the local attestation-api base URL, same
// default as credrelease and c8s-chart-values.sh.
const DefaultAttestationAPIURL = "http://127.0.0.1:8400"

// loadMeasuredOperatorKeyAndOwnMeasurementFunc matches
// credrelease.LoadMeasuredOperatorKeyAndOwnMeasurement's signature. A package
// var, not a direct call, so tests can fake attestation and the tdx_guest
// sysfs without a real TDX/SNP guest. On SNP the real implementation shares
// one selfReport call between the operator-key HOSTDATA check and the
// launch-digest read, so Render only attests once per boot.
type loadMeasuredOperatorKeyAndOwnMeasurementFunc func(ctx context.Context, platform, attestationAPIURL string) (pub []byte, pubErr error, measurement []byte, rtmrs map[int][]byte, err error)

// loadMeasuredOperatorKeyAndOwnMeasurement defaults to the real,
// launch-bound loader.
var loadMeasuredOperatorKeyAndOwnMeasurement loadMeasuredOperatorKeyAndOwnMeasurementFunc = credrelease.LoadMeasuredOperatorKeyAndOwnMeasurement

// Config is the input to Render.
type Config struct {
	// Platform is the TEE platform, already normalized via
	// ratls.NormalizePlatform to what LoadMeasuredOperatorKey expects
	// ("tdx" or "sev-snp").
	Platform string
	// AttestationAPIURL is the local attestation-api base URL (SNP self-verify).
	AttestationAPIURL string
	// FragmentPath is the opkeydata values.yaml fragment. Empty means no
	// fragment: Render emits the boot-derived tree alone.
	FragmentPath string
	// SignaturePath is the fragment's detached signature
	// (c8s keys sign-values' output). Required whenever FragmentPath is set.
	SignaturePath string
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

	attestationAPIURL := cfg.AttestationAPIURL
	if attestationAPIURL == "" {
		attestationAPIURL = DefaultAttestationAPIURL
	}

	// This guest's own launch measurement, (TDX only) RTMR pins, and the
	// operator pubkey — no longer flags an operator or an outer script
	// resolves and passes in; c8s-chart-values.sh now hands this command
	// only --platform and lets it read its own measured state directly (TDX:
	// tdx_guest sysfs; SNP: one verified self-report, shared between the
	// operator-key HOSTDATA check and the launch-digest read so an SNP
	// operator boot attests itself once, not twice).
	operatorPub, pubErr, measurement, rtmrs, err := loadMeasuredOperatorKeyAndOwnMeasurement(ctx, platform, attestationAPIURL)
	if err != nil {
		return "", fmt.Errorf("resolve this guest's own launch measurement: %w", err)
	}
	ownHex := strings.ToLower(hex.EncodeToString(measurement))

	// pubErr is nil, fs.ErrNotExist (an absent pubkey means this VM was
	// launched without an operator key — no opkeydata disk — same as the
	// shell script's prior behavior of omitting cds.operatorKeys entirely),
	// or some other load/verify failure (a substituted key, an unreachable
	// attestation-api), told apart from the "absent" case by the sentinel
	// rather than a pre-check race against the same file the loader itself
	// reads. A fragment cannot be trusted without a key to verify it
	// against, so one present in the non-operator case fails closed below
	// rather than being silently skipped.
	var operatorKeys []*ecdsa.PublicKey
	switch {
	case pubErr == nil:
		operatorKeys, err = operatorauth.ParsePublicKeysPEM(operatorPub)
		if err != nil {
			return "", fmt.Errorf("operator pubkey: %w", err)
		}
	case errors.Is(pubErr, fs.ErrNotExist):
		if cfg.FragmentPath != "" {
			return "", fmt.Errorf("--fragment %s given but no operator pubkey is staged — a fragment cannot be trusted without a key to verify it against: %w", cfg.FragmentPath, pubErr)
		}
		fmt.Fprintln(os.Stderr, "launch-values render: no operator pubkey staged — non-operator boot, cds.operatorKeys omitted")
		operatorPub = nil
	default:
		return "", fmt.Errorf("load measured operator key: %w", pubErr)
	}

	values := bootDerivedValues(operatorPub, ownHex, rtmrs)
	if operatorPub != nil && cfg.FragmentPath != "" {
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
		// Boot-derived keys win regardless of the allowlist: merge them over
		// the fragment, so precedence does not depend on the list staying
		// complete.
		helmchart.MergeValues(frag.Values, values)
		values = frag.Values
	}

	out, err := yaml.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("marshal values: %w", err)
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
	if err := operatorauth.VerifyDetached(operatorKeys, data, string(sigLine)); err != nil {
		return nil, fmt.Errorf("%s: signature invalid: %w", fragmentPath, err)
	}

	// KnownFields(true) rejects any top-level key besides measurement/values
	// in the same pass that decodes them — one decode instead of a strict
	// probe followed by a real unmarshal.
	var frag fragment
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&frag); err != nil {
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
