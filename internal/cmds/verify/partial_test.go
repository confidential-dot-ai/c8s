package verify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// discoveryDocWithPublicTLS is discoveryDocWith plus the public_tls block
// get-cert writes (empty mode omits the mode field, as a pre-mode document).
func discoveryDocWithPublicTLS(t *testing.T, mode, certPEM string, challenge []byte, evidence string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(discoveryDocWith(t, certPEM, challenge, evidence), &doc); err != nil {
		t.Fatal(err)
	}
	doc["public_tls"] = map[string]any{"hostname": "lb.example.com", "mode": mode}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The discovery gather must classify public_tls.mode: cds (and its
// pre-mode-field empty spelling) and webpki parse; anything else fails closed
// as a security verdict — auto mode must not fall through past a document it
// cannot classify. The declared mode is not recorded: the verdict keys on the
// live handshake observation, which a parsed-but-unprobed document lacks.
func TestDiscoveryPublicTLSModeParsing(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	challenge := []byte("issuance-challenge")
	evidence := `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`

	for _, mode := range []string{"", "cds", "webpki"} {
		ev, err := evidenceFromDiscovery(discoveryDocWithPublicTLS(t, mode, certPEM, challenge, evidence), "test", leafTrust{}, nil)
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if ev.frontDoor != frontDoorUnobserved {
			t.Errorf("mode %q: frontDoor = %v, want unobserved (no handshake was made)", mode, ev.frontDoor)
		}
	}

	_, err := evidenceFromDiscovery(discoveryDocWithPublicTLS(t, "dns", certPEM, challenge, evidence), "test", leafTrust{}, nil)
	if err == nil || !isSecurityError(err) {
		t.Fatalf("an unknown public_tls.mode must fail closed as a security verdict, got %v", err)
	}
	if !strings.Contains(err.Error(), `public_tls.mode "dns"`) {
		t.Errorf("error = %q, want it to name the unrecognized mode", err)
	}
}

// snpVerifiedOutcome builds a passing SNP verdict for ev the way
// verifyEvidence does: newOutcome plus the full ordered policy sequence.
func snpVerifiedOutcome(t *testing.T, cfg config, ev *evidence) Outcome {
	t.Helper()
	launch := "ab" + strings.Repeat("00", 47)
	if cfg.measurements == nil {
		cfg.measurements = []string{launch}
	}
	plan := mustPlan(t, cfg)
	result := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformSNP,
		Claims:         teetypes.Claims{LaunchDigest: launch},
	}
	oc := newOutcome(cfg, ev, result, nil, plan)
	applyVerdictPolicies(&oc, cfg, ev, nil, operatorKeysReport{})
	return oc
}

// A front door whose live handshake presents a serving key the evidence does
// not attest (a WebPKI door, whatever the document declares): the evidence
// verifies, but the verdict is partial — never "✓ VERIFIED" — and the exit
// code tells scripts so.
func TestWebPKIFrontDoorIsPartialNotVerified(t *testing.T) {
	ev := &evidence{
		platform:            "snp",
		source:              "discovery document https://lb.example.com/v1/discovery",
		bindingNote:         "REPORTDATA binds the CDS cert key + issuance challenge",
		certSHA256:          strings.Repeat("aa", 32),
		frontDoor:           frontDoorOther,
		frontDoorCertSHA256: strings.Repeat("bb", 32),
	}
	oc := snpVerifiedOutcome(t, config{}, ev)
	if oc.Verified || !oc.Partial {
		t.Fatalf("unbound front door: verified=%v partial=%v, want a partial verdict", oc.Verified, oc.Partial)
	}
	if got := verdictExitCode(oc); got != exitPartial {
		t.Errorf("exit = %d, want %d", got, exitPartial)
	}
	if len(oc.NotProven) != 1 || !strings.Contains(oc.NotProven[0], "live TLS handshake") ||
		!strings.Contains(oc.NotProven[0], ev.frontDoorCertSHA256) || !strings.Contains(oc.NotProven[0], ev.certSHA256) ||
		!strings.Contains(oc.NotProven[0], "not attestation-bound") {
		t.Errorf("NotProven = %v, want it to name the observed and attested serving keys", oc.NotProven)
	}

	var out bytes.Buffer
	renderText(config{}, oc, &out)
	got := out.String()
	for _, want := range []string{"~ PARTIALLY VERIFIED", "not proven:", "not attestation-bound", "measurement:", "binding:"} {
		if !strings.Contains(got, want) {
			t.Errorf("partial render missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "✓ VERIFIED") {
		t.Errorf("an unattested front door must never print ✓:\n%s", got)
	}

	// JSON carries the same honesty: verified stays false (CI fails closed),
	// partial and the unproven property are machine-readable.
	var jout bytes.Buffer
	render(config{output: "json"}, oc, &jout)
	var parsed map[string]any
	if err := json.Unmarshal(jout.Bytes(), &parsed); err != nil {
		t.Fatalf("json render: %v", err)
	}
	if parsed["verified"] != false || parsed["partial"] != true {
		t.Errorf("json verified=%v partial=%v", parsed["verified"], parsed["partial"])
	}
	if np, ok := parsed["not_proven"].([]any); !ok || len(np) != 1 {
		t.Errorf("json not_proven = %v", parsed["not_proven"])
	}

	// A verification failure dominates the mode: exit 2, not partial.
	verr := &securityError{err: errors.New("rejected")}
	failed := newOutcome(config{}, ev, nil, verr, mustPlan(t, config{measurements: []string{"ab" + strings.Repeat("00", 47)}}))
	applyVerdictPolicies(&failed, config{}, ev, nil, operatorKeysReport{})
	if failed.Partial || verdictExitCode(failed) != exitFailed {
		t.Errorf("failed evidence + webpki: partial=%v exit=%d, want a plain failure", failed.Partial, verdictExitCode(failed))
	}
}

// genoaFileEvidence parses the vendored Genoa fixture (VCEK inline, verifies
// offline) into evidence the way --from-file does.
func genoaFileEvidence(t *testing.T) *evidence {
	t.Helper()
	fixture, err := os.ReadFile("testdata/snp-evidence-genoa.json")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := gatherFromFile(fixture, []byte("genoa-test-fixture"), "fixture", leafTrust{})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// The full verify path on real offline-verifiable evidence: a discovery
// verdict whose live handshake presented an unattested serving key (or could
// not observe one) exits 4, and the same evidence with the attestation-bound
// front door observed — or no front-door property at all — still exits 0.
func TestVerifyEvidenceFrontDoorExitCodes(t *testing.T) {
	plan := &verifyPlan{policy: &ratls.VerifyPolicy{}}

	t.Run("unbound front door exits partial", func(t *testing.T) {
		ev := genoaFileEvidence(t)
		ev.frontDoor = frontDoorOther // as a discovery gather would record it
		var out, errOut bytes.Buffer
		code := verifyEvidence(context.Background(), config{output: "text"}, plan, ev, nil, operatorKeysReport{}, &out, &errOut)
		if code != exitPartial {
			t.Fatalf("exit = %d, want %d; output:\n%s%s", code, exitPartial, out.String(), errOut.String())
		}
		if !strings.Contains(out.String(), "~ PARTIALLY VERIFIED") {
			t.Errorf("output:\n%s", out.String())
		}
	})

	t.Run("unobserved front door exits partial", func(t *testing.T) {
		ev := genoaFileEvidence(t)
		ev.frontDoor = frontDoorUnobserved // discovery doc fetched over a non-TLS connection
		var out, errOut bytes.Buffer
		code := verifyEvidence(context.Background(), config{output: "text"}, plan, ev, nil, operatorKeysReport{}, &out, &errOut)
		if code != exitPartial {
			t.Fatalf("exit = %d, want %d; output:\n%s%s", code, exitPartial, out.String(), errOut.String())
		}
	})

	t.Run("attested front door still verifies", func(t *testing.T) {
		ev := genoaFileEvidence(t)
		ev.frontDoor = frontDoorAttested
		var out, errOut bytes.Buffer
		code := verifyEvidence(context.Background(), config{output: "text"}, plan, ev, nil, operatorKeysReport{}, &out, &errOut)
		if code != exitVerified {
			t.Fatalf("exit = %d, want %d; output:\n%s%s", code, exitVerified, out.String(), errOut.String())
		}
		if !strings.Contains(out.String(), "✓ VERIFIED") {
			t.Errorf("output:\n%s", out.String())
		}
	})

	t.Run("no front-door property still verifies", func(t *testing.T) {
		ev := genoaFileEvidence(t) // frontDoorNone — not discovery-sourced
		var out, errOut bytes.Buffer
		code := verifyEvidence(context.Background(), config{output: "text"}, plan, ev, nil, operatorKeysReport{}, &out, &errOut)
		if code != exitVerified {
			t.Fatalf("exit = %d, want %d; output:\n%s%s", code, exitVerified, out.String(), errOut.String())
		}
	})
}

// writeMeshCAPEM writes ca as the --mesh-ca bundle file.
func writeMeshCAPEM(t *testing.T, ca *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mesh-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// endpointEvidence is the shape attest-pq / saved-bundle gathering produces:
// a transcript-committed mesh leaf whose chain anchor the responder chose.
func endpointEvidence(id *endpointIdentity) *evidence {
	return &evidence{
		platform:         "snp",
		source:           "attestation endpoint https://lb.example.com",
		bindingNote:      "REPORTDATA binds the identity transcript",
		fresh:            true,
		leaf:             id.leaf,
		leafChainDerived: true,
	}
}

// A responder-chosen chain anchor is never reported as verified: without
// --mesh-ca the verdict is partial (exit 4); pinning the CA the leaf actually
// chains to is what earns the tick (exit 0); pinning a CA it does not chain
// to is a failure (exit 2).
func TestAttestPQChainAnchorHonesty(t *testing.T) {
	id := mintEndpointIdentity(t)

	t.Run("responder-chosen chain is partial", func(t *testing.T) {
		cfg := config{}
		oc := snpVerifiedOutcome(t, cfg, endpointEvidence(id))
		if oc.Verified || !oc.Partial {
			t.Fatalf("verified=%v partial=%v, want partial", oc.Verified, oc.Partial)
		}
		if got := verdictExitCode(oc); got != exitPartial {
			t.Errorf("exit = %d, want %d", got, exitPartial)
		}
		if len(oc.NotProven) != 1 || !strings.Contains(oc.NotProven[0], "responder committed") ||
			!strings.Contains(oc.NotProven[0], "--mesh-ca") {
			t.Errorf("NotProven = %v, want it to name the responder-chosen anchor and the way out", oc.NotProven)
		}
		if oc.ChainAnchor != "" {
			t.Errorf("ChainAnchor = %q: a responder-chosen anchor must never report as verified", oc.ChainAnchor)
		}

		var out bytes.Buffer
		renderText(config{}, oc, &out)
		got := out.String()
		for _, want := range []string{"~ PARTIALLY VERIFIED", "not proven:", "responder-chosen", "binding:"} {
			if !strings.Contains(got, want) {
				t.Errorf("partial render missing %q:\n%s", want, got)
			}
		}
		if strings.Contains(got, "✓ VERIFIED") || strings.Contains(got, "\n  chain anchor: ") {
			t.Errorf("a responder-chosen chain must not print a verified anchor:\n%s", got)
		}
	})

	t.Run("pinned anchor verifies", func(t *testing.T) {
		cfg := config{meshCA: writeMeshCAPEM(t, id.ca)}
		oc := snpVerifiedOutcome(t, cfg, endpointEvidence(id))
		if !oc.Verified || oc.Partial {
			t.Fatalf("verified=%v partial=%v error=%q, want verified", oc.Verified, oc.Partial, oc.Error)
		}
		if got := verdictExitCode(oc); got != exitVerified {
			t.Errorf("exit = %d, want %d", got, exitVerified)
		}
		if oc.ChainAnchor == "" || !strings.Contains(oc.ChainAnchor, "verified against the pinned --mesh-ca") {
			t.Errorf("ChainAnchor = %q", oc.ChainAnchor)
		}
		var out bytes.Buffer
		renderText(cfg, oc, &out)
		got := out.String()
		if !strings.Contains(got, "✓ VERIFIED") || !strings.Contains(got, "chain anchor: verified against the pinned --mesh-ca") {
			t.Errorf("pinned-anchor render:\n%s", got)
		}
	})

	t.Run("pinned anchor the leaf does not chain to fails", func(t *testing.T) {
		other := mintEndpointIdentity(t)
		cfg := config{meshCA: writeMeshCAPEM(t, other.ca)}
		oc := snpVerifiedOutcome(t, cfg, endpointEvidence(id))
		if oc.Verified || oc.Partial {
			t.Fatalf("verified=%v partial=%v, want a failure", oc.Verified, oc.Partial)
		}
		if got := verdictExitCode(oc); got != exitFailed {
			t.Errorf("exit = %d, want %d", got, exitFailed)
		}
		if !strings.Contains(oc.Error, "does not chain to the --mesh-ca bundle") {
			t.Errorf("Error = %q", oc.Error)
		}
	})
}

// Both endpoint-evidence sources — a live attest-pq fetch and a saved bundle
// via --from-file — must mark the chain derived, never verified.
func TestEndpointEvidenceMarksChainDerived(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	report := bytes.Repeat([]byte{0x01}, 64)
	x := bytes.Repeat([]byte{0x02}, overenc.X25519PubBytes)
	m := bytes.Repeat([]byte{0x03}, overenc.MLKEM768EKBytes)
	id := mintEndpointIdentity(t)
	data := buildEndpointJSON(t, id, nonce, report, []byte("vcek"), x, m)

	for _, tc := range []struct {
		name string
		get  func() (*evidence, error)
	}{
		{"live fetch", func() (*evidence, error) { return evidenceFromEndpointJSON(data, nonce, "test") }},
		{"saved bundle", func() (*evidence, error) { return gatherFromFile(data, nil, "file", leafTrust{}) }},
	} {
		ev, err := tc.get()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !ev.leafChainDerived {
			t.Errorf("%s: leafChainDerived must record the responder-chosen anchor", tc.name)
		}
		if ev.leafChainVerified {
			t.Errorf("%s: a responder-chosen anchor is not a verified chain", tc.name)
		}
	}
}

// run() over a served discovery document: WebPKI mode with evidence that
// itself fails verification is a failure (exit 2), not a partial — the mode
// demotion only ever applies to a passing verdict. An unknown mode is a
// security verdict, and auto mode must not fall through past it.
func TestRunDiscoveryPublicTLSModeVerdicts(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	challenge := []byte("issuance-challenge")
	stubEvidence := `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`

	serve := func(t *testing.T, doc []byte) string {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(doc)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}

	t.Run("webpki + failing evidence is a failure, not partial", func(t *testing.T) {
		url := serve(t, discoveryDocWithPublicTLS(t, "webpki", certPEM, challenge, stubEvidence))
		var out, errOut bytes.Buffer
		code := run(context.Background(), config{url: url, kind: "lb", output: "text"}, &out, &errOut)
		if code != exitFailed {
			t.Errorf("exit = %d, want %d; output:\n%s%s", code, exitFailed, out.String(), errOut.String())
		}
	})

	t.Run("unknown mode is a verdict failure", func(t *testing.T) {
		url := serve(t, discoveryDocWithPublicTLS(t, "dns", certPEM, challenge, stubEvidence))
		var out, errOut bytes.Buffer
		code := run(context.Background(), config{url: url, kind: "lb", output: "text"}, &out, &errOut)
		if code != exitFailed {
			t.Errorf("exit = %d, want %d; output:\n%s%s", code, exitFailed, out.String(), errOut.String())
		}
		if !strings.Contains(out.String(), `public_tls.mode "dns"`) {
			t.Errorf("the verdict should name the unrecognized mode:\n%s", out.String())
		}
	})
}
