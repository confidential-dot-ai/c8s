package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// selfSignedCertPEM returns a throwaway ECDSA P-256 certificate (PEM) and its
// public key, for testing REPORTDATA-binding math without real SNP crypto.
func selfSignedCertPEM(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cds"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), &key.PublicKey
}

func TestEvidenceFromDiscovery(t *testing.T) {
	certPEM, pub := selfSignedCertPEM(t)
	report := bytes.Repeat([]byte{0x01}, 1184)
	vcek := []byte("vcek-der-bytes")
	challenge := bytes.Repeat([]byte{0x05}, 32)

	buildDoc := func(platform, cert string) []byte {
		doc := map[string]any{
			"cds_tls": map[string]any{"certificate_pem": cert},
			"attestation": map[string]any{
				"platform":  platform,
				"challenge": base64.StdEncoding.EncodeToString(challenge),
				"evidence": map[string]any{
					"attestation_report": base64.StdEncoding.EncodeToString(report),
					"cert_chain":         map[string]any{"vcek": base64.StdEncoding.EncodeToString(vcek)},
				},
			},
		}
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("forwards platform + evidence verbatim and binds cert key + challenge", func(t *testing.T) {
		ev, err := evidenceFromDiscovery(buildDoc("snp", certPEM), "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.platform != "snp" {
			t.Errorf("platform = %q, want snp", ev.platform)
		}
		var inner map[string]any
		if err := json.Unmarshal(ev.rawEvidence, &inner); err != nil {
			t.Fatalf("rawEvidence not JSON: %v", err)
		}
		if inner["attestation_report"] != base64.StdEncoding.EncodeToString(report) {
			t.Error("evidence object not forwarded verbatim")
		}
		if ev.fresh {
			t.Error("discovery is bound to the issuance challenge, not a fresh nonce")
		}
		want, err := ratls.ReportDataForKey(pub, challenge)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ev.erd, keyAnchor(want)) {
			t.Error("erd must equal the unpadded ReportDataForKey(cert.pubkey, challenge) — the issuance binding")
		}
	})

	t.Run("forwards a non-snp platform (e.g. tdx) rather than rejecting it", func(t *testing.T) {
		ev, err := evidenceFromDiscovery(buildDoc("tdx", certPEM), "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.platform != "tdx" {
			t.Errorf("platform = %q, want tdx forwarded", ev.platform)
		}
	})

	t.Run("rejects missing certificate", func(t *testing.T) {
		if _, err := evidenceFromDiscovery(buildDoc("snp", ""), "test"); err == nil {
			t.Fatal("expected error when certificate_pem is absent")
		}
	})
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		raw      string
		port     int
		wantDial string
		wantBase string
	}{
		{"cds.example.com", 8443, "cds.example.com:8443", "https://cds.example.com:8443"},
		{"cds.example.com:9999", 8443, "cds.example.com:9999", "https://cds.example.com:9999"},
		{"https://lb.example.com", 443, "lb.example.com:443", "https://lb.example.com:443"},
		{"https://lb.example.com:8443/ignored", 443, "lb.example.com:8443", "https://lb.example.com:8443"},
		{"2001:db8::2", 8443, "[2001:db8::2]:8443", "https://[2001:db8::2]:8443"},
		{"[2001:db8::2]:9999", 8443, "[2001:db8::2]:9999", "https://[2001:db8::2]:9999"},
	}
	for _, c := range cases {
		dial, base, err := normalizeTarget(c.raw, c.port)
		if err != nil {
			t.Fatalf("normalizeTarget(%q): %v", c.raw, err)
		}
		if dial != c.wantDial || base != c.wantBase {
			t.Errorf("normalizeTarget(%q) = (%q,%q), want (%q,%q)", c.raw, dial, base, c.wantDial, c.wantBase)
		}
	}
}

func TestBuildPolicy_RejectsOutOfRangeMinTCB(t *testing.T) {
	if _, err := buildPolicy(config{minTCBSNP: 256}); err == nil {
		t.Fatal("expected --min-tcb-snp 256 to be rejected (would truncate to 0)")
	}
	if _, err := buildPolicy(config{minTCBBootloader: 255, minTCBTEE: 1}); err != nil {
		t.Errorf("in-range min-tcb values should be accepted: %v", err)
	}
}

func TestParseExpectedReportData(t *testing.T) {
	if _, err := parseExpectedReportData(strings.Repeat("ab", 64)); err != nil {
		t.Errorf("64-byte hex should parse: %v", err)
	}
	if _, err := parseExpectedReportData(strings.Repeat("cd", 48)); err != nil {
		t.Errorf("48-byte hex should parse: %v", err)
	}
	// Any 1–64 bytes is accepted, kept unpadded — the binding digest length
	// isn't fixed across platforms/schemes.
	if got, err := parseExpectedReportData(strings.Repeat("ab", 10)); err != nil || len(got) != 10 {
		t.Errorf("10-byte hex should parse unpadded: %v (len %d)", err, len(got))
	}
	if _, err := parseExpectedReportData("zzzz"); err == nil {
		t.Error("non-hex should fail")
	}
	if _, err := parseExpectedReportData(""); err == nil {
		t.Error("empty should fail")
	}
	if _, err := parseExpectedReportData(strings.Repeat("ab", 65)); err == nil {
		t.Error("more than 64 bytes should fail")
	}
}

// endpointIdentity is a minted mesh identity (CA-signed ECDSA leaf plus its
// issuing CA) used to build attest-pq responses whose identity transcript and
// proof of possession actually verify.
type endpointIdentity struct {
	leaf     *x509.Certificate
	ca       *x509.Certificate
	key      *ecdsa.PrivateKey
	chainPEM string
}

func mintEndpointIdentity(t *testing.T) *endpointIdentity {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mesh CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "lb.c8s-system.svc"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return &endpointIdentity{leaf: leaf, ca: ca, key: leafKey, chainPEM: chain}
}

// transcript computes the identity transcript the server would have bound for
// this identity and session.
func (id *endpointIdentity) transcript(t *testing.T, nonce, x25519, mlkem []byte) []byte {
	t.Helper()
	erd, err := overenc.IdentityTranscriptHash(overenc.PublicKey{X25519: x25519, MLKEM768: mlkem}, nonce, id.leaf.Raw, id.ca.Raw)
	if err != nil {
		t.Fatal(err)
	}
	return erd
}

// proofJSON builds the wire identity_proof object: ECDSA-SHA384 by the leaf
// key over sha512.Sum384(transcript), mirroring the sidecar's prove().
func (id *endpointIdentity) proofJSON(t *testing.T, transcript []byte) map[string]any {
	t.Helper()
	digest := sha512.Sum384(transcript)
	sig, err := ecdsa.SignASN1(rand.Reader, id.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	leafHash := sha256.Sum256(id.leaf.Raw)
	caHash := sha256.Sum256(id.ca.Raw)
	b64u := base64.RawURLEncoding.EncodeToString
	return map[string]any{
		"algorithm":      "ecdsa-sha384",
		"leaf_sha256":    b64u(leafHash[:]),
		"mesh_ca_sha256": b64u(caHash[:]),
		"signature":      b64u(sig),
	}
}

// buildEndpointJSON makes an attest-pq attestation-response body with the
// given fields. A nil identity omits the mesh chain and identity proof.
func buildEndpointJSON(t *testing.T, id *endpointIdentity, nonce, report, vcek, x25519, mlkem []byte) []byte {
	t.Helper()
	evidence := map[string]any{
		"attestation_report": base64.StdEncoding.EncodeToString(report),
		"cert_chain":         map[string]any{"vcek": base64.StdEncoding.EncodeToString(vcek)},
	}
	return buildEndpointJSONWithEvidence(t, id, nonce, evidence, x25519, mlkem)
}

func buildEndpointJSONWithEvidence(t *testing.T, id *endpointIdentity, nonce []byte, evidence any, x25519, mlkem []byte) []byte {
	t.Helper()
	b64u := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	resp := map[string]any{
		"version":        types.BindingAttestPQ,
		"platform":       "snp",
		"nonce":          b64u(nonce),
		"evidence":       evidence,
		"session_pubkey": map[string]any{"x25519": b64u(x25519), "mlkem768": b64u(mlkem)},
	}
	if id != nil {
		resp["cds_cert_pem"] = id.chainPEM
		resp["identity_proof"] = id.proofJSON(t, id.transcript(t, nonce, x25519, mlkem))
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEvidenceFromEndpointJSON(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	report := bytes.Repeat([]byte{0x01}, 64)
	x := bytes.Repeat([]byte{0x02}, overenc.X25519PubBytes)
	m := bytes.Repeat([]byte{0x03}, overenc.MLKEM768EKBytes)
	id := mintEndpointIdentity(t)
	data := buildEndpointJSON(t, id, nonce, report, []byte("vcek"), x, m)

	// mutateProof rebuilds data with one identity_proof field replaced.
	mutateProof := func(t *testing.T, field, value string) []byte {
		t.Helper()
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		obj["identity_proof"].(map[string]any)[field] = value
		out, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	t.Run("fresh when nonce echoes; erd is the identity transcript", func(t *testing.T) {
		ev, err := evidenceFromEndpointJSON(data, nonce, "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if !ev.fresh {
			t.Error("expected fresh=true when challenge echoes")
		}
		if !bytes.Equal(ev.erd, id.transcript(t, nonce, x, m)) {
			t.Error("erd does not match the identity transcript over keys, nonce, leaf, and CA")
		}
		if ev.leaf == nil || !bytes.Equal(ev.leaf.Raw, id.leaf.Raw) {
			t.Error("the transcript-committed mesh leaf should surface for the --mesh-ca/--workload paths")
		}
	})

	t.Run("from-file (no expected nonce) verifies but stays non-fresh", func(t *testing.T) {
		ev, err := evidenceFromEndpointJSON(data, nil, "file")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.fresh {
			t.Error("a saved response must not count as a freshness proof")
		}
		if !bytes.Equal(ev.erd, id.transcript(t, nonce, x, m)) {
			t.Error("erd must still be the identity transcript")
		}
	})

	t.Run("tampered proof signature is a security error", func(t *testing.T) {
		sig, err := ecdsa.SignASN1(rand.Reader, id.key, bytes.Repeat([]byte{0x5C}, 48))
		if err != nil {
			t.Fatal(err)
		}
		mutated := mutateProof(t, "signature", base64.RawURLEncoding.EncodeToString(sig))
		if _, err := evidenceFromEndpointJSON(mutated, nonce, "test"); err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError on a signature over the wrong transcript, got %v", err)
		}
	})

	t.Run("wrong leaf hash in the proof is a security error", func(t *testing.T) {
		otherHash := sha256.Sum256([]byte("not-the-leaf"))
		mutated := mutateProof(t, "leaf_sha256", base64.RawURLEncoding.EncodeToString(otherHash[:]))
		if _, err := evidenceFromEndpointJSON(mutated, nonce, "test"); err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError on leaf_sha256 mismatch, got %v", err)
		}
	})

	t.Run("committed CA absent from the served chain is a security error", func(t *testing.T) {
		otherHash := sha256.Sum256([]byte("not-a-served-ca"))
		mutated := mutateProof(t, "mesh_ca_sha256", base64.RawURLEncoding.EncodeToString(otherHash[:]))
		if _, err := evidenceFromEndpointJSON(mutated, nonce, "test"); err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError when no served cert matches mesh_ca_sha256, got %v", err)
		}
	})

	t.Run("unknown proof algorithm is a security error", func(t *testing.T) {
		mutated := mutateProof(t, "algorithm", "ecdsa-sha256")
		if _, err := evidenceFromEndpointJSON(mutated, nonce, "test"); err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError on an unknown proof algorithm, got %v", err)
		}
	})

	t.Run("leaf not signed by the committed CA is a security error", func(t *testing.T) {
		// Serve id's leaf with a *different* identity's CA and commit that CA
		// honestly in the transcript and proof: everything verifies except the
		// issuing relationship, which must fail closed.
		other := mintEndpointIdentity(t)
		b64u := base64.RawURLEncoding.EncodeToString
		erd, err := overenc.IdentityTranscriptHash(overenc.PublicKey{X25519: x, MLKEM768: m}, nonce, id.leaf.Raw, other.ca.Raw)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha512.Sum384(erd)
		sig, err := ecdsa.SignASN1(rand.Reader, id.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		leafHash := sha256.Sum256(id.leaf.Raw)
		caHash := sha256.Sum256(other.ca.Raw)
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		obj["cds_cert_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.leaf.Raw})) +
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.ca.Raw}))
		obj["identity_proof"] = map[string]any{
			"algorithm":      "ecdsa-sha384",
			"leaf_sha256":    b64u(leafHash[:]),
			"mesh_ca_sha256": b64u(caHash[:]),
			"signature":      b64u(sig),
		}
		mutated, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromEndpointJSON(mutated, nonce, "test"); err == nil || !isSecurityError(err) || !strings.Contains(err.Error(), "not signed by") {
			t.Fatalf("expected a chain securityError, got %v", err)
		}
	})

	t.Run("missing identity proof rejected", func(t *testing.T) {
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		delete(obj, "identity_proof")
		mutated, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromEndpointJSON(mutated, nonce, "test"); err == nil || !strings.Contains(err.Error(), "identity_proof") {
			t.Fatalf("expected a missing-proof error, got %v", err)
		}
	})

	t.Run("nonce mismatch is a security error (not swallowed by auto fallback)", func(t *testing.T) {
		_, err := evidenceFromEndpointJSON(data, bytes.Repeat([]byte{0x09}, nonceSize), "test")
		if err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError on nonce mismatch, got %v", err)
		}
		if isConnectError(err) {
			t.Error("nonce mismatch must not be a connectError (would trigger silent cert fallback)")
		}
	})

	t.Run("wrong or missing version rejected (cross-endpoint responses)", func(t *testing.T) {
		for _, version := range []string{"", "c8s-verify/v1", types.BindingAttestLB, "c8s/attest-pq/v2"} {
			var obj map[string]any
			if err := json.Unmarshal(data, &obj); err != nil {
				t.Fatal(err)
			}
			if version == "" {
				delete(obj, "version")
			} else {
				obj["version"] = version
			}
			mutated, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := evidenceFromEndpointJSON(mutated, nonce, "test"); err == nil || !strings.Contains(err.Error(), "version") {
				t.Errorf("version %q should be rejected, got %v", version, err)
			}
		}
	})

	t.Run("missing session keys rejected", func(t *testing.T) {
		bare := buildEndpointJSON(t, nil, nonce, report, []byte("vcek"), nil, nil)
		if _, err := evidenceFromEndpointJSON(bare, nonce, "test"); err == nil {
			t.Fatal("expected error when session_pubkey is absent")
		}
	})

	t.Run("wrong-size session key rejected", func(t *testing.T) {
		// The transcript is length-framed; IdentityTranscriptHash refuses a
		// non-canonical key size outright rather than producing a binding that
		// fails report-data match downstream.
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		obj["session_pubkey"].(map[string]any)["x25519"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 16))
		mutated, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromEndpointJSON(mutated, nonce, "test"); err == nil || !strings.Contains(err.Error(), "X25519") {
			t.Fatalf("expected a key-size error from the transcript, got %v", err)
		}
	})

	t.Run("non-snp platform is forwarded, not rejected", func(t *testing.T) {
		var obj map[string]any
		_ = json.Unmarshal(data, &obj)
		obj["platform"] = "tdx"
		other, _ := json.Marshal(obj)
		ev, err := evidenceFromEndpointJSON(other, nonce, "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.platform != "tdx" {
			t.Errorf("platform = %q, want tdx forwarded", ev.platform)
		}
	})
}

// TestEvidenceFromEndpointJSON_RealShape feeds a literal JSON document in the
// exact shape the attestation endpoint emits (per c8s-verify-js PROTOCOL.md),
// rather than one built from this package's own structs — so a renamed or
// re-nested wire field fails here even though the struct-built fixtures above
// wouldn't notice.
func TestEvidenceFromEndpointJSON_RealShape(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xA1}, nonceSize)
	x := bytes.Repeat([]byte{0xB2}, overenc.X25519PubBytes)
	m := bytes.Repeat([]byte{0xC3}, overenc.MLKEM768EKBytes)
	report := bytes.Repeat([]byte{0xD4}, 64)
	b64u := base64.RawURLEncoding.EncodeToString

	id := mintEndpointIdentity(t)
	erd := id.transcript(t, nonce, x, m)
	digest := sha512.Sum384(erd)
	sig, err := ecdsa.SignASN1(rand.Reader, id.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	leafHash := sha256.Sum256(id.leaf.Raw)
	caHash := sha256.Sum256(id.ca.Raw)

	payload := fmt.Sprintf(`{
  "version": %q,
  "platform": "snp",
  "nonce": %q,
  "evidence": {
    "attestation_report": %q,
    "cert_chain": { "vcek": %q }
  },
  "cds_cert_pem": %q,
  "session_pubkey": { "x25519": %q, "mlkem768": %q },
  "identity_proof": { "algorithm": "ecdsa-sha384", "leaf_sha256": %q, "mesh_ca_sha256": %q, "signature": %q }
}`,
		types.BindingAttestPQ,
		b64u(nonce),
		base64.StdEncoding.EncodeToString(report),
		base64.StdEncoding.EncodeToString([]byte("vcek-der")),
		id.chainPEM,
		b64u(x), b64u(m),
		b64u(leafHash[:]), b64u(caHash[:]), b64u(sig),
	)

	ev, err := evidenceFromEndpointJSON([]byte(payload), nonce, "endpoint")
	if err != nil {
		t.Fatalf("real-shape endpoint payload should parse: %v", err)
	}
	if !ev.fresh {
		t.Error("expected fresh=true when the challenge echoes")
	}
	if ev.platform != "snp" {
		t.Errorf("platform = %q, want snp", ev.platform)
	}
	if !bytes.Equal(ev.erd, erd) {
		t.Error("erd does not match the identity transcript")
	}
	// The platform-specific evidence object is forwarded verbatim.
	if !bytes.Contains(ev.rawEvidence, []byte("attestation_report")) {
		t.Error("evidence object should be forwarded verbatim")
	}
}

// TestParseRealSNPEvidence drives a *real* captured {platform, evidence} object
// — a Genoa SEV-SNP report + VCEK, vendored from the c8s-verify-js reference
// impl's fixture (demo/fixtures/snp-evidence-genoa.json) — through the parser,
// so field/encoding drift between the JS and Go implementations fails here.
func TestParseRealSNPEvidence(t *testing.T) {
	fixture, err := os.ReadFile("testdata/snp-evidence-genoa.json")
	if err != nil {
		t.Fatal(err)
	}

	// The bare {platform, evidence} path consumes it directly.
	bare, err := evidenceFromBareJSON(fixture, make([]byte, 48), "fixture")
	if err != nil {
		t.Fatalf("evidenceFromBareJSON on the real fixture: %v", err)
	}
	if bare.platform != "snp" {
		t.Errorf("platform = %q, want snp", bare.platform)
	}
	if !bytes.Contains(bare.rawEvidence, []byte("attestation_report")) || !bytes.Contains(bare.rawEvidence, []byte("vcek")) {
		t.Error("real evidence (report + vcek) should be forwarded verbatim")
	}

	// The attestation endpoint wraps that same platform-specific evidence; parse
	// a real endpoint response built around it.
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(fixture, &env); err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x5A}, nonceSize)
	x := bytes.Repeat([]byte{0xB2}, overenc.X25519PubBytes)
	m := bytes.Repeat([]byte{0xC3}, overenc.MLKEM768EKBytes)
	id := mintEndpointIdentity(t)
	resp := buildEndpointJSONWithEvidence(t, id, nonce, env.Evidence, x, m)

	ev, err := evidenceFromEndpointJSON(resp, nonce, "endpoint")
	if err != nil {
		t.Fatalf("evidenceFromEndpointJSON on the real-evidence response: %v", err)
	}
	if !ev.fresh {
		t.Error("expected fresh=true when the challenge echoes")
	}
	// json.Marshal compacts an embedded RawMessage, so compare against the
	// compacted fixture bytes: the value must round-trip unchanged.
	var wantEvidence bytes.Buffer
	if err := json.Compact(&wantEvidence, env.Evidence); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.rawEvidence, wantEvidence.Bytes()) {
		t.Error("real evidence object should round-trip unchanged through the endpoint parser")
	}
	if !bytes.Equal(ev.erd, id.transcript(t, nonce, x, m)) {
		t.Error("erd binding mismatch")
	}
}

// TestVerifyRealAzSnpEvidence_UnpaddedAnchor drives real az-snp evidence (vTPM
// quote extraData = ASCII "challenge", VCEK inline; vendored from
// attestation-go's azsnp testdata) through the --from-file override path. The
// anchor must reach the verifier unpadded: the Azure vTPM verifiers compare it
// raw against the quote's extraData, so the historical zero-padding to 64
// bytes failed every az-snp target with "TPM nonce length mismatch".
func TestVerifyRealAzSnpEvidence_UnpaddedAnchor(t *testing.T) {
	fixture, err := os.ReadFile("testdata/azsnp-evidence-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := gatherFromFile(fixture, []byte("challenge"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if ev.platform != "az-snp" {
		t.Fatalf("platform = %q, want az-snp", ev.platform)
	}
	res, err := verifyInProcess(context.Background(), ev, &ratls.VerifyPolicy{}, nil)
	if err != nil {
		t.Fatalf("az-snp evidence with its bound nonce must verify: %v", err)
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		t.Fatal("report_data_match must be affirmatively true")
	}

	// A different anchor fails closed, at the nonce gate specifically.
	ev.erd = []byte("not-the-nonce")
	if _, err := verifyInProcess(context.Background(), ev, &ratls.VerifyPolicy{}, nil); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("wrong nonce must fail closed at the nonce check, got: %v", err)
	}
}

func TestGatherFromEndpoint_Integration(t *testing.T) {
	report := bytes.Repeat([]byte{0x01}, 64)
	x := bytes.Repeat([]byte{0x02}, overenc.X25519PubBytes)
	m := bytes.Repeat([]byte{0x03}, overenc.MLKEM768EKBytes)
	id := mintEndpointIdentity(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != attestationPath {
			http.NotFound(w, r)
			return
		}
		nb := r.URL.Query().Get("nonce")
		nonce, _ := base64.RawURLEncoding.DecodeString(nb)
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildEndpointJSON(t, id, nonce, report, []byte("vcek"), x, m))
	}))
	defer srv.Close()

	ev, err := gatherFromEndpoint(context.Background(), srv.URL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("gatherFromEndpoint: %v", err)
	}
	if !ev.fresh {
		t.Error("expected fresh evidence from live endpoint")
	}
	var inner map[string]any
	if err := json.Unmarshal(ev.rawEvidence, &inner); err != nil {
		t.Fatalf("rawEvidence not JSON: %v", err)
	}
	if inner["attestation_report"] != base64.StdEncoding.EncodeToString(report) {
		t.Error("evidence object not forwarded verbatim from the endpoint")
	}
}

func TestGatherFromEndpoint_HTTPErrorIsConnectError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := gatherFromEndpoint(context.Background(), srv.URL, "", 5*time.Second)
	if err == nil || !isConnectError(err) {
		t.Fatalf("expected connectError on HTTP 503, got %v", err)
	}
}

func TestRenderOutcome(t *testing.T) {
	ev := &evidence{
		platform:    "snp",
		source:      "test",
		bindingNote: "test binding",
		fresh:       true,
	}
	measHex := "ab" + strings.Repeat("00", 47) // 48-byte launch digest
	result := &teetypes.VerificationResult{SignatureValid: true, Claims: teetypes.Claims{LaunchDigest: measHex}}

	pinnedPolicy := func(t *testing.T) *ratls.VerifyPolicy {
		t.Helper()
		m, err := ratls.ParseHexMeasurementsList([]string{measHex})
		if err != nil {
			t.Fatal(err)
		}
		return &ratls.VerifyPolicy{Measurements: m}
	}

	t.Run("verified + pinned -> no UNSAFE warning", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "text"}
		oc := newOutcome(cfg, ev, result, nil, pinnedPolicy(t))
		render(cfg, oc, &out)
		if !oc.Verified {
			t.Fatalf("expected verified; oc=%+v", oc)
		}
		if !strings.Contains(out.String(), "VERIFIED") || strings.Contains(out.String(), "UNSAFE") {
			t.Errorf("unexpected output: %s", out.String())
		}
	})

	t.Run("unpinned warns UNSAFE", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "text"}
		render(cfg, newOutcome(cfg, ev, result, nil, &ratls.VerifyPolicy{}), &out)
		if !strings.Contains(out.String(), "UNSAFE") {
			t.Errorf("expected UNSAFE warning when no measurements pinned: %s", out.String())
		}
	})

	t.Run("json output", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "json"}
		render(cfg, newOutcome(cfg, ev, result, nil, &ratls.VerifyPolicy{}), &out)
		var oc Outcome
		if err := json.Unmarshal(out.Bytes(), &oc); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if !oc.Verified || oc.Measurement != measHex {
			t.Errorf("unexpected outcome: %+v", oc)
		}
	})

	t.Run("verdict error -> NOT VERIFIED", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "text"}
		oc := newOutcome(cfg, ev, nil, &securityError{err: errors.New("rejected")}, &ratls.VerifyPolicy{})
		render(cfg, oc, &out)
		if oc.Verified || !strings.Contains(out.String(), "NOT VERIFIED") {
			t.Errorf("unexpected output: %s", out.String())
		}
	})

	t.Run("measurement not in allowlist -> not verified", func(t *testing.T) {
		// A genuine TEE whose launch digest isn't pinned must fail closed: the
		// allowlist is enforced here (the verifier has no --measurements input).
		other, err := ratls.ParseHexMeasurementsList([]string{"00" + strings.Repeat("11", 47)})
		if err != nil {
			t.Fatal(err)
		}
		oc := newOutcome(config{}, ev, result, nil, &ratls.VerifyPolicy{Measurements: other})
		if oc.Verified || !strings.Contains(oc.Error, "not in --measurements allowlist") {
			t.Errorf("expected allowlist rejection, got %+v", oc)
		}
	})
}

func TestGatherFromFile_RejectsExpectedReportDataOnCert(t *testing.T) {
	// A certificate's binding is its key; an override would silently replace a
	// real binding while still reporting "binds the certificate public key".
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("does-not-matter")})
	if _, err := gatherFromFile(pemCert, make([]byte, 48), "file"); err == nil {
		t.Fatal("expected --expected-report-data to be rejected for a certificate file")
	}
}

func TestRun_NoTarget(t *testing.T) {
	// No URL and no --from-file is a usage error.
	var out, errOut bytes.Buffer
	code := run(context.Background(), config{}, &out, &errOut)
	if code != exitUsage {
		t.Errorf("code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "no target") {
		t.Errorf("missing 'no target' message: %s", errOut.String())
	}
}

// TestRunDiscoveryVerify_EndToEnd exercises run() through the discovery URL
// path: GET an unauthenticated discovery doc, then verify in-process. The stub
// evidence isn't a real SNP report, so verification fails closed — which proves
// the discovery → gather → verify → render → exit-code chain runs and the
// binding is extracted: a verification failure (exit 2), not a gather failure
// (exit 3).
func TestRunDiscoveryVerify_EndToEnd(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	challenge := []byte("issuance-challenge")
	doc := discoveryDocWith(t, certPEM, challenge, `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`)

	// The "tls-lb": serves the discovery doc unauthenticated at /v1/discovery.
	lb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != defaultDiscoveryPath {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write(doc)
	}))
	defer lb.Close()

	var out, errOut bytes.Buffer
	code := run(context.Background(), config{
		url:    lb.URL,
		kind:   "lb",
		output: "text",
	}, &out, &errOut)
	output := out.String() + errOut.String()

	if code != exitFailed {
		t.Fatalf("code = %d, want %d (stub evidence must fail closed at verify, not gather); output:\n%s",
			code, exitFailed, output)
	}
	if !strings.Contains(out.String(), "NOT VERIFIED") {
		t.Errorf("expected NOT VERIFIED, got:\n%s", output)
	}
}

// TestResolveMode locks in kind→mode routing. The regression it guards: an
// explicit --kind must drive the evidence mode when --mode is left at its
// (auto) default, so `c8s cds verify --kind lb` resolves to discovery rather
// than dialing for the embedded RA-TLS extension the LB front door never
// serves. An explicit non-auto --mode always wins over kind.
func TestResolveMode(t *testing.T) {
	cases := []struct {
		name string
		kind string
		mode string
		want string
	}{
		{"lb kind, auto mode", "lb", "auto", "discovery"},
		{"lb kind, empty mode", "lb", "", "discovery"},
		{"cds kind, auto mode", "cds", "auto", "ratls-cert"},
		{"workload kind, auto mode", "workload", "auto", "ratls-cert"},
		{"auto kind, auto mode", "auto", "auto", "auto"},
		{"empty kind, empty mode", "", "", "auto"},
		{"explicit mode overrides lb kind", "lb", "ratls-cert", "ratls-cert"},
		{"explicit mode overrides cds kind", "cds", "attest-pq", "attest-pq"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveMode(config{kind: tc.kind, mode: tc.mode})
			if got != tc.want {
				t.Errorf("resolveMode(kind=%q, mode=%q) = %q, want %q", tc.kind, tc.mode, got, tc.want)
			}
		})
	}
}

// TestGatherEvidence_AutoPrefersDiscovery proves auto mode (no --kind) detects
// an LB by fetching its discovery doc first — the bare `c8s verify <lb>` path.
func TestGatherEvidence_AutoPrefersDiscovery(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	doc := discoveryDocWith(t, certPEM, []byte("challenge"), `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`)
	lb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != defaultDiscoveryPath {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write(doc)
	}))
	defer lb.Close()

	ev, err := gatherEvidence(context.Background(), config{url: lb.URL, kind: "auto"}, nil)
	if err != nil {
		t.Fatalf("auto mode should reach the discovery doc, got: %v", err)
	}
	if !strings.Contains(ev.source, "discovery document") {
		t.Errorf("source = %q, want the discovery-doc path", ev.source)
	}
}

// TestGatherEvidence_AutoFallsBackToServingCert proves auto mode falls through
// to the RA-TLS serving cert when discovery is absent (a non-LB TLS endpoint):
// the surfaced error is the cert-path verdict, not the discovery 404.
func TestGatherEvidence_AutoFallsBackToServingCert(t *testing.T) {
	// 404s every path (no /v1/discovery) and presents httptest's plain serving
	// cert, which carries no RA-TLS extension.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := gatherEvidence(context.Background(), config{url: srv.URL, kind: "auto"}, nil)
	if !errors.Is(err, ratls.ErrNotAttested) {
		t.Fatalf("want fall-through to the serving-cert path (ErrNotAttested), got: %v", err)
	}
}
