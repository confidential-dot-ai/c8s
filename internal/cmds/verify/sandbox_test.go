package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// attestedCert builds a self-signed cert carrying a (fake) SNP attestation
// extension, optionally with a sandbox-ID extension.
func attestedCert(t *testing.T, sandboxID string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: make([]byte, ratls.SNPReportSize)}
	der, err := ratls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sandboxID != "" {
		der = reissueWithSandboxID(t, key, sandboxID)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// reissueWithSandboxID mints a self-signed leaf carrying both the attestation
// and sandbox-ID extensions — the shape CDS produces, minus the CA signature.
func reissueWithSandboxID(t *testing.T, key *ecdsa.PrivateKey, sandboxID string) []byte {
	t.Helper()
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: make([]byte, ratls.SNPReportSize)}
	attExt, err := att.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	sandboxExt, err := ratls.MarshalSandboxIDExtension(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(7),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{attExt, sandboxExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestEvidenceFromCertReadsSandboxID(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	ev, err := evidenceFromCert(attestedCert(t, id), "test")
	if err != nil {
		t.Fatal(err)
	}
	if ev.sandboxID != id {
		t.Fatalf("sandboxID = %q, want %q", ev.sandboxID, id)
	}
	if ev.sandboxErr != nil {
		t.Fatalf("sandboxErr = %v", ev.sandboxErr)
	}
	if ev.leaf == nil {
		t.Fatal("leaf not retained; --mesh-ca could not check what CDS signed")
	}

	// A claims-free cert keeps the plain key anchor.
	want, err := ratls.ReportDataForKey(ev.leaf.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(ev.erd) != string(want[:48]) {
		t.Fatalf("erd = %x, want the plain key anchor %x", ev.erd, want[:48])
	}
}

// The reported ID is always qualified by what authenticates it: unqualified it
// would read as attested, which it is not.
func TestApplySandboxPolicyReportsProvenance(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	ev, err := evidenceFromCert(attestedCert(t, id), "test")
	if err != nil {
		t.Fatal(err)
	}

	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{}, ev)
	if oc.SandboxID != id {
		t.Fatalf("SandboxID = %q, want %q", oc.SandboxID, id)
	}
	if !strings.Contains(oc.SandboxIDNote, "not verified") {
		t.Fatalf("note = %q, want it to say the ID is unverified without --mesh-ca", oc.SandboxIDNote)
	}

	// A failed hardware verdict must not surface an "attested-looking" ID.
	failed := Outcome{Verified: false}
	applySandboxPolicy(&failed, config{}, ev)
	if failed.SandboxID != "" {
		t.Fatalf("SandboxID = %q on a failed verdict, want empty", failed.SandboxID)
	}
}

// A self-signed leaf cannot satisfy --sandbox-id: it does not chain to the mesh
// CA, and CDS's signature is the only thing that vouches for the ID.
func TestApplySandboxPolicySelfSignedFailsMeshCA(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	cert := attestedCert(t, id)
	ev, err := evidenceFromCert(cert, "test")
	if err != nil {
		t.Fatal(err)
	}

	// A CA bundle that did not sign this leaf.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mesh-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certutil.EncodeCertPEM(caDER), 0o600); err != nil {
		t.Fatal(err)
	}

	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{sandboxID: id, meshCA: caPath}, ev)
	if oc.Verified {
		t.Fatal("self-signed leaf claiming the pinned sandbox ID passed --mesh-ca")
	}
	if !strings.Contains(oc.Error, "mesh-ca") {
		t.Fatalf("error = %q, want it to name the CA check", oc.Error)
	}
}

// A malformed sandbox-ID extension fails the verdict rather than being ignored.
func TestApplySandboxPolicyUnparseableIDFailsClosed(t *testing.T) {
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{}, &evidence{sandboxErr: errSandboxTest})
	if oc.Verified {
		t.Fatal("unparseable sandbox-ID extension did not fail the verdict")
	}
}

var errSandboxTest = &sandboxTestError{}

type sandboxTestError struct{}

func (*sandboxTestError) Error() string { return "bad sandbox extension" }

// caSignedLeaf mints a leaf carrying sandboxID and signed by a fresh CA,
// returning the leaf and the CA bundle path — the shape CDS produces.
func caSignedLeaf(t *testing.T, sandboxID string) (*x509.Certificate, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mesh-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := ratls.MarshalSandboxIDExtension(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, certutil.EncodeCertPEM(caDER), 0o600); err != nil {
		t.Fatal(err)
	}
	return leaf, path
}

// With a mesh CA the leaf chains to, the pin holds and the note says the ID was
// actually verified rather than merely reported.
func TestApplySandboxPolicyVerifiedAgainstMeshCA(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	leaf, caPath := caSignedLeaf(t, id)
	ev := &evidence{leaf: leaf, sandboxID: id}

	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{sandboxID: id, meshCA: caPath}, ev)
	if !oc.Verified {
		t.Fatalf("verdict failed: %s", oc.Error)
	}
	if !strings.Contains(oc.SandboxIDNote, "verified: the leaf chains") {
		t.Fatalf("note = %q, want it to record the chain check", oc.SandboxIDNote)
	}

	// A different expected ID on the same chain-valid leaf must still fail.
	mismatch := Outcome{Verified: true}
	applySandboxPolicy(&mismatch, config{sandboxID: "someother", meshCA: caPath}, ev)
	if mismatch.Verified {
		t.Fatal("a mismatched --sandbox-id passed on a chain-valid leaf")
	}
}

// --mesh-ca asks a question; with no leaf to ask it of, that is an error rather
// than a silently skipped check reported as success.
func TestApplySandboxPolicyMeshCANeedsALeaf(t *testing.T) {
	_, caPath := caSignedLeaf(t, "abc")
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{meshCA: caPath}, &evidence{})
	if oc.Verified {
		t.Fatal("--mesh-ca silently passed with no leaf to check")
	}
}

// --operator-keys pins the attested config-claims digest, with the served list
// cross-checked against the attested value. Each way that can fail must demote
// the verdict, and a claims-free target must fail closed rather than compare
// against nothing.
func TestOperatorKeysPinAgainstClaims(t *testing.T) {
	pubPEM, _ := operatorPubPEM(t)
	keysPath := filepath.Join(t.TempDir(), "op.pub")
	if err := os.WriteFile(keysPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := expectedOperatorKeysDigest(config{operatorKeys: keysPath})
	if err != nil {
		t.Fatal(err)
	}
	claims := &ratls.ConfigClaims{
		OperatorKeysDigest: expected,
		SeedDigest:         ratls.UnsetDigest(),
		WorkloadDigest:     ratls.UnsetDigest(),
		MeshCADigest:       ratls.UnsetDigest(),
		AllowlistDigest:    ratls.UnsetDigest(),
	}
	policy := &ratls.VerifyPolicy{OperatorKeysDigest: expected}

	for _, tc := range []struct {
		name   string
		ev     *evidence
		report operatorKeysReport
		want   bool
	}{
		{"attested and served match", &evidence{configClaims: claims}, operatorKeysReport{digest: expected}, true},
		{"served set differs from attested", &evidence{configClaims: claims}, operatorKeysReport{digest: []byte("different")}, false},
		{"fetch failed", &evidence{configClaims: claims}, operatorKeysReport{fetchErr: errSandboxTest}, false},
		{"no claims to pin against", &evidence{}, operatorKeysReport{note: "kind is not cds"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oc := Outcome{Verified: true}
			applyClaimsPolicy(&oc, tc.ev, policy, tc.report)
			if oc.Verified != tc.want {
				t.Fatalf("Verified = %v, want %v (error: %s)", oc.Verified, tc.want, oc.Error)
			}
		})
	}
}

// An unreadable or empty --mesh-ca bundle fails the verdict rather than being
// treated as "no CA supplied", which would silently downgrade the check.
func TestMeshCABundleErrors(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.pem")
	if _, err := buildPolicy(config{meshCA: missing}); err == nil {
		t.Fatal("buildPolicy accepted a missing --mesh-ca file")
	}

	notPEM := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildPolicy(config{meshCA: notPEM}); err == nil {
		t.Fatal("buildPolicy accepted a --mesh-ca file with no certificates")
	}

	// And at policy-application time, where the file is read again.
	leaf, _ := caSignedLeaf(t, "abc")
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{meshCA: notPEM}, &evidence{leaf: leaf})
	if oc.Verified {
		t.Fatal("an unusable --mesh-ca bundle passed at apply time")
	}
}
