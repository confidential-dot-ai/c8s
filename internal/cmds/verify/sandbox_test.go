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
	applySandboxPolicy(&oc, config{}, ev, operatorKeysReport{})
	if oc.SandboxID != id {
		t.Fatalf("SandboxID = %q, want %q", oc.SandboxID, id)
	}
	if !strings.Contains(oc.SandboxIDNote, "not verified") {
		t.Fatalf("note = %q, want it to say the ID is unverified without --mesh-ca", oc.SandboxIDNote)
	}

	// A failed hardware verdict must not surface an "attested-looking" ID.
	failed := Outcome{Verified: false}
	applySandboxPolicy(&failed, config{}, ev, operatorKeysReport{})
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
	applySandboxPolicy(&oc, config{sandboxID: id, meshCA: caPath}, ev, operatorKeysReport{})
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
	applySandboxPolicy(&oc, config{}, &evidence{sandboxErr: errSandboxTest}, operatorKeysReport{})
	if oc.Verified {
		t.Fatal("unparseable sandbox-ID extension did not fail the verdict")
	}
}

var errSandboxTest = &sandboxTestError{}

type sandboxTestError struct{}

func (*sandboxTestError) Error() string { return "bad sandbox extension" }
