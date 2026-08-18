package ratls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// PackSNPMinTcb's layout is the SEV-SNP ABI TcbVersion (byte 0 = bootloader,
// byte 1 = tee, byte 6 = snp, byte 7 = microcode); a shift mutation here
// silently unfloors a component on every flag-plumbed path.
func TestPackSNPMinTcb(t *testing.T) {
	m := types.MinTcb{Bootloader: 0x11, Tee: 0x22, Snp: 0x33, Microcode: 0x44}
	if got, want := PackSNPMinTcb(m), uint64(0x44_33_00_00_00_00_22_11); got != want {
		t.Fatalf("PackSNPMinTcb(%+v) = %#x, want %#x", m, got, want)
	}
	// The zero floor packs to 0 — the "no floor" value callers skip on.
	if got := PackSNPMinTcb(types.MinTcb{}); got != 0 {
		t.Fatalf("PackSNPMinTcb(zero) = %#x, want 0", got)
	}
	for _, m := range []types.MinTcb{
		{Bootloader: 3, Snp: 8},
		{Tee: 1},
		{Microcode: 115},
		{Bootloader: 255, Tee: 255, Snp: 255, Microcode: 255},
		m,
	} {
		if got := unpackSNPMinTcb(PackSNPMinTcb(m)); got != m {
			t.Errorf("unpackSNPMinTcb(PackSNPMinTcb(%+v)) = %+v", m, got)
		}
	}
}

// A sandbox-ID pin rests on CDS's signature over the leaf. Neither path that
// verifies hardware evidence alone can establish that, so both refuse the pin
// rather than silently ignoring it and reporting success.
func TestSandboxPinFailsClosedOnEvidenceOnlyPaths(t *testing.T) {
	policy := &VerifyPolicy{AttestationApiURL: "http://127.0.0.1:1", SandboxID: "abc123"}

	if _, err := VerifyAttestation(nil, &Attestation{TEEType: TEETypeSEVSNP}, policy, nil); err == nil {
		t.Fatal("VerifyAttestation accepted a sandbox-ID pin it cannot authenticate")
	} else if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("err = %v, want ErrPolicyViolation", err)
	}

	cert := &x509.Certificate{}
	if _, err := VerifyCert(cert, policy, nil); err == nil {
		t.Fatal("VerifyCert accepted a sandbox-ID pin it cannot authenticate")
	}
}

// A workload pin is CA-vouched exactly like the sandbox ID, so the same two
// evidence-only paths refuse it rather than silently ignoring it.
func TestWorkloadPinFailsClosedOnEvidenceOnlyPaths(t *testing.T) {
	policy := &VerifyPolicy{AttestationApiURL: "http://127.0.0.1:1", WorkloadName: "api"}

	if _, err := VerifyAttestation(nil, &Attestation{TEEType: TEETypeSEVSNP}, policy, nil); err == nil {
		t.Fatal("VerifyAttestation accepted a workload pin it cannot authenticate")
	} else if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("err = %v, want ErrPolicyViolation", err)
	}

	if _, err := VerifyCert(&x509.Certificate{}, policy, nil); err == nil {
		t.Fatal("VerifyCert accepted a workload pin it cannot authenticate")
	}
}

// Both paths also require an attestation-api: there is no in-process verifier,
// so without one they must fail rather than accept unverified evidence.
func TestVerifyRequiresAttestationApi(t *testing.T) {
	if _, err := VerifyAttestation(nil, &Attestation{TEEType: TEETypeSEVSNP}, &VerifyPolicy{}, nil); err == nil {
		t.Fatal("VerifyAttestation ran with no attestation-api URL")
	} else if !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("err = %v, want ErrInvalidReport", err)
	}
}

// CheckSandboxPin is the one implementation both the mesh CA path and c8s
// verify use. Empty is a no-op so callers can invoke it unconditionally.
func TestCheckSandboxPin(t *testing.T) {
	withID, err := certWithSandboxID(t, "sandbox-abc")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSandboxPin(withID, ""); err != nil {
		t.Fatalf("empty pin should be a no-op: %v", err)
	}
	if err := CheckSandboxPin(withID, "sandbox-abc"); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}
	if err := CheckSandboxPin(withID, "other"); err == nil {
		t.Fatal("mismatched pin accepted")
	}
	if err := CheckSandboxPin(&x509.Certificate{}, "sandbox-abc"); err == nil {
		t.Fatal("pin satisfied by a certificate carrying no sandbox ID")
	}
}

func certWithSandboxID(t *testing.T, id string) (*x509.Certificate, error) {
	t.Helper()
	ext, err := MarshalSandboxIDExtension(id)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{Extensions: []pkix.Extension{ext}}, nil
}
