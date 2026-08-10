package join

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Register values used across the tests. All 48-byte SHA-384 hex.
var (
	digestA = strings.Repeat("ad", 48)
	digestB = strings.Repeat("bd", 48)
	rtmr1A  = strings.Repeat("a1", 48)
	rtmr2A  = strings.Repeat("a2", 48)
	rtmr1B  = strings.Repeat("b1", 48)
)

// tdxEnvelope is a minimal self-describing evidence envelope for RA-TLS
// certs; verdicts come from the fake attestation-api, nothing parses it.
const tdxEnvelope = `{"platform":"tdx","evidence":{}}`

// fakeAPI is a stand-in local attestation-api: POST /attest returns a TDX
// envelope, POST /verify answers via verifyFn keyed by call number (1-based),
// so tests can serve different claims to ownRefs and verifyPeer.
type fakeAPI struct {
	URL            string
	attestPlatform string
	verifyFn       func(call int, req types.VerifyRequest) types.VerifyResponse
	verifyCalls    atomic.Int32
}

func newFakeAPI(t *testing.T, verifyFn func(call int, req types.VerifyRequest) types.VerifyResponse) *fakeAPI {
	t.Helper()
	f := &fakeAPI{attestPlatform: string(types.PlatformTdx), verifyFn: verifyFn}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/attest":
			_ = json.NewEncoder(w).Encode(types.AttestResponse{
				Platform: f.attestPlatform,
				Evidence: json.RawMessage(`{"quote":"ZmFrZS1xdW90ZQ=="}`),
			})
		case "/verify":
			var req types.VerifyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("verify body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(f.verifyFn(int(f.verifyCalls.Add(1)), req))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}

// verifyResp builds a /verify response with the given claims and verdicts.
func verifyResp(digest, r1, r2 string, sigValid, rdMatch bool) types.VerifyResponse {
	pd, err := json.Marshal(map[string]string{"rtmr_1": r1, "rtmr_2": r2})
	if err != nil {
		panic(err)
	}
	return types.VerifyResponse{Result: types.VerificationResult{
		Platform:        string(types.PlatformTdx),
		SignatureValid:  sigValid,
		Claims:          types.Claims{LaunchDigest: digest, PlatformData: pd},
		ReportDataMatch: &rdMatch,
	}}
}

// staticVerify answers every /verify call identically.
func staticVerify(resp types.VerifyResponse) func(int, types.VerifyRequest) types.VerifyResponse {
	return func(int, types.VerifyRequest) types.VerifyResponse { return resp }
}

// mustRefs builds an imageRefs from hex register values.
func mustRefs(t *testing.T, digest, r1, r2 string) imageRefs {
	t.Helper()
	d, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal(err)
	}
	return imageRefs{launchDigest: d, rtmr1: r1, rtmr2: r2}
}

// attestedLeaf builds a genuine RA-TLS leaf cert embedding envelope.
func attestedLeaf(t *testing.T, envelope string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ratls.CreateAttestedCert(key, &ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: []byte(envelope)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// selfSigned signs tmpl with a fresh P-256 key and parses the result.
func selfSigned(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// attestedLeafWindow builds an RA-TLS leaf with an explicit validity window
// (CreateAttestedCert always starts at now, which the freshness check needs to
// vary).
func attestedLeafWindow(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	ext, err := (&ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: []byte(tdxEnvelope)}).MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	return selfSigned(t, &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "ratls-window"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		ExtraExtensions: []pkix.Extension{ext},
	})
}

// plainLeaf builds a self-signed cert with no RA-TLS extension.
func plainLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	return selfSigned(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "plain"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	})
}

func TestOwnRefs(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
		refs, err := ownRefs(context.Background(), attestationclient.NewClient(api.URL))
		if err != nil {
			t.Fatal(err)
		}
		want := mustRefs(t, digestA, rtmr1A, rtmr2A)
		if !bytes.Equal(refs.launchDigest, want.launchDigest) || refs.rtmr1 != want.rtmr1 || refs.rtmr2 != want.rtmr2 {
			t.Errorf("refs = %+v, want %+v", refs, want)
		}
	})

	t.Run("non-tdx platform rejected", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
		api.attestPlatform = string(types.PlatformSnp)
		if _, err := ownRefs(context.Background(), attestationclient.NewClient(api.URL)); err == nil {
			t.Fatal("expected error for non-tdx platform")
		}
	})

	t.Run("invalid signature fails closed", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, false, true)))
		_, err := ownRefs(context.Background(), attestationclient.NewClient(api.URL))
		if !errors.Is(err, attestationclient.ErrSignatureInvalid) {
			t.Fatalf("err = %v, want ErrSignatureInvalid", err)
		}
	})

	t.Run("report_data mismatch fails closed", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, false)))
		_, err := ownRefs(context.Background(), attestationclient.NewClient(api.URL))
		if !errors.Is(err, attestationclient.ErrReportDataMismatch) {
			t.Fatalf("err = %v, want ErrReportDataMismatch", err)
		}
	})

	t.Run("api down", func(t *testing.T) {
		if _, err := ownRefs(context.Background(), attestationclient.NewClient("http://127.0.0.1:1")); err == nil {
			t.Fatal("expected error with no attestation-api")
		}
	})
}

func TestRefsFromClaims(t *testing.T) {
	pd := func(r1, r2 string) json.RawMessage {
		b, err := json.Marshal(map[string]string{"rtmr_1": r1, "rtmr_2": r2})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	tests := []struct {
		name    string
		claims  types.Claims
		wantErr bool
	}{
		{"ok", types.Claims{LaunchDigest: digestA, PlatformData: pd(rtmr1A, rtmr2A)}, false},
		{"uppercase normalised", types.Claims{LaunchDigest: digestA, PlatformData: pd(strings.ToUpper(rtmr1A), rtmr2A)}, false},
		{"digest not hex", types.Claims{LaunchDigest: "zz", PlatformData: pd(rtmr1A, rtmr2A)}, true},
		{"digest short", types.Claims{LaunchDigest: digestA[:10], PlatformData: pd(rtmr1A, rtmr2A)}, true},
		{"digest empty", types.Claims{LaunchDigest: "", PlatformData: pd(rtmr1A, rtmr2A)}, true},
		{"rtmr_1 missing", types.Claims{LaunchDigest: digestA, PlatformData: pd("", rtmr2A)}, true},
		{"rtmr_2 short", types.Claims{LaunchDigest: digestA, PlatformData: pd(rtmr1A, "abcd")}, true},
		{"platform_data absent", types.Claims{LaunchDigest: digestA}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			refs, err := refsFromClaims(tc.claims)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && (refs.rtmr1 != rtmr1A || refs.rtmr2 != rtmr2A) {
				t.Errorf("refs = %+v not normalised to lowercase", refs)
			}
		})
	}
}

func TestVerifyPeer(t *testing.T) {
	own := mustRefs(t, digestA, rtmr1A, rtmr2A)

	t.Run("same-image peer accepted, report_data bound to leaf key", func(t *testing.T) {
		leaf := attestedLeaf(t, tdxEnvelope)
		wantRD, err := ratls.ReportDataForKey(leaf.PublicKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		api := newFakeAPI(t, func(_ int, req types.VerifyRequest) types.VerifyResponse {
			if req.Params == nil || req.Params.ExpectedReportData == nil {
				t.Error("verify request carries no expected_report_data")
			} else if !bytes.Equal(req.Params.ExpectedReportData.Bytes(), wantRD[:]) {
				t.Error("expected_report_data is not ReportDataForKey(leaf pubkey)")
			}
			return verifyResp(digestA, rtmr1A, rtmr2A, true, true)
		})
		if err := verifyPeer(context.Background(), attestationclient.NewClient(api.URL), leaf, own); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("case-insensitive register compare", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(strings.ToUpper(digestA), strings.ToUpper(rtmr1A), strings.ToUpper(rtmr2A), true, true)))
		if err := verifyPeer(context.Background(), attestationclient.NewClient(api.URL), attestedLeaf(t, tdxEnvelope), own); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("validity window", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			name       string
			notBefore  time.Time
			notAfter   time.Time
			wantAccept bool
		}{
			{"current", now.Add(-time.Hour), now.Add(time.Hour), true},
			{"expired", now.Add(-25 * time.Hour), now.Add(-time.Hour), false},
			{"not yet valid", now.Add(time.Hour), now.Add(25 * time.Hour), false},
			{"just issued on a fast peer clock", now.Add(time.Minute), now.Add(24 * time.Hour), true},
			{"just expired within skew", now.Add(-24 * time.Hour), now.Add(-time.Minute), true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
				leaf := attestedLeafWindow(t, tc.notBefore, tc.notAfter)
				err := verifyPeer(context.Background(), attestationclient.NewClient(api.URL), leaf, own)
				if tc.wantAccept != (err == nil) {
					t.Fatalf("err = %v, wantAccept %v", err, tc.wantAccept)
				}
				if !tc.wantAccept && api.verifyCalls.Load() != 0 {
					t.Error("evidence was sent for verification despite a stale cert")
				}
			})
		}
	})

	t.Run("no RA-TLS extension", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
		if err := verifyPeer(context.Background(), attestationclient.NewClient(api.URL), plainLeaf(t), own); err == nil {
			t.Fatal("expected error for cert without attestation")
		}
	})

	t.Run("non-tdx envelope", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
		leaf := attestedLeaf(t, `{"platform":"snp","evidence":{}}`)
		if err := verifyPeer(context.Background(), attestationclient.NewClient(api.URL), leaf, own); err == nil {
			t.Fatal("expected error for non-tdx peer")
		}
	})

	t.Run("launch digest mismatch", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestB, rtmr1A, rtmr2A, true, true)))
		err := verifyPeer(context.Background(), attestationclient.NewClient(api.URL), attestedLeaf(t, tdxEnvelope), own)
		if !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
	})

	t.Run("rtmr_1 mismatch", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1B, rtmr2A, true, true)))
		err := verifyPeer(context.Background(), attestationclient.NewClient(api.URL), attestedLeaf(t, tdxEnvelope), own)
		if !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
	})

	t.Run("rtmr_2 mismatch", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr1B, true, true)))
		err := verifyPeer(context.Background(), attestationclient.NewClient(api.URL), attestedLeaf(t, tdxEnvelope), own)
		if !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
	})

	t.Run("report_data mismatch is not a policy error", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, false)))
		err := verifyPeer(context.Background(), attestationclient.NewClient(api.URL), attestedLeaf(t, tdxEnvelope), own)
		if err == nil || errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want binding failure", err)
		}
	})
}
