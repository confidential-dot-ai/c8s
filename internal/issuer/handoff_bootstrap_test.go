package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// TestNextRefreshAfter exercises the refresh-cadence math without touching
// any network state. Each branch matters: a token with very long TTL must be
// capped so we don't sleep through cluster events, and an already-expired one
// must retry quickly rather than yield a negative delay.
//
// "no readable token" is no longer this function's concern — AtomicHandoffEAR
// refuses to store a token whose exp it cannot read, so the refresh loop falls
// back to minHandoffRefresh before it ever gets here. See
// TestAtomicHandoffEARRejectsUnreadableToken.
func TestNextRefreshAfter(t *testing.T) {
	cases := []struct {
		name       string
		exp        time.Time
		wantApprox time.Duration
		tolerance  time.Duration
	}{
		{
			name:       "zero expiry",
			exp:        time.Time{},
			wantApprox: 30 * time.Second,
			tolerance:  time.Second,
		},
		{
			name:       "expired token",
			exp:        time.Now().Add(-time.Minute),
			wantApprox: 30 * time.Second,
			tolerance:  time.Second,
		},
		{
			name:       "long-TTL token capped at maxHandoffRefresh",
			exp:        time.Now().Add(48 * time.Hour),
			wantApprox: time.Hour,
			tolerance:  time.Second,
		},
		{
			name:       "ordinary TTL halved",
			exp:        time.Now().Add(20 * time.Minute),
			wantApprox: 10 * time.Minute,
			tolerance:  2 * time.Second,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nextRefreshAfter(c.exp)
			if got < c.wantApprox-c.tolerance || got > c.wantApprox+c.tolerance {
				t.Fatalf("nextRefreshAfter = %v, want ≈ %v", got, c.wantApprox)
			}
		})
	}
}

// TestAtomicHandoffEARRejectsUnreadableToken pins the invariant that moved the
// parse to write time: a token whose exp cannot be read is never stored, so a
// reader can never obtain a token the refresh loop cannot schedule against.
func TestAtomicHandoffEARRejectsUnreadableToken(t *testing.T) {
	for name, token := range map[string]string{
		"empty":       "",
		"not a jwt":   "not.a.jwt",
		"missing exp": makeUnsignedJWTWithClaimsForTest(t, `{"iat":0}`),
	} {
		t.Run(name, func(t *testing.T) {
			a := &AtomicHandoffEAR{}
			if err := a.Set(token); err == nil {
				t.Fatal("expected Set to reject a token with no readable exp")
			}
			if _, err := a.Current(); err == nil {
				t.Fatal("rejected token must not be observable via Current")
			}
			if _, err := a.ExpiresAt(); err == nil {
				t.Fatal("rejected token must not be observable via ExpiresAt")
			}
		})
	}
}

// TestAtomicHandoffEARRoundTrip confirms the basic invariants the refresh
// loop and the request handler depend on: an unset source returns an
// error, a set source returns the token, set is observable atomically, and
// concurrent readers/writers don't tear.
func TestAtomicHandoffEARRoundTrip(t *testing.T) {
	a := &AtomicHandoffEAR{}
	if _, err := a.Current(); err == nil {
		t.Fatal("expected unset source to return error")
	}
	if _, err := a.ExpiresAt(); err == nil {
		t.Fatal("expected unset source to return error from ExpiresAt")
	}

	wantExp := time.Now().Add(time.Hour).Truncate(time.Second)
	token1 := makeUnsignedJWTForTest(t, wantExp.Unix())
	if err := a.Set(token1); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := a.Current()
	if err != nil {
		t.Fatalf("Current after set: %v", err)
	}
	if got != token1 {
		t.Fatalf("Current = %q, want %q", got, token1)
	}
	// The expiry is derived once at Set and must match the token handed back,
	// not be re-derived per read.
	gotExp, err := a.ExpiresAt()
	if err != nil {
		t.Fatalf("ExpiresAt after set: %v", err)
	}
	if !gotExp.Equal(wantExp) {
		t.Fatalf("ExpiresAt = %v, want %v", gotExp, wantExp)
	}

	// Concurrent set + Current — race detector catches sliced reads.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = a.Current()
				}
			}
		}()
	}
	// Pre-build the tokens so the loop measures store/load contention rather
	// than JWT construction.
	tokens := make([]string, 8)
	for i := range tokens {
		tokens[i] = makeUnsignedJWTForTest(t, time.Now().Add(time.Duration(i+1)*time.Hour).Unix())
	}
	for i := 0; i < 1000; i++ {
		if err := a.Set(tokens[i%len(tokens)]); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

// --- LocalHandoffBootstrap (cds in-process attest-key) ---

type stubAttestation struct {
	attestResp types.AttestResponse
	attestErr  error
	verifyResp types.VerifyResponse
	verifyErr  error
	verifyReqs *[]types.VerifyRequest // when set, Verify records each request
}

func (s stubAttestation) Attest(context.Context, types.AttestRequest) (types.AttestResponse, error) {
	return s.attestResp, s.attestErr
}

func (s stubAttestation) Verify(_ context.Context, req types.VerifyRequest) (types.VerifyResponse, error) {
	if s.verifyReqs != nil {
		*s.verifyReqs = append(*s.verifyReqs, req)
	}
	return s.verifyResp, s.verifyErr
}

type stubMinter struct {
	called              atomic.Int32
	gotDigest           string
	gotPub              *ecdsa.PublicKey
	gotOperatorKeysHash string
	tokenToIssue        string
}

func (m *stubMinter) IssueAttestedKey(_ json.RawMessage, launchDigest string, pub *ecdsa.PublicKey, operatorKeysHash string) (string, error) {
	m.called.Add(1)
	m.gotDigest = launchDigest
	m.gotPub = pub
	m.gotOperatorKeysHash = operatorKeysHash
	return m.tokenToIssue, nil
}

const testOperatorKeysHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func verifyOK(match bool, digest string) types.VerifyResponse {
	return types.VerifyResponse{Result: types.VerificationResult{
		SignatureValid:  true,
		ReportDataMatch: &match,
		Claims: types.Claims{
			LaunchDigest: digest,
			PlatformData: json.RawMessage(`{"policy":{"debug_allowed":false}}`),
		},
	}}
}

// TestLocalHandoffBootstrapMintsOnlyAfterVerify is the load-bearing test for
// the cds-local handoff signer EAR: it must mint exactly when the verifier
// confirms both SignatureValid and ReportDataMatch, and must refuse otherwise.
// Skipping verification would let a host-supplied evidence blob dictate the
// EAR's launch digest — the value /handoff peers pin against.
func TestLocalHandoffBootstrapMintsOnlyAfterVerify(t *testing.T) {
	cases := []struct {
		name     string
		verify   types.VerifyResponse
		wantMint bool
	}{
		{"signature valid + report-data match", verifyOK(true, "deadbeef"), true},
		{"signature invalid", types.VerifyResponse{Result: types.VerificationResult{SignatureValid: false}}, false},
		{"report-data mismatch", verifyOK(false, "deadbeef"), false},
		{"report-data nil", types.VerifyResponse{Result: types.VerificationResult{SignatureValid: true}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			minter := &stubMinter{tokenToIssue: "minted-ear"}
			b, err := NewLocalHandoffBootstrap(
				stubAttestation{
					attestResp: types.AttestResponse{Platform: "snp"},
					verifyResp: tc.verify,
				},
				minter,
				testOperatorKeysHash,
				nil,
			)
			if err != nil {
				t.Fatalf("NewLocalHandoffBootstrap: %v", err)
			}
			lb := b.(*localHandoffBootstrap)
			pubDER, err := x509.MarshalPKIXPublicKey(&lb.signer.PublicKey)
			if err != nil {
				t.Fatalf("marshal pubkey: %v", err)
			}

			token, err := lb.attestKey(context.Background(), pubDER)
			if tc.wantMint {
				if err != nil {
					t.Fatalf("attestKey: %v", err)
				}
				if token != "minted-ear" {
					t.Fatalf("token = %q, want minted-ear", token)
				}
				if minter.called.Load() != 1 {
					t.Fatalf("minter calls = %d, want 1", minter.called.Load())
				}
				if minter.gotDigest != "deadbeef" {
					t.Fatalf("launch digest = %q, want deadbeef", minter.gotDigest)
				}
				if minter.gotPub == nil || !minter.gotPub.Equal(&lb.signer.PublicKey) {
					t.Fatalf("minted EAR not bound to the signer pubkey")
				}
				if minter.gotOperatorKeysHash != testOperatorKeysHash {
					t.Fatalf("operator key-set hash = %q, want %q", minter.gotOperatorKeysHash, testOperatorKeysHash)
				}
			} else {
				if err == nil {
					t.Fatalf("expected attestKey to refuse, got token %q", token)
				}
				if minter.called.Load() != 0 {
					t.Fatalf("minter called %d times on a failed verify; must be 0", minter.called.Load())
				}
			}
		})
	}
}

// TestLocalHandoffBootstrapMinTCBFloor pins the floor on the handoff
// self-attestation: SNP evidence carries it and is refused below it, while TDX
// evidence (what PlatformAuto resolves to on a TDX host) drops it — a floor
// asserted against TDX claims would refuse CDS's own EAR bootstrap.
func TestLocalHandoffBootstrapMinTCBFloor(t *testing.T) {
	floor := types.MinTcb{Bootloader: 3, Snp: 8}
	match := true
	verifyWith := func(tcb, platformData string) types.VerifyResponse {
		return types.VerifyResponse{Result: types.VerificationResult{
			SignatureValid:  true,
			ReportDataMatch: &match,
			Claims: types.Claims{
				LaunchDigest: "deadbeef",
				Tcb:          json.RawMessage(tcb),
				PlatformData: json.RawMessage(platformData),
			},
		}}
	}

	cases := []struct {
		name      string
		platform  string
		verify    types.VerifyResponse
		wantMint  bool
		wantFloor bool // the /verify request must carry the floor
	}{
		{
			name:     "SNP at the floor mints and carries the floor",
			platform: "snp",
			verify: verifyWith(
				`{"type":"Snp","bootloader":3,"tee":0,"snp":8,"microcode":115}`,
				`{"policy":{"debug_allowed":false}}`,
			),
			wantMint:  true,
			wantFloor: true,
		},
		{
			name:     "below-floor SNP evidence mints nothing",
			platform: "snp",
			verify: verifyWith(
				`{"type":"Snp","bootloader":3,"tee":0,"snp":7,"microcode":115}`,
				`{"policy":{"debug_allowed":false}}`,
			),
			wantMint:  false,
			wantFloor: true,
		},
		{
			name:     "TDX evidence drops the floor and mints",
			platform: "tdx",
			verify: verifyWith(
				`{"type":"Tdx","tcb_svn":"00000000000000000000000000000000"}`,
				`{"td_attributes_parsed":{"debug":false}}`,
			),
			wantMint:  true,
			wantFloor: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reqs []types.VerifyRequest
			minter := &stubMinter{tokenToIssue: "minted-ear"}
			b, err := NewLocalHandoffBootstrap(
				stubAttestation{
					attestResp: types.AttestResponse{Platform: tc.platform},
					verifyResp: tc.verify,
					verifyReqs: &reqs,
				},
				minter,
				testOperatorKeysHash,
				&floor,
			)
			if err != nil {
				t.Fatalf("NewLocalHandoffBootstrap: %v", err)
			}
			lb := b.(*localHandoffBootstrap)
			pubDER, err := x509.MarshalPKIXPublicKey(&lb.signer.PublicKey)
			if err != nil {
				t.Fatalf("marshal pubkey: %v", err)
			}

			_, err = lb.attestKey(context.Background(), pubDER)
			if tc.wantMint && err != nil {
				t.Fatalf("attestKey: %v", err)
			}
			if !tc.wantMint && err == nil {
				t.Fatal("expected attestKey to refuse below-floor evidence")
			}
			if len(reqs) != 1 || reqs[0].Params == nil {
				t.Fatalf("verify requests = %+v, want 1 with params", reqs)
			}
			if tc.wantFloor && (reqs[0].Params.MinTcb == nil || *reqs[0].Params.MinTcb != floor) {
				t.Fatalf("min_tcb = %+v, want %+v", reqs[0].Params.MinTcb, floor)
			}
			if !tc.wantFloor && reqs[0].Params.MinTcb != nil {
				t.Fatalf("min_tcb = %+v, want nil for platform %q", reqs[0].Params.MinTcb, tc.platform)
			}
		})
	}
}

// TestLocalHandoffBootstrapRequiresDeps guards the constructor's nil checks: a
// nil attestation-api or minter is a wiring bug that must fail loudly at
// startup, not silently disable handoff.
func TestLocalHandoffBootstrapRequiresDeps(t *testing.T) {
	as := stubAttestation{}
	mi := &stubMinter{}
	for _, tc := range []struct {
		name string
		as   AttestationApi
		mi   LocalEARMinter
	}{
		{"nil attestation", nil, mi},
		{"nil minter", as, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewLocalHandoffBootstrap(tc.as, tc.mi, testOperatorKeysHash, nil); err == nil {
				t.Fatal("expected constructor to reject nil dependency")
			}
		})
	}
	if _, err := NewLocalHandoffBootstrap(as, mi, "", nil); err == nil {
		t.Fatal("expected constructor to reject an empty operator key-set hash")
	}
}

// refreshStubAttestation drives RunRefresh: onAttest runs before anything
// else (tests use it to cancel the refresh loop), and Attest fails on a done
// context so the per-iteration deadline is honored.
type refreshStubAttestation struct {
	attestErr error
	verify    types.VerifyResponse
	onAttest  func()
}

func (s refreshStubAttestation) Attest(ctx context.Context, _ types.AttestRequest) (types.AttestResponse, error) {
	if s.onAttest != nil {
		s.onAttest()
	}
	if s.attestErr != nil {
		return types.AttestResponse{}, s.attestErr
	}
	if err := ctx.Err(); err != nil {
		return types.AttestResponse{}, err
	}
	return types.AttestResponse{Platform: "snp"}, nil
}

func (s refreshStubAttestation) Verify(context.Context, types.VerifyRequest) (types.VerifyResponse, error) {
	return s.verify, nil
}

// cancellingMinter cancels the refresh loop after minting so RunRefresh
// returns right after the first successful iteration.
type cancellingMinter struct {
	token  string
	cancel context.CancelFunc
}

func (m *cancellingMinter) IssueAttestedKey(json.RawMessage, string, *ecdsa.PublicKey, string) (string, error) {
	m.cancel()
	return m.token, nil
}

func TestRunRefreshStoresMintedEAR(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	token := makeUnsignedJWTForTest(t, time.Now().Add(time.Hour).Unix())
	b, err := NewLocalHandoffBootstrap(
		refreshStubAttestation{verify: verifyOK(true, "deadbeef")},
		&cancellingMinter{token: token, cancel: cancel},
		testOperatorKeysHash,
		nil,
	)
	if err != nil {
		t.Fatalf("NewLocalHandoffBootstrap: %v", err)
	}
	lb := b.(*localHandoffBootstrap)

	capture := &captureHandler{}
	lb.RunRefresh(ctx, slog.New(capture))

	got, err := lb.earSource.Current()
	if err != nil {
		t.Fatalf("Current after refresh: %v", err)
	}
	if got != token {
		t.Fatalf("stored EAR = %q, want minted token", got)
	}
	if _, ok := capture.find("handoff EAR refreshed (local)"); !ok {
		t.Fatal("successful refresh did not log the refreshed message")
	}
}

func TestRunRefreshWarnsWhenBootstrapAttestFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, err := NewLocalHandoffBootstrap(
		refreshStubAttestation{attestErr: fmt.Errorf("attestation-api down"), onAttest: cancel},
		&stubMinter{},
		testOperatorKeysHash,
		nil,
	)
	if err != nil {
		t.Fatalf("NewLocalHandoffBootstrap: %v", err)
	}
	lb := b.(*localHandoffBootstrap)

	capture := &captureHandler{}
	lb.RunRefresh(ctx, slog.New(capture))

	if _, err := lb.earSource.Current(); err == nil {
		t.Fatal("failed bootstrap must not store an EAR")
	}
	// With no previous EAR the failure must log the bootstrap message, not the
	// keeping-previous-EAR one.
	if _, ok := capture.find("handoff bootstrap: local attest-key failed; will retry"); !ok {
		t.Fatal("bootstrap failure did not log the will-retry message")
	}
	if _, ok := capture.find("handoff refresh: local attest-key failed; keeping previous EAR"); ok {
		t.Fatal("bootstrap failure logged the keeping-previous-EAR message with no previous EAR")
	}
}

func makeUnsignedJWTForTest(t *testing.T, exp int64) string {
	t.Helper()
	return makeUnsignedJWTWithClaimsForTest(t, fmt.Sprintf(`{"exp":%d,"iat":0}`, exp))
}

func makeUnsignedJWTWithClaimsForTest(t *testing.T, claims string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(claims))
	// Signature is irrelevant for unverifiedEARExpiry — it parses claims only.
	return header + "." + body + ".sig"
}
