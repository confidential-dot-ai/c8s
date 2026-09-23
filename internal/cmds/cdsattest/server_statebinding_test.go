package cdsattest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const testRoute = "api"

func b64urlDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return raw
}

// mutableState is a StateProvider a test drives: it holds one statement and
// the time it was fetched, so both a policy move and staleness are set rather
// than waited for.
type mutableState struct {
	mu        sync.Mutex
	signed    policystate.SignedState
	fetchedAt time.Time
	have      bool
}

func (m *mutableState) State() (policystate.SignedState, time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.signed, m.fetchedAt, m.have
}

func (m *mutableState) set(signed policystate.SignedState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signed, m.fetchedAt, m.have = signed, time.Now(), true
}

// age backdates the held statement past the server's maximum age.
func (m *mutableState) age(by time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fetchedAt = m.fetchedAt.Add(-by)
}

// stateFixture is a deployment a test moves through an update: the authority
// key, the provider the server reads, and the statements to install.
type stateFixture struct {
	t     *testing.T
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	state *mutableState
}

func newStateFixture(t *testing.T) *stateFixture {
	t.Helper()
	pub, priv := mustGenerateKey(t)
	f := &stateFixture{t: t, pub: pub, priv: priv, state: &mutableState{}}
	f.install(f.settled(1, digestP))
	return f
}

// settled is the statement of a deployment with nothing outstanding.
func (f *stateFixture) settled(position uint64, active string) policystate.State {
	s := testState(f.t, f.pub, position)
	s.ActiveDigest = active
	return s
}

// publishing is the statement between a publication and the switch: the
// advertised bound is source-or-target while the removal drains.
func (f *stateFixture) publishing(position uint64, switched bool) policystate.State {
	s := f.settled(position, digestP)
	s.Update = &policystate.Update{
		Version:       2,
		SourceDigest:  digestP,
		TargetDigest:  digestQ,
		RequiresDrain: true,
		Switched:      switched,
	}
	if switched {
		s.ActiveVersion, s.ActiveDigest = 2, digestQ
	}
	return s
}

func (f *stateFixture) install(s policystate.State) {
	f.t.Helper()
	f.state.set(mustSignState(f.t, f.priv, s))
}

// freshStateProvider is a deployment at rest: one active policy, nothing
// outstanding. Every attest-pq test needs one, since a front door with no CDS
// state source serves no attest-pq at all.
func freshStateProvider(t *testing.T) *mutableState {
	t.Helper()
	return newStateFixture(t).state
}

// newStateBoundServer builds the sidecar with a CDS state source, which is the
// only shape that serves attest-pq.
func newStateBoundServer(t *testing.T, state StateProvider) (*Server, *httptest.Server, *capturingProvider) {
	t.Helper()
	identity := writeTestMeshIdentity(t)
	prov := &capturingProvider{}
	srv := NewServer(Config{
		Logger:               quietLogger(),
		Evidence:             prov,
		FrontDoorMode:        types.FrontDoorModeCDS,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		ExpectedWorkload:     testRoute,
		State:                state,
		StateMaxAge:          time.Minute,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts, prov
}

// boundOf is what a verifier recomputes from a served bundle: the statement's
// own bound, which must be exactly the envelope the response advertises.
func boundOf(t *testing.T, bundle types.AttestationBundle) []string {
	t.Helper()
	var signed policystate.SignedState
	if err := policystate.Decode(bundle.State, &signed); err != nil {
		t.Fatalf("decode the bound statement: %v", err)
	}
	if err := policystate.VerifySignedState(signed); err != nil {
		t.Fatalf("the bound statement does not verify: %v", err)
	}
	return policystate.Bound(signed.Statement)
}

// stateHashOf is what a verifier recomputes: the hash of the served
// statement, never the state_hash field the response chose for itself.
func stateHashOf(t *testing.T, bundle types.AttestationBundle) string {
	t.Helper()
	var signed policystate.SignedState
	if err := policystate.Decode(bundle.State, &signed); err != nil {
		t.Fatalf("decode the bound statement: %v", err)
	}
	hash, err := policystate.StateHash(signed.Statement)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestAttestPQBindsTheDeploymentPolicy(t *testing.T) {
	f := newStateFixture(t)
	_, ts, prov := newStateBoundServer(t, f.state)

	nonce := testNonce(t)
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := fetchBundle(t, ts.URL, ck, nonce)

	if bundle.Version != types.BindingAttestPQ {
		t.Fatalf("binding identifier = %q, want %q", bundle.Version, types.BindingAttestPQ)
	}
	if bundle.Route != testRoute {
		t.Fatalf("route = %q, want %q", bundle.Route, testRoute)
	}
	want := boundOf(t, bundle)
	if !slices.Equal(bundle.Envelope, want) {
		t.Fatalf("envelope = %v, want the statement's bound %v", bundle.Envelope, want)
	}
	var signed policystate.SignedState
	if err := policystate.Decode(bundle.State, &signed); err != nil {
		t.Fatal(err)
	}
	hash, err := policystate.StateHash(signed.Statement)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.StateHash != hash {
		t.Fatalf("state_hash = %q, want %q", bundle.StateHash, hash)
	}

	// report_data must be the transcript over the recomputed hash, envelope
	// and route — not over anything the response chose for itself.
	certs, err := certutil.ParsePEMCertificates([]byte(bundle.CDSCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	wantRD, err := overenc.IdentityTranscriptHash(bundle.FrontDoorMode, ck.EncapsulationKey(),
		b64urlDecode(t, bundle.XWingCT), b64urlDecode(t, bundle.SessionID), nonce,
		certs[0].Raw, certs[1].Raw, hash, want, bundle.Route)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := base64.RawURLEncoding.DecodeString(bundle.IdentityProof.LeafSHA256)
	if err != nil || len(proof) == 0 {
		t.Fatalf("bundle carries no identity proof: %v", err)
	}
	if !bytes.Equal(prov.lastReportData, wantRD) {
		t.Fatal("report_data is not the transcript over the served state hash, envelope and route")
	}
}

// During an update that removes permissions, a session established now is
// pinned to both digests: it may reach a workload admitted under either.
func TestAttestPQDuringAnUpdateCarriesBothDigests(t *testing.T) {
	f := newStateFixture(t)
	f.install(f.publishing(2, false))
	_, ts, _ := newStateBoundServer(t, f.state)

	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := fetchBundle(t, ts.URL, ck, testNonce(t))
	want := []string{digestP, digestQ}
	slices.Sort(want)
	if !slices.Equal(bundle.Envelope, want) {
		t.Fatalf("envelope = %v, want the source-or-target bound %v", bundle.Envelope, want)
	}
}

// There is no unbound mode: without a CDS state source attest-pq serves
// nothing rather than an attestation that says nothing about the policy.
func TestAttestPQWithoutCDSRefuses(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Logger:               quietLogger(),
		Evidence:             testFixture(),
		FrontDoorMode:        types.FrontDoorModeCDS,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postAttestPQ(t, ts.URL, validAttestPQBody(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("attest-pq without CDS = %d, want %d", resp.StatusCode, http.StatusNotImplemented)
	}
	if code := errorCode(t, resp); code != types.ErrorCodeBindingUnavailable {
		t.Fatalf("error code = %q, want %q", code, types.ErrorCodeBindingUnavailable)
	}
}

func TestAttestPQOnStaleStateRefuses(t *testing.T) {
	f := newStateFixture(t)
	_, ts, _ := newStateBoundServer(t, f.state)
	f.state.age(2 * time.Minute)

	resp := postAttestPQ(t, ts.URL, validAttestPQBody(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("attest-pq on stale state = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if code := errorCode(t, resp); code != types.ErrorCodeStateStale {
		t.Fatalf("error code = %q, want %q", code, types.ErrorCodeStateStale)
	}
}

// attest-lb rides nginx TLS straight to the upstream: this sidecar owns no
// such session, so it binds no policy and claims no barrier for one.
func TestAttestLBCarriesNoStateBinding(t *testing.T) {
	f := newStateFixture(t)
	identity := writeTestMeshIdentity(t)
	certPath, _ := writeTestServingLeaf(t)
	srv := NewServer(Config{
		Logger:               quietLogger(),
		Evidence:             testFixture(),
		FrontDoorMode:        types.FrontDoorModeCDS,
		ServingCertFile:      certPath,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		ExpectedWorkload:     testRoute,
		State:                f.state,
		StateMaxAge:          time.Minute,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	bundle := getBundle(t, ts.URL+"/.well-known/c8s/attest-lb?nonce="+base64.RawURLEncoding.EncodeToString(testNonce(t)))
	if bundle.Version != types.BindingAttestLB {
		t.Fatalf("binding identifier = %q, want %q", bundle.Version, types.BindingAttestLB)
	}
	if len(bundle.State) != 0 || bundle.StateHash != "" || len(bundle.Envelope) != 0 || bundle.Route != "" {
		t.Fatalf("attest-lb bundle carries a state binding: %+v", bundle)
	}
}

func getBundle(t *testing.T, url string) types.AttestationBundle {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s = %d, want 200: %s", url, resp.StatusCode, body)
	}
	var b types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var body types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Error
}
