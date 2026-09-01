package issuer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/teewebpki"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/crypto/cryptobyte"
)

type testKeyProvider struct{ pub *ecdsa.PublicKey }

const handoffTestOperatorKeysHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func handoffTestClusterIdentity(t *testing.T) *tls.Certificate {
	t.Helper()
	key := handoffTestKey(t)
	ext, err := ratls.MarshalMatchedWorkloadExtension(&ratls.MatchedWorkload{
		Name: "c8s-cds-2026-09-01", Identity: "c8s-cds",
		AllowlistVersion: "1", AllowlistDigest: bytes.Repeat([]byte{0x44}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "c8s-cds"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func handoffTestServer(t *testing.T, hh *HandoffHandler) (*httptest.Server, *tls.Certificate) {
	t.Helper()
	identity := handoffTestClusterIdentity(t)
	leaf := identity.Leaf
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{{leaf}},
		}
		if r.URL.Path == "/handoff/activate" {
			hh.HandleActivate(w, r)
			return
		}
		if r.URL.Path == "/handoff/confirm" {
			hh.HandleConfirm(w, r)
			return
		}
		if r.URL.Path == "/handoff/abort" {
			hh.HandleAbort(w, r)
			return
		}
		hh.HandleHandoff(w, r)
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, identity
}

func handoffTestClusterSignature(t *testing.T, identity *tls.Certificate, ear, publicKey string) string {
	t.Helper()
	_, key, err := handoffClusterIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	message, err := handoffClusterMessage(ear, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signHandoffMessage(key, message)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func handoffTestDigest() types.Digest {
	digest, err := types.ParseDigest("sha256:" + strings.Repeat("1", 64))
	if err != nil {
		panic(err)
	}
	return digest
}

func (p testKeyProvider) PublicKey(string) (*ecdsa.PublicKey, error) {
	return p.pub, nil
}

type staticHandoffEARSource struct{ ear string }

func (s staticHandoffEARSource) Current() (string, error) {
	return strings.TrimSpace(s.ear), nil
}

// ExpiresAt parses on every read rather than at store time, unlike
// AtomicHandoffEAR. That keeps this fake a one-field literal and lets tests
// drive the "expiry unreadable" branch by supplying a non-JWT ear.
func (s staticHandoffEARSource) ExpiresAt() (time.Time, error) {
	return unverifiedEARExpiry(strings.TrimSpace(s.ear))
}

func snapshotFromCA(ca *CA) func() (CASnapshot, bool) {
	return func() (CASnapshot, bool) {
		return CASnapshot{
			Cert:             ca.Cert,
			Key:              ca.Key,
			AllowlistVersion: "17",
			Allowlist: map[types.Digest]string{
				handoffTestDigest(): "registry.example/dynamic:latest",
			},
			Workloads: map[string]allowlist.Workload{
				"web": {Containers: []allowlist.Container{{Digest: handoffTestDigest()}}},
			},
			TEEWebPKI: &teewebpki.Snapshot{
				Schema: teewebpki.Schema, Version: 7,
				TLSKeySeed:      bytes.Repeat([]byte{0x31}, teewebpki.SeedSize),
				ACMEAccountSeed: bytes.Repeat([]byte{0x42}, teewebpki.SeedSize),
				ACMEState:       json.RawMessage(`{"account":"active","order":"pending"}`),
			},
			Secrets: &secrets.Snapshot{
				Version: secrets.SnapshotVersion, MaxPaths: 8, MaxPerHolder: 2, MaxValue: 64,
				Entries: []secrets.SnapshotEntry{
					{Path: "/api/key", Value: []byte("handoff-secret-marker"), Origin: secrets.OriginWorkload, HolderName: "api"},
					{Path: "/operator/key", Value: []byte("operator-secret"), Origin: secrets.OriginOperator},
				},
			},
		}, true
	}
}

func TestAttestedHandoffTransfersCAKeyToAllowedReplica(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	bm := NewBundleManager(time.Hour, "", "default/mesh/ca-bundle", slog.Default())
	bm.SetInitial(ca.Cert)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Bundle:              bm,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, clusterIdentity := handoffTestServer(t, hh)

	clientDeps := HandoffClientDeps{
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		ClusterIdentity:     clusterIdentity,
	}
	material, err := RequestHandoff(context.Background(), clientDeps, srv.URL, requesterEAR, requesterHandoffKey, srv.Client())
	if err != nil {
		t.Fatalf("requestHandoff failed: %v", err)
	}

	if got, want := certutil.CertFingerprint(material.CACert.Raw), certutil.CertFingerprint(ca.Cert.Raw); got != want {
		t.Fatalf("handoff CA fingerprint = %s, want %s", got, want)
	}
	if err := ValidateCAKeyPair(material.CACert, material.CAKey); err != nil {
		t.Fatalf("handoff keypair invalid: %v", err)
	}
	if !material.CAKey.PublicKey.Equal(&ca.Key.PublicKey) {
		t.Fatalf("handoff CA key does not match active key")
	}
	if len(material.Bundle) != 1 {
		t.Fatalf("handoff bundle count = %d, want 1", len(material.Bundle))
	}
	if material.AllowlistVersion != "17" || material.Allowlist[handoffTestDigest()] != "registry.example/dynamic:latest" {
		t.Fatalf("handoff allowlist snapshot = version %q, digests %#v", material.AllowlistVersion, material.Allowlist)
	}
	if w, ok := material.Workloads["web"]; !ok || len(w.Containers) != 1 || w.Containers[0].Digest != handoffTestDigest() {
		t.Fatalf("handoff workloads snapshot = %#v", material.Workloads)
	}
	if material.TEEWebPKI == nil || material.TEEWebPKI.Version != 7 ||
		!bytes.Equal(material.TEEWebPKI.TLSKeySeed, bytes.Repeat([]byte{0x31}, teewebpki.SeedSize)) ||
		string(material.TEEWebPKI.ACMEState) != `{"account":"active","order":"pending"}` {
		t.Fatalf("handoff tee-webpki state = %#v", material.TEEWebPKI)
	}
	if material.Secrets == nil || len(material.Secrets.Entries) != 2 ||
		string(material.Secrets.Entries[0].Value) != "handoff-secret-marker" ||
		material.Secrets.Entries[0].HolderName != "api" {
		t.Fatal("handoff did not preserve application-secret values and holder ownership")
	}
}

func TestHandoffCiphertextDoesNotExposeSecretValues(t *testing.T) {
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	hh := &HandoffHandler{signer: handoffTestKey(t)}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	response, err := hh.wrap(HandoffRequest{
		EAR: "requester-ear", PublicKey: encodeB64(recipient.PublicKey().Bytes()),
	}, mustSnapshot(t, snapshotFromCA(ca)), "issuer-ear")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"handoff-secret-marker", "operator-secret"} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatalf("encrypted handoff response exposed an application-secret value")
		}
	}
}

func mustSnapshot(t *testing.T, snapshot func() (CASnapshot, bool)) CASnapshot {
	t.Helper()
	got, ok := snapshot()
	if !ok {
		t.Fatal("snapshot unavailable")
	}
	return got
}

func TestHandoffRetryIsIdempotentAndActivationIsOneWay(t *testing.T) {
	tokenKey := handoffTestKey(t)
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	activeKey := handoffTestKey(t)
	requesterKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterKey)
	hh, err := NewHandoffHandler(HandoffDeps{
		KeyProvider:         testKeyProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		EndpointDrainDelay:  80 * time.Millisecond,
		Signer:              activeKey, EARSource: staticHandoffEARSource{ear: activeEAR},
		Snapshot: snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, identity := handoffTestServer(t, hh)
	deps := HandoffClientDeps{
		KeyProvider:         testKeyProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		ClusterIdentity:     identity,
	}
	prepared, err := prepareHandoffRequest(deps, srv.URL, requesterEAR, requesterKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	first, err := prepared.execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepared.execute(context.Background())
	if err != nil {
		t.Fatalf("identical retry failed: %v", err)
	}
	if first.TransferID == "" || first.TransferID != second.TransferID {
		t.Fatal("identical retry changed the transfer identity")
	}
	if first.Secrets == nil || second.Secrets == nil ||
		!bytes.Equal(first.Secrets.Entries[0].Value, second.Secrets.Entries[0].Value) {
		t.Fatal("identical retry did not return the same encrypted application-secret snapshot")
	}

	// The same selected mesh identity can restart its transfer with a new
	// X25519 key. The new transfer fences the old request.
	other, err := prepareHandoffRequest(deps, srv.URL, requesterEAR, requesterKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	current, err := other.execute(context.Background())
	if err != nil {
		t.Fatalf("selected successor could not resume transfer: %v", err)
	}
	if current.TransferID == first.TransferID {
		t.Fatal("resumed transfer did not fence the old request")
	}
	if err := first.Activate(context.Background()); err == nil {
		t.Fatal("fenced transfer activated")
	}

	// A different mesh leaf cannot replace the selected successor.
	otherServer, otherIdentity := handoffTestServer(t, hh)
	otherDeps := deps
	otherDeps.ClusterIdentity = otherIdentity
	otherSuccessor, err := prepareHandoffRequest(otherDeps, otherServer.URL, requesterEAR, requesterKey, otherServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherSuccessor.execute(context.Background()); err == nil {
		t.Fatal("a different successor received state")
	} else {
		var statusErr *HandoffStatusError
		if !errors.As(err, &statusErr) || statusErr.Status != http.StatusConflict {
			t.Fatalf("second request error = %v, want HTTP 409", err)
		}
	}
	if hh.Active() || !hh.Serving() {
		t.Fatal("predecessor must be frozen but still serve before activation")
	}
	mutation := hh.GuardMutation(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	mutation.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/allowlist", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("frozen mutation = %d, want 503", recorder.Code)
	}
	activateCtx, cancelActivate := context.WithCancel(context.Background())
	firstAttempt := make(chan error, 1)
	go func() { firstAttempt <- current.Activate(activateCtx) }()
	deadline := time.Now().Add(time.Second)
	for hh.ReadyForTraffic() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if hh.ReadyForTraffic() {
		t.Fatal("predecessor stayed Ready after activation started")
	}
	if hh.Active() || !hh.Serving() {
		t.Fatal("draining predecessor must stay frozen and readable")
	}
	recorder = httptest.NewRecorder()
	mutation.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/allowlist", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining mutation = %d, want 503", recorder.Code)
	}
	// Disconnect the first activation client. The endpoint drain must continue on the
	// CDS-owned timer. A same-successor retry during drain waits for it.
	cancelActivate()
	select {
	case err := <-firstAttempt:
		if err == nil {
			t.Fatal("canceled activation request returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled activation request did not return")
	}
	activated := make(chan error, 1)
	go func() { activated <- current.Activate(context.Background()) }()
	select {
	case err := <-activated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("activation did not finish after endpoint drain delay")
	}
	if hh.Active() || !hh.Serving() {
		t.Fatal("predecessor must stay frozen and readable before confirmation")
	}
	if err := current.Activate(context.Background()); err != nil {
		t.Fatalf("identical activation retry failed: %v", err)
	}
	if err := current.Confirm(context.Background()); err != nil {
		t.Fatalf("confirm takeover: %v", err)
	}
	if hh.Active() || hh.Serving() {
		t.Fatal("predecessor stayed serving after confirmed takeover")
	}
}

func TestActivationClientRetriesTransientAndLostSuccessResponses(t *testing.T) {
	identity := handoffTestClusterIdentity(t)
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		switch attempts {
		case 1:
			http.Error(w, "predecessor is still draining", http.StatusServiceUnavailable)
		case 2:
			// A 2xx response with no body models a lost activation result. The
			// predecessor can already be retired, so the client must retry.
			w.WriteHeader(http.StatusOK)
		default:
			_ = json.NewEncoder(w).Encode(HandoffActivateResponse{Activated: true})
		}
	}))
	defer srv.Close()

	prepared := &preparedHandoffRequest{
		deps:    HandoffClientDeps{ClusterIdentity: identity},
		peerURL: srv.URL, transferID: "transfer", client: srv.Client(),
		pinnedClient: srv.Client(), peerAddress: srv.Listener.Addr().String(),
		activationRetryInterval: time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := prepared.activate(ctx); err != nil {
		t.Fatalf("activation retry failed: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("activation attempts = %d, want 3", attempts)
	}
}

func TestConfirmationClientRetriesTransientAndLostSuccessResponses(t *testing.T) {
	identity := handoffTestClusterIdentity(t)
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		switch attempts {
		case 1:
			http.Error(w, "predecessor is still draining", http.StatusServiceUnavailable)
		case 2:
			w.WriteHeader(http.StatusOK)
		default:
			_ = json.NewEncoder(w).Encode(HandoffConfirmResponse{Confirmed: true})
		}
	}))
	defer srv.Close()
	prepared := &preparedHandoffRequest{
		deps: HandoffClientDeps{ClusterIdentity: identity}, peerURL: srv.URL,
		transferID: "transfer", client: srv.Client(), pinnedClient: srv.Client(),
		peerAddress: srv.Listener.Addr().String(), activationRetryInterval: time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := prepared.confirm(ctx); err != nil {
		t.Fatalf("confirmation retry failed: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("confirmation attempts = %d, want 3", attempts)
	}
}

func TestHandoffPinnedPathSurvivesServiceEndpointWithdrawal(t *testing.T) {
	tokenKey := handoffTestKey(t)
	activeKey := handoffTestKey(t)
	requesterKey := handoffTestKey(t)
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	hh, err := NewHandoffHandler(HandoffDeps{
		KeyProvider:         testKeyProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash, EndpointDrainDelay: time.Millisecond,
		Signer: activeKey, EARSource: staticHandoffEARSource{ear: handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeKey)},
		Snapshot: snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	predecessor, identity := handoffTestServer(t, hh)
	var serviceUp atomic.Bool
	serviceUp.Store(true)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "handoff.service.invalid:") {
			if !serviceUp.Load() {
				return nil, fmt.Errorf("Service has no ready endpoint")
			}
			address = predecessor.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, address)
	}
	client := &http.Client{Transport: transport}
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterKey)
	prepared, err := prepareHandoffRequest(HandoffClientDeps{
		KeyProvider: testKeyProvider{pub: &tokenKey.PublicKey}, AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash: handoffTestOperatorKeysHash, ClusterIdentity: identity,
	}, "http://handoff.service.invalid", requesterEAR, requesterKey, client)
	if err != nil {
		t.Fatal(err)
	}
	material, err := prepared.execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	serviceUp.Store(false)
	if err := material.Activate(context.Background()); err != nil {
		t.Fatalf("pinned activation after endpoint withdrawal: %v", err)
	}
	if err := material.Confirm(context.Background()); err != nil {
		t.Fatalf("pinned confirmation after endpoint withdrawal: %v", err)
	}
}

func TestPreActivationLeaseSafelyThawsPredecessor(t *testing.T) {
	tokenKey := handoffTestKey(t)
	activeKey := handoffTestKey(t)
	requesterKey := handoffTestKey(t)
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	var resumed atomic.Bool
	hh, err := NewHandoffHandler(HandoffDeps{
		KeyProvider: testKeyProvider{pub: &tokenKey.PublicKey}, AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash: handoffTestOperatorKeysHash, EndpointDrainDelay: time.Millisecond, TransferLease: 20 * time.Millisecond,
		Signer: activeKey, EARSource: staticHandoffEARSource{ear: handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeKey)},
		Snapshot: snapshotFromCA(ca), Resume: func() { resumed.Store(true) },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, identity := handoffTestServer(t, hh)
	_, err = RequestHandoff(context.Background(), HandoffClientDeps{
		KeyProvider: testKeyProvider{pub: &tokenKey.PublicKey}, AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash: handoffTestOperatorKeysHash, ClusterIdentity: identity,
	}, srv.URL, handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterKey), requesterKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for !hh.Active() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !hh.Active() || !resumed.Load() {
		t.Fatal("pre-activation lease did not restore the predecessor")
	}
}

func TestOperatorAbortRecoversFrozenTransferIdempotently(t *testing.T) {
	tokenKey := handoffTestKey(t)
	activeKey := handoffTestKey(t)
	requesterKey := handoffTestKey(t)
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	var resumed atomic.Bool
	hh, err := NewHandoffHandler(HandoffDeps{
		KeyProvider: testKeyProvider{pub: &tokenKey.PublicKey}, AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash: handoffTestOperatorKeysHash, EndpointDrainDelay: time.Millisecond,
		Signer: activeKey, EARSource: staticHandoffEARSource{ear: handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeKey)},
		Snapshot: snapshotFromCA(ca), Resume: func() { resumed.Store(true) },
		AuthorizeWrite: func(*http.Request, []byte) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, identity := handoffTestServer(t, hh)
	material, err := RequestHandoff(context.Background(), HandoffClientDeps{
		KeyProvider: testKeyProvider{pub: &tokenKey.PublicKey}, AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash: handoffTestOperatorKeysHash, ClusterIdentity: identity,
	}, srv.URL, handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterKey), requesterKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(HandoffAbortRequest{TransferID: material.TransferID})
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := srv.Client().Post(srv.URL+"/handoff/abort", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("abort attempt %d = %d", attempt+1, resp.StatusCode)
		}
	}
	otherBody, _ := json.Marshal(HandoffAbortRequest{TransferID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, sha256.Size))})
	resp, err := srv.Client().Post(srv.URL+"/handoff/abort", "application/json", bytes.NewReader(otherBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("different abort after idempotent abort = %d, want 409", resp.StatusCode)
	}
	if !hh.Active() || !resumed.Load() {
		t.Fatal("operator abort did not restore the predecessor")
	}
}

func TestOperatorAbortPhasePolicy(t *testing.T) {
	tests := []struct {
		name  string
		phase leadershipPhase
		want  int
	}{
		{name: "active", phase: leadershipActive, want: http.StatusConflict},
		{name: "frozen", phase: leadershipFrozen, want: http.StatusOK},
		{name: "draining", phase: leadershipDraining, want: http.StatusOK},
		{name: "takeover ready", phase: leadershipTakeoverReady, want: http.StatusOK},
		{name: "retired", phase: leadershipRetired, want: http.StatusConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenKey := handoffTestKey(t)
			activeKey := handoffTestKey(t)
			requesterKey := handoffTestKey(t)
			ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
			if err != nil {
				t.Fatal(err)
			}
			hh, err := NewHandoffHandler(HandoffDeps{
				KeyProvider: testKeyProvider{pub: &tokenKey.PublicKey}, AllowedMeasurements: map[string]bool{"allowed_measurement": true},
				OperatorKeysHash: handoffTestOperatorKeysHash, EndpointDrainDelay: time.Second,
				Signer: activeKey, EARSource: staticHandoffEARSource{ear: handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeKey)},
				Snapshot: snapshotFromCA(ca), AuthorizeWrite: func(*http.Request, []byte) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			srv, identity := handoffTestServer(t, hh)
			material, err := RequestHandoff(context.Background(), HandoffClientDeps{
				KeyProvider: testKeyProvider{pub: &tokenKey.PublicKey}, AllowedMeasurements: map[string]bool{"allowed_measurement": true},
				OperatorKeysHash: handoffTestOperatorKeysHash, ClusterIdentity: identity,
			}, srv.URL, handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterKey), requesterKey, srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			hh.leader.mu.Lock()
			hh.leader.phase = tc.phase
			if tc.phase == leadershipDraining {
				hh.leader.drainDone = make(chan struct{})
			}
			hh.leader.mu.Unlock()

			body, _ := json.Marshal(HandoffAbortRequest{TransferID: material.TransferID})
			resp, err := srv.Client().Post(srv.URL+"/handoff/abort", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("abort in %s phase = %d, want %d", tc.name, resp.StatusCode, tc.want)
			}
			if tc.want == http.StatusOK && !hh.Active() {
				t.Fatal("successful abort did not restore active leadership")
			}
			if tc.phase == leadershipRetired && hh.Serving() {
				t.Fatal("abort reactivated a retired predecessor")
			}
		})
	}
}

func TestOperatorAbortAfterConfirmedTakeoverIsRejected(t *testing.T) {
	tokenKey := handoffTestKey(t)
	activeKey := handoffTestKey(t)
	requesterKey := handoffTestKey(t)
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	hh, err := NewHandoffHandler(HandoffDeps{
		KeyProvider: testKeyProvider{pub: &tokenKey.PublicKey}, AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash: handoffTestOperatorKeysHash, EndpointDrainDelay: time.Millisecond,
		Signer: activeKey, EARSource: staticHandoffEARSource{ear: handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeKey)},
		Snapshot: snapshotFromCA(ca), AuthorizeWrite: func(*http.Request, []byte) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, identity := handoffTestServer(t, hh)
	material, err := RequestHandoff(context.Background(), HandoffClientDeps{
		KeyProvider: testKeyProvider{pub: &tokenKey.PublicKey}, AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash: handoffTestOperatorKeysHash, ClusterIdentity: identity,
	}, srv.URL, handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterKey), requesterKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := material.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := material.Confirm(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(HandoffAbortRequest{TransferID: material.TransferID})
	resp, err := srv.Client().Post(srv.URL+"/handoff/abort", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("abort after confirmed takeover = %d, want 409", resp.StatusCode)
	}
	if hh.Active() || hh.Serving() {
		t.Fatal("abort after confirmation reactivated the predecessor")
	}
}

func TestCheckHandoffEARAgeRejectsFutureToken(t *testing.T) {
	now := time.Now()
	err := checkHandoffEARAge(&EARClaims{IssuedAt: now.Add(JWTClockSkew + time.Minute).Unix()}, time.Minute, now)
	if err == nil {
		t.Fatal("future handoff EAR was accepted")
	}
}

func TestHandoffBundleStartsWithHandedOffActiveCA(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	rotated, err := NewCAWithParent("Rotated Mesh CA", time.Hour, elliptic.P384(), ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the small rotation window where /ca has published the next
	// bundle before the active signer pointer is swapped.
	bm := NewBundleManager(time.Hour, "", "default/mesh/ca-bundle", slog.Default())
	bm.SetWithCurrent(rotated.Cert, []*x509.Certificate{ca.Cert})

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Bundle:              bm,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, clusterIdentity := handoffTestServer(t, hh)

	clientDeps := HandoffClientDeps{
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		ClusterIdentity:     clusterIdentity,
	}
	material, err := RequestHandoff(context.Background(), clientDeps, srv.URL, requesterEAR, requesterHandoffKey, srv.Client())
	if err != nil {
		t.Fatalf("requestHandoff failed: %v", err)
	}
	if len(material.Bundle) != 2 {
		t.Fatalf("handoff bundle count = %d, want active + published next CA", len(material.Bundle))
	}
	if !material.CACert.Equal(ca.Cert) || !material.Bundle[0].Equal(ca.Cert) {
		t.Fatalf("handoff bundle first CA must match handed-off active signer")
	}
	if !material.Bundle[1].Equal(rotated.Cert) {
		t.Fatalf("handoff bundle should retain the published next CA after active signer")
	}
}

func TestHandoffRejectsRequesterKeyNotBoundToEAR(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	attackerKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, clusterIdentity := handoffTestServer(t, hh)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	sig, err := signHandoffMessage(attackerKey, mustHandoffRequestMessage(t, requesterEAR, pub))
	if err != nil {
		t.Fatal(err)
	}
	req := HandoffRequest{
		EAR:              requesterEAR,
		PublicKey:        pub,
		Signature:        sig,
		ClusterSignature: handoffTestClusterSignature(t, clusterIdentity, requesterEAR, pub),
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Post(srv.URL+"/handoff", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("handoff status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestHandoffRejectsUnallowedRequesterMeasurement(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEAR(t, tokenKey, "allowed_measurement")
	requesterHandoffKey := handoffTestKey(t)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "other_measurement", requesterHandoffKey)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, clusterIdentity := handoffTestServer(t, hh)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	sig, err := signHandoffMessage(requesterHandoffKey, mustHandoffRequestMessage(t, requesterEAR, pub))
	if err != nil {
		t.Fatal(err)
	}
	req := HandoffRequest{
		EAR:              requesterEAR,
		PublicKey:        pub,
		Signature:        sig,
		ClusterSignature: handoffTestClusterSignature(t, clusterIdentity, requesterEAR, pub),
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Post(srv.URL+"/handoff", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("handoff status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestRequestHandoffRequiresMeasurementAllowlist(t *testing.T) {
	_, err := RequestHandoff(context.Background(), HandoffClientDeps{}, "http://127.0.0.1", "ear", handoffTestKey(t), http.DefaultClient)
	if err == nil {
		t.Fatal("expected missing measurement allowlist error")
	}
}

func TestRequestHandoffReturnsTypedStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	deps := HandoffClientDeps{
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		ClusterIdentity:     handoffTestClusterIdentity(t),
	}
	_, err := RequestHandoff(context.Background(), deps, srv.URL, "ear", handoffTestKey(t), srv.Client())
	var statusErr *HandoffStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("RequestHandoff error = %v, want *HandoffStatusError", err)
	}
	if statusErr.Status != http.StatusNotFound {
		t.Fatalf("HandoffStatusError.Status = %d, want %d", statusErr.Status, http.StatusNotFound)
	}
}

func TestUnwrapHandoffResponseRejectsBadNonceLength(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	issuerKey := handoffTestKey(t)
	requesterKey := handoffTestKey(t)
	issuerEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", issuerKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterKey)

	requesterECDH, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requesterPub := encodeB64(requesterECDH.PublicKey().Bytes())
	peerECDH, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerPub := encodeB64(peerECDH.PublicKey().Bytes())
	sig, err := signHandoffMessage(issuerKey, mustHandoffResponseMessage(t, requesterEAR, issuerEAR, requesterPub, peerPub))
	if err != nil {
		t.Fatal(err)
	}

	clientDeps := HandoffClientDeps{
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
	}
	_, err = UnwrapHandoffResponse(HandoffResponse{
		IssuerEAR:  issuerEAR,
		PublicKey:  peerPub,
		Signature:  sig,
		Nonce:      encodeB64([]byte{1, 2, 3}),
		Ciphertext: encodeB64([]byte("ciphertext")),
	}, clientDeps, requesterEAR, requesterPub, requesterECDH)
	if err == nil || !strings.Contains(err.Error(), "handoff nonce length") {
		t.Fatalf("error = %v, want nonce length validation", err)
	}
}

func TestHandoffTranscriptsAreDomainSeparated(t *testing.T) {
	transcripts := map[string][]byte{
		handoffRequestSignaturePurpose:  mustHandoffRequestMessage(t, "requester-ear", "requester-pub"),
		handoffResponseSignaturePurpose: mustHandoffResponseMessage(t, "requester-ear", "issuer-ear", "requester-pub", "issuer-pub"),
		handoffPayloadKeyPurpose:        mustHandoffTranscript(t, handoffPayloadKeyPurpose, "requester-ear", "issuer-ear"),
		handoffPayloadAADPurpose:        mustHandoffAAD(t, "requester-ear", "issuer-ear", "requester-pub", "issuer-pub"),
	}

	seen := map[string]string{}
	for purpose, transcript := range transcripts {
		components := decodeHandoffTranscript(t, transcript)
		if components[0] != handoffProtocolLabel {
			t.Fatalf("%s transcript protocol label = %q, want %q", purpose, components[0], handoffProtocolLabel)
		}
		if components[1] != purpose {
			t.Fatalf("%s transcript purpose label = %q, want %q", purpose, components[1], purpose)
		}
		key := string(transcript)
		if previous, ok := seen[key]; ok {
			t.Fatalf("%s transcript duplicates %s: %x", purpose, previous, transcript)
		}
		seen[key] = purpose
	}
}

func TestHandoffTranscriptLengthPrefixesAmbiguousFields(t *testing.T) {
	left := mustHandoffTranscript(t, "purpose", "a", "b\nc")
	right := mustHandoffTranscript(t, "purpose", "a\nb", "c")
	if bytes.Equal(left, right) {
		t.Fatalf("length-prefixed transcripts collided: %x", left)
	}

	if got := decodeHandoffTranscript(t, left); !slices.Equal(got, []string{handoffProtocolLabel, "purpose", "a", "b\nc"}) {
		t.Fatalf("left transcript components = %#v", got)
	}
}

func TestHandoffUsesLatestIssuerEARBeforeTransfer(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR1 := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	activeEAR2 := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	earSource := &AtomicHandoffEAR{}
	if err := earSource.Set(activeEAR1); err != nil {
		t.Fatalf("Set: %v", err)
	}

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           earSource,
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, clusterIdentity := handoffTestServer(t, hh)
	if err := earSource.Set(activeEAR2); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := handoffResponseIssuerEAR(t, srv, clusterIdentity, requesterEAR, requesterHandoffKey); got != activeEAR2 {
		t.Fatalf("issuer EAR after refresh = %q, want %q", got, activeEAR2)
	}
}

func handoffResponseIssuerEAR(t *testing.T, srv *httptest.Server, clusterIdentity *tls.Certificate, requesterEAR string, signer *ecdsa.PrivateKey) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	sig, err := signHandoffMessage(signer, mustHandoffRequestMessage(t, requesterEAR, pub))
	if err != nil {
		t.Fatal(err)
	}
	req := HandoffRequest{
		EAR:              requesterEAR,
		PublicKey:        pub,
		Signature:        sig,
		ClusterSignature: handoffTestClusterSignature(t, clusterIdentity, requesterEAR, pub),
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Post(srv.URL+"/handoff", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("handoff status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var hr HandoffResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		t.Fatal(err)
	}
	return hr.IssuerEAR
}

func decodeHandoffTranscript(t *testing.T, transcript []byte) []string {
	t.Helper()
	input := cryptobyte.String(transcript)
	var components []string
	for !input.Empty() {
		var n uint32
		if !input.ReadUint32(&n) {
			t.Fatalf("truncated transcript length prefix: %x", []byte(input))
		}
		var component []byte
		if !input.ReadBytes(&component, int(n)) {
			t.Fatalf("transcript component length %d exceeds remaining %d", n, len(input))
		}
		components = append(components, string(component))
	}
	if len(components) < 2 {
		t.Fatalf("transcript has %d components, want at least 2", len(components))
	}
	return components
}

func mustHandoffRequestMessage(t *testing.T, ear, requesterPub string) []byte {
	t.Helper()
	message, err := handoffRequestMessage(ear, requesterPub)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func mustHandoffResponseMessage(t *testing.T, requesterEAR, issuerEAR, requesterPub, issuerPub string) []byte {
	t.Helper()
	message, err := handoffResponseMessage(requesterEAR, issuerEAR, requesterPub, issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func mustHandoffAAD(t *testing.T, requesterEAR, issuerEAR, requesterPub, issuerPub string) []byte {
	t.Helper()
	aad, err := handoffAAD(requesterEAR, issuerEAR, requesterPub, issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	return aad
}

func mustHandoffTranscript(t *testing.T, purpose string, fields ...string) []byte {
	t.Helper()
	transcript, err := handoffTranscript(purpose, fields...)
	if err != nil {
		t.Fatal(err)
	}
	return transcript
}

func handoffTestEAR(t *testing.T, tokenKey *ecdsa.PrivateKey, measurement string) string {
	t.Helper()
	return handoffTestEARWithKey(t, tokenKey, measurement, nil)
}

func handoffTestEARWithKey(t *testing.T, tokenKey *ecdsa.PrivateKey, measurement string, teeKey *ecdsa.PrivateKey) string {
	t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{
		earclaims.IssuedAt:         now,
		earclaims.ExpiresAt:        now + 3600,
		earclaims.OperatorKeysHash: handoffTestOperatorKeysHash,
		earclaims.Submods: map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.LaunchDigest: measurement,
			},
		},
	}
	if teeKey != nil {
		claims[earclaims.TEEPublicKey] = teePubKeyB64(t, teeKey)
	}
	return signJWT(t, tokenKey, claims)
}

func TestUnverifiedEARExpiryReadsExpClaim(t *testing.T) {
	tokenKey := handoffTestKey(t)
	teeKey := handoffTestKey(t)
	token := handoffTestEARWithKey(t, tokenKey, "m", teeKey)

	got, err := unverifiedEARExpiry(token)
	if err != nil {
		t.Fatalf("handoffEARExpiry: %v", err)
	}
	delta := time.Until(got).Seconds()
	if delta < 3500 || delta > 3700 {
		t.Errorf("expiry delta = %.0fs, want ~3600s", delta)
	}
}

func TestUnverifiedEARExpiryRejectsMalformed(t *testing.T) {
	for name, token := range map[string]string{
		"two-parts":   "header.claims",
		"bad-base64":  "header.!!!.sig",
		"missing-exp": signJWT(t, handoffTestKey(t), map[string]any{earclaims.IssuedAt: time.Now().Unix()}),
		"bad-claims":  "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig",
	} {
		if _, err := unverifiedEARExpiry(token); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestHandoffEARExpiryUpdaterMarksInvalidSourceNegative(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handoffEARExpirySeconds.Set(3600)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	RunHandoffEARExpiryUpdater(ctx, staticHandoffEARSource{ear: "bad.token"}, time.Hour, logger)

	if got := testutil.ToFloat64(handoffEARExpirySeconds); got >= 0 {
		t.Fatalf("handoff EAR expiry gauge = %v, want negative on invalid source", got)
	}
}

func TestNewHandoffHandlerValidatesInputs(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	bm := NewBundleManager(time.Hour, "", "ca-bundle", slog.Default())
	bm.SetInitial(ca.Cert)

	signer := handoffTestKey(t)
	src := staticHandoffEARSource{ear: "ear-token"}

	baseDeps := func(allowed map[string]bool) HandoffDeps {
		return HandoffDeps{
			Logger:              slog.Default(),
			KeyProvider:         kp,
			AllowedMeasurements: allowed,
			OperatorKeysHash:    handoffTestOperatorKeysHash,
			Bundle:              bm,
			Signer:              signer,
			EARSource:           src,
			Snapshot:            snapshotFromCA(ca),
		}
	}

	nilSigner := baseDeps(map[string]bool{"m": true})
	nilSigner.Signer = nil
	if _, err := NewHandoffHandler(nilSigner); err == nil {
		t.Error("expected error when signer key is nil")
	}
	nilSource := baseDeps(map[string]bool{"m": true})
	nilSource.EARSource = nil
	if _, err := NewHandoffHandler(nilSource); err == nil {
		t.Error("expected error when EAR source is nil")
	}

	if _, err := NewHandoffHandler(baseDeps(nil)); err == nil {
		t.Error("expected error when handoff measurement allowlist is empty")
	}
	missingPolicy := baseDeps(map[string]bool{"m": true})
	missingPolicy.OperatorKeysHash = ""
	if _, err := NewHandoffHandler(missingPolicy); err == nil {
		t.Error("expected error when operator-key policy hash is empty")
	}
	negativeDrain := baseDeps(map[string]bool{"m": true})
	negativeDrain.EndpointDrainDelay = -time.Second
	if _, err := NewHandoffHandler(negativeDrain); err == nil {
		t.Error("expected error when endpoint drain delay is negative")
	}

	// An EAR source that hasn't bootstrapped yet is accepted at construction
	// time — the handler returns 503 at request time. This decouples
	// CDS startup from handoff EAR readiness.
	notReady := baseDeps(map[string]bool{"m": true})
	notReady.EARSource = erroringHandoffEARSource{}
	hh, err := NewHandoffHandler(notReady)
	if err != nil {
		t.Fatalf("newHandoffHandler must accept a not-yet-ready EAR source: %v", err)
	}
	if hh.signer == nil || hh.earSource == nil {
		t.Fatal("handoffHandler missing signer or EAR source")
	}

	hh, err = NewHandoffHandler(baseDeps(map[string]bool{"m": true}))
	if err != nil {
		t.Fatalf("newHandoffHandler: %v", err)
	}
	if hh.signer == nil || hh.earSource == nil {
		t.Fatal("handoffHandler missing signer or EAR source")
	}
}

func TestCheckOperatorPolicyRejectsMissingAndMismatch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims *EARClaims
	}{
		{name: "missing claim", claims: &EARClaims{}},
		{name: "malformed claim", claims: &EARClaims{OperatorKeysHash: "bad"}},
		{name: "different policy", claims: &EARClaims{OperatorKeysHash: strings.Repeat("b", 64)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOperatorPolicy(tc.claims, handoffTestOperatorKeysHash, "requester")
			var validationErr *TokenValidationError
			if !errors.As(err, &validationErr) || validationErr.Reason != ReasonOperatorPolicy {
				t.Fatalf("error = %v, want operator-policy TokenValidationError", err)
			}
		})
	}
	if err := checkOperatorPolicy(&EARClaims{OperatorKeysHash: handoffTestOperatorKeysHash}, handoffTestOperatorKeysHash, "requester"); err != nil {
		t.Fatalf("matching operator policy rejected: %v", err)
	}
}

func TestValidateAllowlistSnapshot(t *testing.T) {
	for _, version := range []string{"", "0", "-1", "not-a-version"} {
		if err := validateAllowlistSnapshot(version, map[types.Digest]string{}); err == nil {
			t.Fatalf("validateAllowlistSnapshot accepted version %q", version)
		}
	}
	if err := validateAllowlistSnapshot("1", nil); err == nil {
		t.Fatal("validateAllowlistSnapshot accepted nil digests")
	}
	if err := validateAllowlistSnapshot("1", map[types.Digest]string{}); err != nil {
		t.Fatalf("validateAllowlistSnapshot rejected an empty snapshot: %v", err)
	}
}

func (h *captureHandler) anyAtLevel(level slog.Level) (capturedRecord, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.level >= level {
			return r, true
		}
	}
	return capturedRecord{}, false
}

func TestNewHandoffHandlerDefaultsNilLogger(t *testing.T) {
	tokenKey := handoffTestKey(t)
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	hh, err := NewHandoffHandler(HandoffDeps{
		KeyProvider:         testKeyProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: map[string]bool{"m": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              handoffTestKey(t),
		EARSource:           staticHandoffEARSource{ear: "ear"},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatalf("newHandoffHandler: %v", err)
	}
	if hh.deps.Logger == nil {
		t.Fatal("nil Logger must be defaulted, not stored")
	}
}

func TestHandoffSuccessLogsNoErrors(t *testing.T) {
	tokenKey := handoffTestKey(t)
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	capture := &captureHandler{}
	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.New(capture),
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatalf("newHandoffHandler: %v", err)
	}
	srv, clusterIdentity := handoffTestServer(t, hh)

	clientDeps := HandoffClientDeps{
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		ClusterIdentity:     clusterIdentity,
	}
	if _, err := RequestHandoff(context.Background(), clientDeps, srv.URL, requesterEAR, requesterHandoffKey, srv.Client()); err != nil {
		t.Fatalf("requestHandoff: %v", err)
	}
	if r, ok := capture.anyAtLevel(slog.LevelWarn); ok {
		t.Fatalf("successful handoff logged %q at level %v", r.msg, r.level)
	}
}

func TestRequestHandoffNilClientUsesDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	deps := HandoffClientDeps{
		KeyProvider:         testKeyProvider{},
		AllowedMeasurements: map[string]bool{"m": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		ClusterIdentity:     handoffTestClusterIdentity(t),
	}
	_, err := RequestHandoff(context.Background(), deps, srv.URL, "requester-ear", handoffTestKey(t), nil)
	var statusErr *HandoffStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != http.StatusTeapot {
		t.Fatalf("RequestHandoff error = %v, want 418 *HandoffStatusError", err)
	}
}

func TestRequestHandoffTreats3xxAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMultipleChoices)
	}))
	t.Cleanup(srv.Close)

	deps := HandoffClientDeps{
		KeyProvider:         testKeyProvider{},
		AllowedMeasurements: map[string]bool{"m": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		ClusterIdentity:     handoffTestClusterIdentity(t),
	}
	_, err := RequestHandoff(context.Background(), deps, srv.URL, "requester-ear", handoffTestKey(t), srv.Client())
	var statusErr *HandoffStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != http.StatusMultipleChoices {
		t.Fatalf("RequestHandoff error = %v, want 300 *HandoffStatusError", err)
	}
}

func TestHandoffEARExpiryUpdaterSetsPositiveExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ear := handoffTestEAR(t, handoffTestKey(t), "m")
	handoffEARExpirySeconds.Set(-1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	RunHandoffEARExpiryUpdater(ctx, staticHandoffEARSource{ear: ear}, time.Hour, logger)

	got := testutil.ToFloat64(handoffEARExpirySeconds)
	if got < 3500 || got > 3700 {
		t.Fatalf("handoff EAR expiry gauge = %v, want ~3600", got)
	}
}

func TestParseHandoffPayloadParentCertificate(t *testing.T) {
	ca, err := NewCAWithCurve("payload-ca", time.Hour, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	parent, err := NewCAWithCurve("payload-parent", time.Hour, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(certutil.EncodeCertPEM(ca.Cert.Raw))

	base := handoffPayload{
		CAKey:            string(keyPEM),
		CACertificate:    certPEM,
		CABundle:         certPEM,
		AllowlistVersion: "1",
		Allowlist:        map[types.Digest]string{},
	}

	valid := base
	valid.ParentCertificate = string(certutil.EncodeCertPEM(parent.Cert.Raw))
	plain, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ParseHandoffPayload(plain)
	if err != nil {
		t.Fatalf("ParseHandoffPayload with valid parent: %v", err)
	}
	if material.ParentCert == nil || !material.ParentCert.Equal(parent.Cert) {
		t.Fatal("parsed parent certificate does not match payload")
	}

	garbage := base
	garbage.ParentCertificate = "not a certificate"
	plain, err = json.Marshal(garbage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHandoffPayload(plain); err == nil || !strings.Contains(err.Error(), "parse handoff parent certificate") {
		t.Fatalf("ParseHandoffPayload with garbage parent: err = %v, want parse failure", err)
	}

	malformedSecrets := base
	malformedSecrets.Secrets = &secrets.Snapshot{
		Version: secrets.SnapshotVersion, MaxPaths: 2, MaxPerHolder: 1, MaxValue: 8,
		Entries: []secrets.SnapshotEntry{{Path: "/key", Value: []byte("secret-value-marker"), Origin: "unknown"}},
	}
	plain, err = json.Marshal(malformedSecrets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHandoffPayload(plain); err == nil || !strings.Contains(err.Error(), "secret handoff state") || strings.Contains(err.Error(), "secret-value-marker") {
		t.Fatalf("malformed secret snapshot error = %v", err)
	}
}

func TestValidateEARTokenAcceptsES384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	claims := jwt.MapClaims(validTestEARClaims(map[string]any{
		earclaims.IssuedAt:  now,
		earclaims.ExpiresAt: now + 3600,
	}))
	token, err := jwt.NewWithClaims(jwt.SigningMethodES384, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, ""); err != nil {
		t.Fatalf("ES384 EAR rejected: %v", err)
	}
}

func TestValidateEARTokenAllowsClockSkewedExpiry(t *testing.T) {
	tokenKey := handoffTestKey(t)
	now := time.Now().Unix()
	// Expired 10s ago: inside the 30s leeway, so it must still validate.
	token := signJWT(t, tokenKey, map[string]any{
		earclaims.IssuedAt:  now - 600,
		earclaims.ExpiresAt: now - 10,
	})
	if _, err := ValidateEARToken(token, testKeyProvider{pub: &tokenKey.PublicKey}, ""); err != nil {
		t.Fatalf("token expired within leeway rejected: %v", err)
	}
}

type erroringHandoffEARSource struct{}

func (erroringHandoffEARSource) Current() (string, error) {
	return "", fmt.Errorf("ear source unavailable")
}

func (erroringHandoffEARSource) ExpiresAt() (time.Time, error) {
	return time.Time{}, fmt.Errorf("ear source unavailable")
}

// TestHandoffReturns503BeforeBootstrap proves that a handoff handler whose
// EAR source has not bootstrapped yet returns 503 (rather than crashing,
// returning 401, or blocking the request).
func TestHandoffReturns503BeforeBootstrap(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	bm := NewBundleManager(time.Hour, "", "ca-bundle", slog.Default())
	bm.SetInitial(ca.Cert)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"m": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Bundle:              bm,
		Signer:              handoffTestKey(t),
		EARSource:           erroringHandoffEARSource{},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatalf("newHandoffHandler: %v", err)
	}
	srv, _ := handoffTestServer(t, hh)

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestHandoffReturns503ForEmptyCASnapshot(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot: func() (CASnapshot, bool) {
			return CASnapshot{}, true
		},
	})
	if err != nil {
		t.Fatalf("newHandoffHandler: %v", err)
	}
	srv, clusterIdentity := handoffTestServer(t, hh)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	sig, err := signHandoffMessage(requesterHandoffKey, mustHandoffRequestMessage(t, requesterEAR, pub))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(HandoffRequest{
		EAR:              requesterEAR,
		PublicKey:        pub,
		Signature:        sig,
		ClusterSignature: handoffTestClusterSignature(t, clusterIdentity, requesterEAR, pub),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if !hh.Active() || !hh.Serving() {
		t.Fatal("failed snapshot left the predecessor frozen")
	}
}

func TestHandoffInvalidRecipientKeyDoesNotFreezePredecessor(t *testing.T) {
	tokenKey := handoffTestKey(t)
	activeKey := handoffTestKey(t)
	requesterKey := handoffTestKey(t)
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterKey)
	hh, err := NewHandoffHandler(HandoffDeps{
		KeyProvider:         testKeyProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, clusterIdentity := handoffTestServer(t, hh)

	// The request proofs are valid. Only the X25519 recipient key has an
	// invalid size. The failure happens after the predecessor takes a stable
	// snapshot, so it must roll leadership back to active.
	publicKey := encodeB64([]byte{1, 2, 3})
	requestSignature, err := signHandoffMessage(requesterKey, mustHandoffRequestMessage(t, requesterEAR, publicKey))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(HandoffRequest{
		EAR:              requesterEAR,
		PublicKey:        publicKey,
		Signature:        requestSignature,
		ClusterSignature: handoffTestClusterSignature(t, clusterIdentity, requesterEAR, publicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	if !hh.Active() || !hh.Serving() {
		t.Fatal("invalid recipient key left the predecessor frozen")
	}
}

func TestMaximumBoundedHandoffPayloadRoundTrip(t *testing.T) {
	ca, err := NewCAWithCurve("large handoff", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	secretSnapshot := &secrets.Snapshot{
		Version: secrets.SnapshotVersion, MaxPaths: 2048, MaxPerHolder: 64, MaxValue: 11200,
		Entries: make([]secrets.SnapshotEntry, 1024),
	}
	for i := range secretSnapshot.Entries {
		secretSnapshot.Entries[i] = secrets.SnapshotEntry{
			Path: fmt.Sprintf("/large/%04d", i), Value: bytes.Repeat([]byte{byte(i)}, 11200), Origin: secrets.OriginOperator,
		}
	}
	ledger := &sandboxledger.Snapshot{Entries: make([]sandboxledger.SnapshotEntry, sandboxledger.MaxSnapshotEntries)}
	for i := range ledger.Entries {
		ledger.Entries[i] = sandboxledger.SnapshotEntry{
			SandboxID: fmt.Sprintf("%0128d", i), InventoryHost: strings.Repeat("h", 255), Expires: time.Now().Add(time.Hour),
		}
	}
	digests := make(map[types.Digest]string, 8000)
	for i := 0; i < 8000; i++ {
		digest, err := types.ParseDigest(fmt.Sprintf("sha256:%064x", i+1))
		if err != nil {
			t.Fatal(err)
		}
		digests[digest] = "registry.example/system@" + digest.String()
	}
	payload := handoffPayload{
		CAKey: string(keyPEM), CACertificate: string(certutil.EncodeCertPEM(ca.Cert.Raw)),
		CABundle: string(certutil.EncodeCertPEM(ca.Cert.Raw)), AllowlistVersion: "1",
		Allowlist: digests, Secrets: secretSnapshot, SandboxLedger: ledger,
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) <= 20<<20 || len(plain) > maxHandoffPlaintextBytes {
		t.Fatalf("large payload size = %d, bounds (%d, %d]", len(plain), 20<<20, maxHandoffPlaintextBytes)
	}
	material, err := ParseHandoffPayload(plain)
	if err != nil {
		t.Fatalf("round-trip maximum bounded handoff: %v", err)
	}
	if len(material.Secrets.Entries) != 1024 || len(material.SandboxLedger.Entries) != sandboxledger.MaxSnapshotEntries {
		t.Fatal("large handoff lost bounded state")
	}
}

func handoffTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// signJWT creates an ES256 JWT signed by the given key, adding mandatory EAR
// shape fields unless the caller provided them.
func signJWT(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	claims = validTestEARClaims(claims)
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload

	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}

	// Encode as r||s (each 32 bytes for P-256).
	keySize := 32
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func teePubKeyB64(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// validTestEARClaims fills in the mandatory EAR shape fields (profile,
// verifier id, submods) so signed test tokens pass ValidateEARToken.
func validTestEARClaims(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims)+3)
	for k, v := range claims {
		out[k] = v
	}
	if _, ok := out[earclaims.EATProfile]; !ok {
		out[earclaims.EATProfile] = earclaims.EARProfileTag
	}
	if _, ok := out[earclaims.EARVerifierID]; !ok {
		out[earclaims.EARVerifierID] = map[string]any{
			earclaims.Developer: "test",
			earclaims.Build:     "test",
		}
	}
	if !hasNonEmptyObjectClaim(out[earclaims.Submods]) {
		out[earclaims.Submods] = map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.EARStatus: 2,
			},
		}
	}
	return out
}

func hasNonEmptyObjectClaim(v any) bool {
	switch typed := v.(type) {
	case map[string]any:
		return len(typed) > 0
	case map[string]string:
		return len(typed) > 0
	case map[string]json.RawMessage:
		return len(typed) > 0
	default:
		return false
	}
}

func TestValidateCAKeyPair(t *testing.T) {
	ca, err := NewCA("handoff ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	other, err := NewCA("other ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA other: %v", err)
	}

	if err := ValidateCAKeyPair(ca.Cert, ca.Key); err != nil {
		t.Fatalf("valid CA keypair: unexpected error %v", err)
	}
	if err := ValidateCAKeyPair(nil, ca.Key); err == nil {
		t.Error("nil cert: expected error")
	}
	if err := ValidateCAKeyPair(ca.Cert, nil); err == nil {
		t.Error("nil key: expected error")
	}
	if err := ValidateCAKeyPair(ca.Cert, other.Key); err == nil {
		t.Error("mismatched key: expected error")
	}

	expired := *ca.Cert
	expired.NotBefore = time.Now().Add(-2 * time.Hour)
	expired.NotAfter = time.Now().Add(-time.Hour)
	if err := ValidateCAKeyPair(&expired, ca.Key); err == nil {
		t.Error("expired cert: expected error")
	}

	notCA := *ca.Cert
	notCA.IsCA = false
	if err := ValidateCAKeyPair(&notCA, ca.Key); err == nil {
		t.Error("non-CA cert: expected error")
	}

	noCertSign := *ca.Cert
	noCertSign.KeyUsage = x509.KeyUsageDigitalSignature
	if err := ValidateCAKeyPair(&noCertSign, ca.Key); err == nil {
		t.Error("cert without cert-sign usage: expected error")
	}
}
