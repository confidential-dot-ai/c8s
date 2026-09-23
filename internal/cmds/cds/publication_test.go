package cds

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/coordinator"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// publishingCDS is a router wired to a real store and coordinator, which is
// what the publication endpoints are only meaningful against.
type publishingCDS struct {
	router http.Handler
	store  *allowlist.Store
	coord  *coordinator.Coordinator
	active activePolicy
}

const testDigestA = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"

// publishedEntry is one operator-authored allowlist entry, the body of a
// PUT /allowlist/workloads/{name}. Dropping a mount destination narrows the
// rule, which is what makes an update require a drain.
func publishedEntry(mounts ...string) string {
	return `{"initContainers":[],"containers":[{"digest":"` + testDigestA + `",` +
		`"command":{"policy":"any"},"args":{"policy":"any"},` +
		`"mounts":{"policy":"exact","destinations":["` + strings.Join(mounts, `","`) + `"]}}]}`
}

// wideEntry and narrowEntry differ only in the mount set: publishing
// narrowEntry over wideEntry retires the wide rule.
func wideEntry() string   { return publishedEntry("/a", "/b") }
func narrowEntry() string { return publishedEntry("/a") }

func newPublishingCDS(t *testing.T) *publishingCDS {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("allowlist.OpenInMemory() = _, %v, want no error", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	coord, err := coordinator.OpenInMemory(coordinator.Options{DeploymentID: "test-deployment"})
	if err != nil {
		t.Fatalf("coordinator.OpenInMemory() = _, %v, want no error", err)
	}
	t.Cleanup(func() { _ = coord.Close() })
	if err := bootstrapPolicy(&store, coord, 0); err != nil {
		t.Fatalf("bootstrapPolicy() = %v, want no error", err)
	}

	active := activePolicy{coordinator: coord}
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("issuer.NewCA() = _, %v, want no error", err)
	}
	challenges := attestation.NewChallengeStore(time.Minute)
	deps := dependencies{
		AttestHandler: AttestHandler{Challenges: &challenges, CA: ca, CertTTL: time.Hour},
		AllowlistHandler: allowlist.Handler{
			Store:           &store,
			WriteAuthorizer: func(*http.Request, []byte) error { return nil },
			Publications: &allowlist.Publications{
				Publisher:    policyPublisher{coordinator: coord},
				Active:       active,
				AuthorizedBy: "operator-keys:test",
			},
		},
		Publication:      &publicationHandler{Coordinator: coord, MaxWriteBodyBytes: allowlistWriteBodyCap},
		ReadyFn:          func() bool { return true },
		CACertPEM:        certutil.EncodeCertPEM(ca.Cert.Raw),
		RateLimiter:      newTestRateLimiter(t),
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	}
	return &publishingCDS{router: newRouter(deps), store: &store, coord: coord, active: active}
}

func (c *publishingCDS) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	switch b := body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case string:
		reader = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("json.Marshal(%T) = _, %v, want no error", body, err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	c.router.ServeHTTP(w, req)
	return w
}

// putWorkload writes one entry and asserts the status the write answered with.
func (c *publishingCDS) putWorkload(t *testing.T, entry string, want int) {
	t.Helper()
	if w := c.do(t, http.MethodPut, "/allowlist/workloads/api", entry); w.Code != want {
		t.Fatalf("PUT /allowlist/workloads/api = %d, want %d (body %q)", w.Code, want, w.Body.String())
	}
}

// decodeJSON parses a response body with the same strict decoder a client
// would use.
func decodeJSON[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
	if err := policystate.Decode(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("Decode(%s) = %v, want no error", w.Body.String(), err)
	}
	return out
}

// testParticipant is one enrolled boot driving an update through the HTTP API.
type testParticipant struct {
	id  string
	key ed25519.PrivateKey
}

func (c *publishingCDS) enroll(t *testing.T, name string) testParticipant {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() = _, _, %v, want no error", err)
	}
	p := testParticipant{id: policystate.BootID(pub), key: priv}
	body := signed(t, priv, policystate.Enrollment{
		Protocol:      policystate.Protocol,
		BootID:        p.id,
		Name:          name,
		BootKey:       policystate.EncodeBootKey(pub),
		AppliedDigest: c.state(t).Statement.ActiveDigest,
	})
	if w := c.do(t, http.MethodPost, policystate.PathEnroll, body); w.Code != http.StatusNoContent {
		t.Fatalf("POST enroll = %d, want 204 (body %q)", w.Code, w.Body.String())
	}
	return p
}

func (c *publishingCDS) state(t *testing.T) policystate.SignedState {
	t.Helper()
	s := decodeJSON[policystate.SignedState](t, c.do(t, http.MethodGet, policystate.PathState, nil))
	if err := policystate.VerifySignedState(s); err != nil {
		t.Fatalf("VerifySignedState() = %v, want no error", err)
	}
	return s
}

func signed[T any](t *testing.T, priv ed25519.PrivateKey, msg T) policystate.Envelope[T] {
	t.Helper()
	env, err := policystate.SignMessage(priv, policystate.DomainAck, msg)
	if err != nil {
		t.Fatalf("SignMessage() = _, %v, want no error", err)
	}
	return env
}

func TestAllowlistServesTheActivePolicyUntilTheUpdateSwitches(t *testing.T) {
	c := newPublishingCDS(t)

	// The bootstrap publication is active at once, so /allowlist answers from
	// the start with the seeded (empty) document.
	first := c.do(t, http.MethodGet, "/allowlist", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("GET /allowlist = %d, want 200", first.Code)
	}
	if got, want := first.Header().Get("ETag"), `W/"1"`; got != want {
		t.Errorf("GET /allowlist ETag = %q, want %q", got, want)
	}
	activeP := first.Body.String()

	node := c.enroll(t, "node-a")
	c.putWorkload(t, wideEntry(), http.StatusNoContent)

	head := decodeJSON[policystate.Head](t, c.do(t, http.MethodGet, policystate.PathLatest, nil))
	if head.Version != 2 {
		t.Fatalf("latest.Version after one write = %d, want 2", head.Version)
	}
	if got := c.do(t, http.MethodGet, "/allowlist", nil).Body.String(); got != activeP {
		t.Errorf("GET /allowlist after publishing v2 = %s, want the active %s", got, activeP)
	}

	// The node's ack is the only thing that switches it.
	ack := signed(t, node.key, policystate.Ack{
		Protocol: policystate.Protocol, BootID: node.id, Version: 2, TargetDigest: head.PolicyDigest,
	})
	if w := c.do(t, http.MethodPost, policystate.PathAck, ack); w.Code != http.StatusNoContent {
		t.Fatalf("POST ack = %d, want 204 (body %q)", w.Code, w.Body.String())
	}

	after := c.do(t, http.MethodGet, "/allowlist", nil)
	if after.Body.String() == activeP {
		t.Fatalf("GET /allowlist after the switch = %s, want the new document", after.Body.String())
	}
	if got, want := after.Header().Get("ETag"), `W/"2"`; got != want {
		t.Errorf("GET /allowlist ETag after the switch = %q, want %q", got, want)
	}
	doc, err := pkgallowlist.ParseJSON(after.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseJSON(GET /allowlist) = _, %v, want no error", err)
	}
	if _, ok := doc.Workloads["api"]; !ok {
		t.Errorf("GET /allowlist workloads = %v, want the written entry", doc.Workloads)
	}
}

func TestSecondWriteDuringAnUpdateIsRefusedAndChangesNothing(t *testing.T) {
	c := newPublishingCDS(t)
	node := c.enroll(t, "node-a")
	c.putWorkload(t, wideEntry(), http.StatusNoContent)

	head := decodeJSON[policystate.Head](t, c.do(t, http.MethodGet, policystate.PathLatest, nil))
	before, _, err := c.store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() = _, _, %v, want no error", err)
	}

	c.putWorkload(t, narrowEntry(), http.StatusConflict)
	if w := c.do(t, http.MethodDelete, "/allowlist/workloads/api", nil); w.Code != http.StatusConflict {
		t.Errorf("DELETE during an update = %d, want 409", w.Code)
	}

	after, _, err := c.store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() = _, _, %v, want no error", err)
	}
	if !bytes.Equal(canonical(t, before), canonical(t, after)) {
		t.Errorf("store = %s, want it untouched at %s", canonical(t, after), canonical(t, before))
	}
	if got := decodeJSON[policystate.Head](t, c.do(t, http.MethodGet, policystate.PathLatest, nil)); got.Version != head.Version {
		t.Errorf("publication head = %d, want %d: the refused writes published nothing", got.Version, head.Version)
	}

	// Enrollment is held outside an update for the same reason.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	joiner := signed(t, priv, policystate.Enrollment{
		Protocol: policystate.Protocol, BootID: policystate.BootID(pub), Name: "node-b",
		BootKey: policystate.EncodeBootKey(pub), AppliedDigest: head.PolicyDigest,
	})
	if w := c.do(t, http.MethodPost, policystate.PathEnroll, joiner); w.Code != http.StatusConflict {
		t.Errorf("POST enroll during an update = %d, want 409 (body %q)", w.Code, w.Body.String())
	}

	// Once the frozen participant finishes, writes are accepted again.
	completeUpdate(t, c, node, 2, head.PolicyDigest)
	c.putWorkload(t, narrowEntry(), http.StatusNoContent)
}

// completeUpdate takes one participant's update from publication to completion.
func completeUpdate(t *testing.T, c *publishingCDS, p testParticipant, version uint64, target string) {
	t.Helper()
	ack := signed(t, p.key, policystate.Ack{
		Protocol: policystate.Protocol, BootID: p.id, Version: version, TargetDigest: target,
	})
	if w := c.do(t, http.MethodPost, policystate.PathAck, ack); w.Code != http.StatusNoContent {
		t.Fatalf("POST ack = %d, want 204 (body %q)", w.Code, w.Body.String())
	}
	done := signed(t, p.key, policystate.Completion{
		Protocol: policystate.Protocol, BootID: p.id, Version: version, TargetDigest: target,
	})
	if w := c.do(t, http.MethodPost, policystate.PathComplete, done); w.Code != http.StatusNoContent {
		t.Fatalf("POST complete = %d, want 204 (body %q)", w.Code, w.Body.String())
	}
}

func canonical(t *testing.T, doc *pkgallowlist.Allowlist) []byte {
	t.Helper()
	raw, err := doc.Canonical()
	if err != nil {
		t.Fatalf("Canonical() = _, %v, want no error", err)
	}
	return raw
}

func TestSecretPolicySeesTheTargetOnlyAfterTheSwitch(t *testing.T) {
	c := newPublishingCDS(t)
	node := c.enroll(t, "node-a")
	// The release path reads the active policy through the same adapter
	// issuance does, so a published-but-unswitched grant must be invisible.
	policy := secrets.NewCachedPolicy(c.active)

	c.putWorkload(t, wideEntry(), http.StatusNoContent)
	doc, err := policy.Allowlist()
	if err != nil {
		t.Fatalf("Allowlist() = _, %v, want no error", err)
	}
	if _, ok := doc.Workloads["api"]; ok {
		t.Fatal("the secrets policy sees the target before the update switched")
	}

	head := decodeJSON[policystate.Head](t, c.do(t, http.MethodGet, policystate.PathLatest, nil))
	completeUpdate(t, c, node, head.Version, head.PolicyDigest)

	doc, err = policy.Allowlist()
	if err != nil {
		t.Fatalf("Allowlist() = _, %v, want no error", err)
	}
	if _, ok := doc.Workloads["api"]; !ok {
		t.Errorf("the secrets policy still serves the source after the switch: %v", doc.Workloads)
	}
}

func TestPublicationReadsAreSelfVerifying(t *testing.T) {
	c := newPublishingCDS(t)
	c.putWorkload(t, wideEntry(), http.StatusNoContent)
	head := decodeJSON[policystate.Head](t, c.do(t, http.MethodGet, policystate.PathLatest, nil))

	// The policy object is fetchable by digest and rehashes to it.
	object := c.do(t, http.MethodGet, policystate.PathObjectPrefix+strings.TrimPrefix(head.PolicyDigest, "sha256:"), nil)
	if object.Code != http.StatusOK {
		t.Fatalf("GET policy object = %d, want 200", object.Code)
	}
	if got := policystate.ContentDigest(object.Body.Bytes()); got != head.PolicyDigest {
		t.Errorf("policy object hashes to %s, want %s", got, head.PolicyDigest)
	}
	if _, err := pkgallowlist.ParseJSON(object.Body.Bytes()); err != nil {
		t.Errorf("ParseJSON(policy object) = _, %v, want no error", err)
	}

	// So is the journal head, from the same path.
	entryBody := c.do(t, http.MethodGet, policystate.PathObjectPrefix+strings.TrimPrefix(head.LogHead, "sha256:"), nil)
	if entryBody.Code != http.StatusOK {
		t.Fatalf("GET entry object = %d, want 200", entryBody.Code)
	}
	var entry policystate.Entry
	if err := policystate.Decode(entryBody.Body.Bytes(), &entry); err != nil {
		t.Fatalf("Decode(entry) = %v, want no error", err)
	}
	if got, err := policystate.EntryDigest(entry); err != nil || got != head.LogHead {
		t.Errorf("entry hashes to %s (%v), want %s", got, err, head.LogHead)
	}
	if entry.Type != policystate.EventPublished {
		t.Errorf("head entry type = %q, want %q", entry.Type, policystate.EventPublished)
	}
}

func TestStateAndChallengeSign(t *testing.T) {
	c := newPublishingCDS(t)
	s := c.state(t)
	if s.Statement.Authority != c.coord.Authority() {
		t.Errorf("state authority = %q, want %q", s.Statement.Authority, c.coord.Authority())
	}

	nonce := bytes.Repeat([]byte{3}, policystate.MinNonceLen)
	body := policystate.ChallengeRequest{Nonce: base64.RawURLEncoding.EncodeToString(nonce)}
	challenged := decodeJSON[policystate.ChallengedState](t, c.do(t, http.MethodPost, policystate.PathChallenge, body))
	if err := policystate.VerifyChallengedState(challenged, nonce); err != nil {
		t.Fatalf("VerifyChallengedState() = %v, want no error", err)
	}
}

func TestPublicationErrorMapping(t *testing.T) {
	c := newPublishingCDS(t)
	node := c.enroll(t, "node-a")

	_, impostor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unknown := "sha256:" + strings.Repeat("0", 64)

	tests := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
	}{
		{name: "unknown object", method: http.MethodGet, path: policystate.PathObjectPrefix + strings.Repeat("0", 64), want: http.StatusNotFound},
		{name: "malformed object digest", method: http.MethodGet, path: policystate.PathObjectPrefix + "nothex", want: http.StatusUnprocessableEntity},
		{name: "nonce too short", method: http.MethodPost, path: policystate.PathChallenge, body: policystate.ChallengeRequest{Nonce: "AAAA"}, want: http.StatusUnprocessableEntity},
		{name: "unknown field in a request body", method: http.MethodPost, path: policystate.PathChallenge, body: `{"nonce":"AAAA","extra":1}`, want: http.StatusUnprocessableEntity},
		{
			name: "ack signed by another key", method: http.MethodPost, path: policystate.PathAck,
			body: signed(t, impostor, policystate.Ack{Protocol: policystate.Protocol, BootID: node.id, Version: 1, TargetDigest: unknown}),
			want: http.StatusUnauthorized,
		},
		{
			name: "ack from an unenrolled boot", method: http.MethodPost, path: policystate.PathAck,
			body: signed(t, node.key, policystate.Ack{Protocol: policystate.Protocol, BootID: unknown, Version: 1, TargetDigest: unknown}),
			want: http.StatusNotFound,
		},
		{
			name: "ack with no update outstanding", method: http.MethodPost, path: policystate.PathAck,
			body: signed(t, node.key, policystate.Ack{Protocol: policystate.Protocol, BootID: node.id, Version: 1, TargetDigest: unknown}),
			want: http.StatusConflict,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := c.do(t, tc.method, tc.path, tc.body)
			if w.Code != tc.want {
				t.Fatalf("%s %s = %d, want %d (body %q)", tc.method, tc.path, w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestBootstrapRefusesAStoreTheJournalNeverPublished(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("allowlist.OpenInMemory() = _, %v, want no error", err)
	}
	defer store.Close()
	entry, err := pkgallowlist.ParseWorkloadJSON([]byte(wideEntry()))
	if err != nil {
		t.Fatalf("ParseWorkloadJSON() = _, %v, want no error", err)
	}
	if err := store.PutWorkload("api", *entry); err != nil {
		t.Fatalf("PutWorkload() = %v, want no error", err)
	}
	coord, err := coordinator.OpenInMemory(coordinator.Options{DeploymentID: "test-deployment"})
	if err != nil {
		t.Fatalf("coordinator.OpenInMemory() = _, %v, want no error", err)
	}
	defer coord.Close()

	err = bootstrapPolicy(&store, coord, 0)
	if err == nil {
		t.Fatal("bootstrapPolicy() imported a store the journal never published")
	}
	if !strings.Contains(err.Error(), "empty allowlist store") {
		t.Errorf("bootstrapPolicy() = %v, want the operator told to start from an empty store", err)
	}
}

// testPublications wires a handler to its own store, for the router tests that
// are about routing rather than about a rollout.
func testPublications(t *testing.T, store *allowlist.Store) *allowlist.Publications {
	t.Helper()
	backed := storeBackedPolicy{store: store}
	return &allowlist.Publications{Publisher: backed, Active: backed, AuthorizedBy: "test"}
}

type storeBackedPolicy struct{ store *allowlist.Store }

func (s storeBackedPolicy) CanPublish() error                { return nil }
func (s storeBackedPolicy) Publish(_ []byte, _ string) error { return nil }

func (s storeBackedPolicy) ActiveBytes() ([]byte, uint64, error) {
	doc, version, err := s.store.LoadAll()
	if err != nil {
		return nil, 0, err
	}
	body, err := doc.Canonical()
	if err != nil {
		return nil, 0, err
	}
	n, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return nil, 0, err
	}
	return body, n, nil
}
