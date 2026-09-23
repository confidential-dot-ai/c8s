package nriimagepolicy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// fakeCDS serves the six /.well-known/c8s routes an enforcer uses — the
// objects, the publication head, the signed state and the three participant
// posts — from an in-memory journal and object store, as CONTRACT2 pins them.
// Tests drive it through publish, switch and complete and read back what the
// node posted.
type fakeCDS struct {
	t *testing.T

	mu           sync.Mutex
	signingKey   ed25519.PrivateKey
	authority    string
	deploymentID string

	objects    map[string][]byte
	head       *policystate.Entry
	headDigest string

	version   uint64
	activeDoc *allowlist.Allowlist
	active    policyRef
	update    *policystate.Update
	targetDoc *allowlist.Allowlist

	// forgedAuthority makes the statement name an authority the signing key is
	// not, the shape a CDS claiming someone else's identity presents.
	forgedAuthority string

	enrollments []policystate.Enrollment
	acks        []policystate.Ack
	completions []policystate.Completion

	// enrollStatus answers every enrollment with this status instead of
	// recording it, which is how a test drives the 409 CDS returns while an
	// update is outstanding.
	enrollStatus int
}

func newFakeCDS(t *testing.T) *fakeCDS {
	t.Helper()
	f := &fakeCDS{t: t, deploymentID: "deployment-under-test", objects: map[string][]byte{}}
	f.rekey()
	return f
}

// rekey installs a fresh authority key, the shape a CDS restart presents: the
// key is generated in memory and never persisted, so a restart is a new
// authority.
func (f *fakeCDS) rekey() {
	f.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatalf("GenerateKey: %v", err)
	}
	fingerprint, err := policystate.AuthorityFingerprint(pub)
	if err != nil {
		f.t.Fatalf("AuthorityFingerprint: %v", err)
	}
	f.signingKey, f.authority = priv, fingerprint
}

// policyRef is a published policy: the version it was published at and the
// digest that names its bytes.
type policyRef struct {
	version uint64
	digest  string
}

func (f *fakeCDS) serve() *httptest.Server {
	srv := httptest.NewServer(f)
	f.t.Cleanup(srv.Close)
	return srv
}

// seed publishes the first policy and makes it active without an update, the
// state a node joins a running deployment in.
func (f *fakeCDS) seed(al *allowlist.Allowlist) string {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()

	digest := f.storeLocked(al)
	f.version++
	f.appendLocked(policystate.EventPublished, policystate.PublishedPayload{
		Version:      f.version,
		TargetDigest: digest,
		AuthorizedBy: policystate.AuthorizedBySeed,
	})
	f.activeDoc = al
	f.active = policyRef{version: f.version, digest: digest}
	return digest
}

// publish opens the one outstanding update to al. It authorizes nothing: the
// node still admits under the active policy until the coordinator switches.
func (f *fakeCDS) publish(al *allowlist.Allowlist) string {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()

	digest := f.storeLocked(al)
	f.version++
	requiresDrain := len(allowlist.Removed(f.activeDoc, al)) > 0
	f.appendLocked(policystate.EventPublished, policystate.PublishedPayload{
		Version:       f.version,
		SourceDigest:  f.active.digest,
		TargetDigest:  digest,
		RequiresDrain: requiresDrain,
		AuthorizedBy:  "operator",
	})
	f.targetDoc = al
	f.update = &policystate.Update{
		Version:       f.version,
		SourceDigest:  f.active.digest,
		TargetDigest:  digest,
		RequiresDrain: requiresDrain,
	}
	return digest
}

// switchUpdate is the coordinator authorizing the target for admission, which
// it does once every frozen participant has acknowledged.
func (f *fakeCDS) switchUpdate() {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.update == nil {
		f.t.Fatal("switch without an outstanding update")
	}
	f.update.Switched = true
	f.activeDoc = f.targetDoc
	f.active = policyRef{version: f.update.Version, digest: f.update.TargetDigest}
}

// completeUpdate closes the update, appending the drain event when the update
// removed permissions. It is what clears the node's pending set.
func (f *fakeCDS) completeUpdate() {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.update.RequiresDrain {
		f.appendLocked(policystate.EventDrained, policystate.DrainedPayload{Version: f.update.Version})
	}
	f.update = nil
	f.targetDoc = nil
}

// storeLocked stores a policy object under its content digest. Callers hold
// f.mu.
func (f *fakeCDS) storeLocked(al *allowlist.Allowlist) string {
	f.t.Helper()
	canonical, err := al.Canonical()
	if err != nil {
		f.t.Fatalf("Canonical: %v", err)
	}
	digest := policystate.ContentDigest(canonical)
	f.objects[digest] = canonical
	return digest
}

// appendLocked adds one journal entry and stores it as an object. Callers hold
// f.mu.
func (f *fakeCDS) appendLocked(typ policystate.EventType, payload any) {
	f.t.Helper()
	entry, err := policystate.NewEntryAt(f.head, f.headDigest, f.authority, typ, payload, time.Now().UTC())
	if err != nil {
		f.t.Fatalf("NewEntryAt(%s): %v", typ, err)
	}
	canonical, err := policystate.Canonical(entry)
	if err != nil {
		f.t.Fatalf("Canonical(entry): %v", err)
	}
	digest := policystate.ContentDigest(canonical)
	f.objects[digest] = canonical
	f.head, f.headDigest = &entry, digest
}

// signedState mints the statement CDS serves. It runs on the server goroutine,
// so a construction error is reported on the response, never through t.Fatal.
func (f *fakeCDS) signedState() (policystate.SignedState, error) {
	st := policystate.State{
		Protocol:      policystate.Protocol,
		DeploymentID:  f.deploymentID,
		Authority:     f.authority,
		LogHead:       f.headDigest,
		LogPosition:   f.head.Position,
		ActiveVersion: f.active.version,
		ActiveDigest:  f.active.digest,
		Update:        f.update,
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	if f.forgedAuthority == "" {
		return policystate.SignState(f.signingKey, st)
	}
	// SignState refuses to name an authority its key is not, so a statement
	// that does is built by hand.
	st.Authority = f.forgedAuthority
	return f.forgeState(st)
}

func (f *fakeCDS) forgeState(st policystate.State) (policystate.SignedState, error) {
	pub, ok := f.signingKey.Public().(ed25519.PublicKey)
	if !ok {
		return policystate.SignedState{}, errors.New("signing key is not ed25519")
	}
	encoded, err := policystate.EncodeAuthorityKey(pub)
	if err != nil {
		return policystate.SignedState{}, err
	}
	canonical, err := policystate.Canonical(st)
	if err != nil {
		return policystate.SignedState{}, err
	}
	sig, err := policystate.Sign(f.signingKey, policystate.DomainState, canonical)
	if err != nil {
		return policystate.SignedState{}, err
	}
	return policystate.SignedState{Statement: st, PublicKey: encoded, Signature: sig}, nil
}

func (f *fakeCDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.URL.Path == policystate.PathState:
		signed, err := f.signedState()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, signed)
	case r.URL.Path == policystate.PathLatest:
		writeJSON(w, policystate.Head{
			Authority:    f.authority,
			Version:      f.version,
			PolicyDigest: f.active.digest,
			LogHead:      f.headDigest,
		})
	case strings.HasPrefix(r.URL.Path, policystate.PathObjectPrefix):
		body, ok := f.objects["sha256:"+strings.TrimPrefix(r.URL.Path, policystate.PathObjectPrefix)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	case r.URL.Path == policystate.PathEnroll:
		if f.enrollStatus != 0 {
			http.Error(w, "an update is outstanding", f.enrollStatus)
			return
		}
		if msg, ok := receive[policystate.Enrollment](f, w, r); ok {
			f.enrollments = append(f.enrollments, msg)
		}
	case r.URL.Path == policystate.PathAck:
		if msg, ok := receive[policystate.Ack](f, w, r); ok {
			f.acks = append(f.acks, msg)
		}
	case r.URL.Path == policystate.PathComplete:
		if msg, ok := receive[policystate.Completion](f, w, r); ok {
			f.completions = append(f.completions, msg)
		}
	default:
		http.NotFound(w, r)
	}
}

// receive decodes a participant envelope and checks its signature against the
// boot key of the enrollment it claims, so a test cannot pass by posting
// unsigned messages. It reports on the response rather than through t: this
// runs on the server goroutine.
func receive[T any](f *fakeCDS, w http.ResponseWriter, r *http.Request) (T, bool) {
	var env policystate.Envelope[T]
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return env.Message, false
	}
	if err := policystate.Decode(body, &env); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return env.Message, false
	}
	key, err := f.bootKey(env.Message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return env.Message, false
	}
	if err := policystate.VerifyMessage(key, policystate.DomainAck, env); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return env.Message, false
	}
	w.WriteHeader(http.StatusOK)
	return env.Message, true
}

// bootKey is the key an enrolled participant signs with. An enrollment carries
// its own key; every later message is checked against the recorded one.
func (f *fakeCDS) bootKey(msg any) (ed25519.PublicKey, error) {
	if e, ok := msg.(policystate.Enrollment); ok {
		return policystate.DecodeBootKey(e.BootKey)
	}
	if len(f.enrollments) == 0 {
		return nil, errors.New("a participant message arrived before any enrollment")
	}
	return policystate.DecodeBootKey(f.enrollments[len(f.enrollments)-1].BootKey)
}

// recorded returns what participants posted, copied under the lock so a test
// can read it while the loop is still running.
func (f *fakeCDS) recorded() ([]policystate.Enrollment, []policystate.Ack, []policystate.Completion) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.enrollments), slices.Clone(f.acks), slices.Clone(f.completions)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
