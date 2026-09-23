package allowlist_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// recordingPublisher captures what the handler published, and can refuse up
// front the way the coordinator does while an update is rolling out.
type recordingPublisher struct {
	documents    [][]byte
	authorizedBy []string
	blocked      error
	err          error
}

func (p *recordingPublisher) CanPublish() error { return p.blocked }

func (p *recordingPublisher) Publish(canonical []byte, authorizedBy string) error {
	if p.err != nil {
		return p.err
	}
	p.documents = append(p.documents, canonical)
	p.authorizedBy = append(p.authorizedBy, authorizedBy)
	return nil
}

// fixedActive is an active policy that never changes, which is what makes "the
// store moved, the served document did not" observable.
type fixedActive struct {
	body    []byte
	version uint64
}

func (a fixedActive) ActiveBytes() ([]byte, uint64, error) { return a.body, a.version, nil }

func newPublishingHandler(t *testing.T, pub *recordingPublisher, active allowlist.ActivePolicy) (http.Handler, *allowlist.Store) {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("OpenInMemory() = _, %v, want no error", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h := allowlist.Handler{
		Store:           &store,
		WriteAuthorizer: func(*http.Request, []byte) error { return nil },
		Publications: &allowlist.Publications{
			Publisher:    pub,
			Active:       active,
			AuthorizedBy: "operator-keys:abc",
		},
	}
	r := chi.NewRouter()
	r.Get("/allowlist", h.HandleList)
	r.Put("/allowlist/workloads/{name}", h.HandlePutWorkload)
	r.Delete("/allowlist/workloads/{name}", h.HandleDeleteWorkload)
	return r, &store
}

const publishEntry = `{"initContainers":[],"containers":[{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"}}]}`

func putEntry(t *testing.T, r http.Handler, name string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/allowlist/workloads/"+name, strings.NewReader(publishEntry)))
	return w
}

func TestMutationsPublishTheWholeDocument(t *testing.T) {
	pub := &recordingPublisher{}
	active := fixedActive{body: []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`), version: 7}
	r, _ := newPublishingHandler(t, pub, active)

	if w := putEntry(t, r, "api"); w.Code != http.StatusNoContent {
		t.Fatalf("PUT workload = %d, want 204 (body %q)", w.Code, w.Body.String())
	}
	if len(pub.documents) != 1 {
		t.Fatalf("published %d documents, want 1", len(pub.documents))
	}
	if !strings.Contains(string(pub.documents[0]), digestA) {
		t.Errorf("published document = %s, want the written entry", pub.documents[0])
	}
	if pub.authorizedBy[0] != "operator-keys:abc" {
		t.Errorf("authorized_by = %q, want %q", pub.authorizedBy[0], "operator-keys:abc")
	}

	// The read still answers from the active document, not the store.
	got := httptest.NewRecorder()
	r.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/allowlist", nil))
	if got.Body.String() != string(active.body) {
		t.Errorf("GET /allowlist = %s, want the active %s", got.Body.String(), active.body)
	}
	if want := `W/"7"`; got.Header().Get("ETag") != want {
		t.Errorf("ETag = %q, want %q", got.Header().Get("ETag"), want)
	}
}

func TestMutationRefusedWhileAnUpdateIsOutstanding(t *testing.T) {
	pub := &recordingPublisher{blocked: errors.New("version 4 is still rolling out")}
	r, store := newPublishingHandler(t, pub, fixedActive{body: []byte("{}"), version: 1})

	w := putEntry(t, r, "api")
	if w.Code != http.StatusConflict {
		t.Fatalf("PUT workload during a rollout = %d, want 409 (body %q)", w.Code, w.Body.String())
	}
	if len(pub.documents) != 0 {
		t.Errorf("published %d documents, want none", len(pub.documents))
	}
	// The refusal happens before the mutation, so the operator's retry later
	// applies to the document they were looking at.
	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() = _, _, %v, want no error", err)
	}
	if len(doc.Workloads) != 0 {
		t.Errorf("store workloads = %v, want the store untouched", doc.Workloads)
	}
}

func TestMutationReportsAFailedPublication(t *testing.T) {
	pub := &recordingPublisher{err: errors.New("journal is full")}
	r, store := newPublishingHandler(t, pub, fixedActive{body: []byte("{}"), version: 1})

	if w := putEntry(t, r, "api"); w.Code != http.StatusInternalServerError {
		t.Fatalf("PUT workload with a failing publisher = %d, want 500", w.Code)
	}
	// The mutation still committed: the next successful write republishes the
	// whole document, so the two converge without operator action.
	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() = _, _, %v, want no error", err)
	}
	if _, ok := doc.Workloads["api"]; !ok {
		t.Errorf("store workloads = %v, want the committed entry", doc.Workloads)
	}
}

func TestDeleteOfAnAbsentWorkloadPublishesNothing(t *testing.T) {
	pub := &recordingPublisher{}
	r, _ := newPublishingHandler(t, pub, fixedActive{body: []byte("{}"), version: 1})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/allowlist/workloads/absent", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("DELETE absent workload = %d, want 404", w.Code)
	}
	if len(pub.documents) != 0 {
		t.Errorf("published %d documents, want none: nothing changed", len(pub.documents))
	}
}
