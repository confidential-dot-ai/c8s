package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	digestApp    = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestFloor  = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	appArgv0     = "/app/serve"
	grantedPath  = "/secret/model/key"
	deniedPath   = "/secret/other/key"
	writablePath = "/secret/session"
)

// brokerFor builds a broker over an allowlist granting digestApp read on
// /secret/model/** and write on /secret/session, only when it runs /app/serve.
func brokerFor(t *testing.T, seed map[string][]byte) *Broker {
	t.Helper()
	doc, err := allowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","digests":{"` + digestFloor + `":"get-cert"},
		"workloads":{"app":{"containers":[{"digest":"` + digestApp + `",
		 "command":{"policy":"exact","argv":["` + appArgv0 + `"]},"args":{"policy":"any"},
		 "paths":{"policy":"allow","read":["/secret/model/**"],"write":["` + writablePath + `"]}}]}}}`))
	if err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	idx := doc.BuildIndex()
	return &Broker{
		Provider: NewMemProvider(seed),
		Index:    func() (*allowlist.Index, error) { return idx, nil },
	}
}

// subj builds the Subject the admission component would supply. In production
// neither field is caller-supplied; here the test plays that component.
func subj(t *testing.T, digest string, argv ...string) Subject {
	t.Helper()
	d, err := types.ParseDigest(digest)
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	return Subject{Digest: d, Argv: argv}
}

func TestBrokerFetchHonorsReadGrant(t *testing.T) {
	b := brokerFor(t, map[string][]byte{grantedPath: []byte("weights"), deniedPath: []byte("other")})
	argv := []string{appArgv0, "--port=8080"}

	got, err := b.Fetch(context.Background(), subj(t, digestApp, argv...), []Ref{{Path: grantedPath}})
	if err != nil {
		t.Fatalf("fetch granted path: %v", err)
	}
	if len(got) != 1 || string(got[0].Data) != "weights" || got[0].Version != "1" {
		t.Fatalf("got %+v, want one v1 secret with the seeded data", got)
	}

	if _, err := b.Fetch(context.Background(), subj(t, digestApp, argv...), []Ref{{Path: deniedPath}}); !errors.Is(err, ErrDenied) {
		t.Fatalf("ungranted path: err = %v, want ErrDenied", err)
	}
}

// One denial fails the whole call, so a partial answer can never be mistaken
// for the caller's complete entitled set.
func TestBrokerFetchIsAllOrNothing(t *testing.T) {
	b := brokerFor(t, map[string][]byte{grantedPath: []byte("weights"), deniedPath: []byte("other")})
	refs := []Ref{{Path: grantedPath}, {Path: deniedPath}}
	if _, err := b.Fetch(context.Background(), subj(t, digestApp, appArgv0), refs); !errors.Is(err, ErrDenied) {
		t.Fatalf("mixed request: err = %v, want ErrDenied", err)
	}
}

// The grant is pinned to the argv the entry allows, so the same bytes run any
// other way hold nothing.
func TestBrokerFetchDeniesUnmatchedArgv(t *testing.T) {
	b := brokerFor(t, map[string][]byte{grantedPath: []byte("weights")})
	argv := []string{"/bin/sh", "-c", "cat " + grantedPath}
	if _, err := b.Fetch(context.Background(), subj(t, digestApp, argv...), []Ref{{Path: grantedPath}}); !errors.Is(err, ErrDenied) {
		t.Fatalf("unmatched argv: err = %v, want ErrDenied", err)
	}
}

func TestBrokerFetchDeniesFloorDigest(t *testing.T) {
	b := brokerFor(t, map[string][]byte{grantedPath: []byte("weights")})
	if _, err := b.Fetch(context.Background(), subj(t, digestFloor), []Ref{{Path: grantedPath}}); !errors.Is(err, ErrDenied) {
		t.Fatalf("floor digest: err = %v, want ErrDenied", err)
	}
}

func TestBrokerFetchRequiresPaths(t *testing.T) {
	b := brokerFor(t, nil)
	if _, err := b.Fetch(context.Background(), subj(t, digestApp, appArgv0), nil); err == nil {
		t.Fatal("an empty fetch must be rejected, not enumerate the grant")
	}
}

func TestBrokerPutHonorsWriteGrant(t *testing.T) {
	b := brokerFor(t, nil)
	argv := []string{appArgv0}

	s, err := b.Put(context.Background(), subj(t, digestApp, argv...), writablePath, []byte("v1"))
	if err != nil {
		t.Fatalf("put granted path: %v", err)
	}
	if s.Version != "1" {
		t.Fatalf("version = %q, want 1", s.Version)
	}
	if s, err = b.Put(context.Background(), subj(t, digestApp, argv...), writablePath, []byte("v2")); err != nil || s.Version != "2" {
		t.Fatalf("second put: %+v, %v — want version 2", s, err)
	}

	// A read grant must not imply write.
	if _, err := b.Put(context.Background(), subj(t, digestApp, argv...), grantedPath, []byte("x")); !errors.Is(err, ErrDenied) {
		t.Fatalf("write to a read-only path: err = %v, want ErrDenied", err)
	}
}

// An init container writes a secret the main container then reads. The two are
// separate grants on separate digests in a real workload; here the point is
// that a fresh Put is what a later Fetch sees.
func TestBrokerWriteThenRead(t *testing.T) {
	doc, err := allowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"app":{
		"initContainers":[{"digest":"` + digestApp + `","command":{"policy":"exact","argv":["/init"]},
		 "args":{"policy":"any"},"paths":{"policy":"allow","write":["` + writablePath + `"]}}],
		"containers":[{"digest":"` + digestFloor + `","command":{"policy":"exact","argv":["/main"]},
		 "args":{"policy":"any"},"paths":{"policy":"allow","read":["` + writablePath + `"]}}]}}}`))
	if err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	idx := doc.BuildIndex()
	b := &Broker{Provider: NewMemProvider(nil), Index: func() (*allowlist.Index, error) { return idx, nil }}

	if _, err := b.Put(context.Background(), subj(t, digestApp, "/init"), writablePath, []byte("session")); err != nil {
		t.Fatalf("init write: %v", err)
	}
	got, err := b.Fetch(context.Background(), subj(t, digestFloor, "/main"), []Ref{{Path: writablePath}})
	if err != nil {
		t.Fatalf("main read: %v", err)
	}
	if string(got[0].Data) != "session" {
		t.Fatalf("data = %q, want the value the init container wrote", got[0].Data)
	}
	// The reader holds no write grant on the same path.
	if _, err := b.Put(context.Background(), subj(t, digestFloor, "/main"), writablePath, []byte("x")); !errors.Is(err, ErrDenied) {
		t.Fatalf("reader write: err = %v, want ErrDenied", err)
	}
}

func TestBrokerGrants(t *testing.T) {
	b := brokerFor(t, nil)
	g, err := b.Grants(subj(t, digestApp, appArgv0))
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	if g.Policy != allowlist.PolicyAllow || len(g.Read) != 1 || len(g.Write) != 1 {
		t.Fatalf("grants = %+v, want one read and one write glob", g)
	}
	if g, _ = b.Grants(subj(t, digestApp, "/bin/sh")); g.Policy != allowlist.PolicyDeny {
		t.Fatalf("unmatched argv grants = %+v, want deny", g)
	}
}

func TestBrokerIndexError(t *testing.T) {
	b := &Broker{
		Provider: NewMemProvider(nil),
		Index:    func() (*allowlist.Index, error) { return nil, errors.New("store down") },
	}
	if _, err := b.Fetch(context.Background(), subj(t, digestApp), []Ref{{Path: grantedPath}}); err == nil {
		t.Fatal("an unavailable allowlist must fail closed")
	}
	if _, err := b.Put(context.Background(), subj(t, digestApp), writablePath, nil); err == nil {
		t.Fatal("an unavailable allowlist must fail closed")
	}
}

// wrongPathProvider answers a granted request with a different path — a bug or a
// hostile adapter. Only the requested paths were authorized, so the call must
// fail rather than hand back material nothing granted.
type wrongPathProvider struct{ Provider }

func (wrongPathProvider) GetMany(context.Context, []Ref) ([]Secret, error) {
	return []Secret{{Path: deniedPath, Version: "1", Data: []byte("other")}}, nil
}

func TestBrokerFetchRejectsProviderPathMismatch(t *testing.T) {
	b := brokerFor(t, map[string][]byte{grantedPath: []byte("weights")})
	b.Provider = wrongPathProvider{b.Provider}
	if _, err := b.Fetch(context.Background(), subj(t, digestApp, appArgv0), []Ref{{Path: grantedPath}}); err == nil {
		t.Fatal("a provider answering with an unrequested path must fail the call")
	}
}
