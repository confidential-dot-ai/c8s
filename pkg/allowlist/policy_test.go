package allowlist

import "testing"

func TestIndex_FloorAdmitsAnyArgv(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"cds"}}`).BuildIndex()
	if !idx.AdmitsDigest(digestA) {
		t.Fatal("floor digest not admitted")
	}
	if !idx.AdmitsContainer(digestA, []string{"/anything", "--dynamic"}) {
		t.Fatal("floor digest must be admitted regardless of argv")
	}
}

// A multi-token command is matched as an exact prefix; args:any leaves the rest
// free. This is the case an entrypoint like "/docker-entrypoint.sh nginx" needs.
func TestIndex_MultiTokenCommandPrefix(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/docker-entrypoint.sh","nginx"]},
		 "args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}) {
		t.Fatal("argv starting with the command prefix should be admitted")
	}
	if idx.AdmitsContainer(digestA, []string{"/docker-entrypoint.sh"}) {
		t.Fatal("argv shorter than the command prefix must be rejected")
	}
	if idx.AdmitsContainer(digestA, []string{"/bin/sh", "nginx", "-g"}) {
		t.Fatal("a different prefix must be rejected")
	}
}

func TestIndex_FullExact(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/app"]},
		 "args":{"policy":"exact","argv":["--serve","--port=8080"]}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"/app", "--serve", "--port=8080"}) {
		t.Fatal("exact command+args should match the concatenation")
	}
	if idx.AdmitsContainer(digestA, []string{"/bin/sh", "--serve", "--port=8080"}) {
		t.Fatal("a swapped command must be rejected")
	}
	if idx.AdmitsContainer(digestA, []string{"/app", "--serve"}) {
		t.Fatal("truncated args must be rejected")
	}
}

func TestIndex_ArgsDenyMeansNoArgs(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"/app"}) {
		t.Fatal("args:deny should admit the command with no extra args")
	}
	if idx.AdmitsContainer(digestA, []string{"/app", "--exfil"}) {
		t.Fatal("args:deny must reject any extra args")
	}
}

// A shared digest may run under several command/args policies; admission is the
// union across entries.
func TestIndex_SharedDigestUnion(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"a":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["busybox","sleep"]},"args":{"policy":"exact","argv":["1"]}}]},
		"b":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["busybox","echo"]},"args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(digestA, []string{"busybox", "sleep", "1"}) {
		t.Fatal("first entry's argv should be admitted")
	}
	if !idx.AdmitsContainer(digestA, []string{"busybox", "echo", "hi"}) {
		t.Fatal("second entry's argv should be admitted")
	}
	if idx.AdmitsContainer(digestA, []string{"busybox", "cat", "/etc/shadow"}) {
		t.Fatal("an argv no entry permits must be rejected")
	}
}

func TestIndex_UnknownDigestDenied(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"x"}}`).BuildIndex()
	if idx.AdmitsDigest(digestB) || idx.AdmitsContainer(digestB, nil) {
		t.Fatal("unknown digest must be denied")
	}
}

// The grant a container holds must come from a policy its argv actually
// satisfied. A digest shared with a permissive entry would otherwise let any
// argv borrow a strict entry's paths — admitted via one entry, granted via
// another.
func TestIndex_PathGrantsAreArgvMatched(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"victim":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/app/serve"]},
		 "paths":{"policy":"allow","read":["/secret/model/**"]}}]},
		"debug":{"containers":[{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`).BuildIndex()

	shell := []string{"/bin/sh", "-c", "cat /secret/model/key"}
	if !idx.AdmitsContainer(digestA, shell) {
		t.Fatal("the permissive entry should still admit the argv")
	}
	if idx.AdmitsRead(digestA, shell, "/secret/model/key") {
		t.Fatal("an argv admitted only by the permissive entry must hold no grant")
	}
	if !idx.AdmitsRead(digestA, []string{"/app/serve"}, "/secret/model/key") {
		t.Fatal("the argv the granting entry pins must hold the grant")
	}
}

func TestIndex_FloorDigestHoldsNoGrant(t *testing.T) {
	// A floor digest carrying a grant is rejected at parse time, so build the
	// index from a document where the floor entry is added afterwards — the
	// state a stale or hand-built index could still reach.
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"},
		 "paths":{"policy":"allow","read":["/s/**"]}}]}}}`)
	al.Digests = map[string]string{digestA: "shared-base"}
	idx := al.BuildIndex()

	if idx.AdmitsRead(digestA, []string{"/bin/sh"}, "/s/x") {
		t.Fatal("a floor digest must hold no grant — no argv was ever matched")
	}
}

func TestIndex_PathGrantsUnionMatchingEntries(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"a":{"containers":[{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"},
		 "paths":{"policy":"allow","read":["/s/a"],"write":["/w/a"]}}]},
		"b":{"containers":[{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"},
		 "paths":{"policy":"allow","read":["/s/a","/s/b"]}}]}}}`).BuildIndex()

	g := idx.PathGrants(digestA, []string{"/app"})
	if g.Policy != PolicyAllow {
		t.Fatalf("policy = %q, want allow", g.Policy)
	}
	if len(g.Read) != 2 || g.Read[0] != "/s/a" || g.Read[1] != "/s/b" {
		t.Fatalf("read = %v, want deduped and sorted [/s/a /s/b]", g.Read)
	}
	if !idx.AdmitsWrite(digestA, []string{"/app"}, "/w/a") {
		t.Fatal("write grant should be honored")
	}
	if idx.AdmitsWrite(digestA, []string{"/app"}, "/s/a") {
		t.Fatal("a read grant must not imply write")
	}
}

// paths:any normalizes to empty read/write lists, so it grants nothing.
func TestIndex_PathsAnyGrantsNothing(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"},
		 "paths":{"policy":"any"}}]}}}`).BuildIndex()
	if idx.AdmitsRead(digestA, []string{"/app"}, "/anything") {
		t.Fatal("paths:any must grant nothing")
	}
}

func TestMatchGlobAndCleanPath(t *testing.T) {
	for _, tc := range []struct {
		glob, path string
		want       bool
	}{
		{"/s/model", "/s/model", true},
		{"/s/model", "/s/model/key", false},
		{"/s/model/**", "/s/model/key", true},
		{"/s/model/**", "/s/model/sub/key", true},
		{"/s/model/**", "/s/model", false},
		{"/s/model/**", "/s/modelx/key", false},
	} {
		if got := matchGlob(tc.glob, tc.path); got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.glob, tc.path, got, tc.want)
		}
	}

	for _, bad := range []string{"relative/x", "/a/../b", "/a/*", "/a/"} {
		if _, err := CleanPath(bad); err == nil {
			t.Errorf("CleanPath(%q) accepted an invalid request path", bad)
		}
	}
	if _, err := CleanPath("/a/b"); err != nil {
		t.Errorf("CleanPath(/a/b): %v", err)
	}
}
