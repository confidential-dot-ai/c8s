package allowlist

import (
	"strings"
	"testing"
)

func TestIndex_AnyArgvEntryAdmitsAnyArgv(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"cds":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsDigest(digestA) {
		t.Fatal("digest not admitted")
	}
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/anything", "--dynamic"}}) {
		t.Fatal("an any/any entry must admit the digest regardless of argv")
	}
}

// A multi-token command is matched as an exact prefix; args:any leaves the rest
// free. This is the case an entrypoint like "/docker-entrypoint.sh nginx" needs.
func TestIndex_MultiTokenCommandPrefix(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/docker-entrypoint.sh","nginx"]},
		 "args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}}) {
		t.Fatal("argv starting with the command prefix should be admitted")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/docker-entrypoint.sh"}}) {
		t.Fatal("argv shorter than the command prefix must be rejected")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/bin/sh", "nginx", "-g"}}) {
		t.Fatal("a different prefix must be rejected")
	}
}

func TestIndex_FullExact(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/app"]},
		 "args":{"policy":"exact","argv":["--serve","--port=8080"]}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/app", "--serve", "--port=8080"}}) {
		t.Fatal("exact command+args should match the concatenation")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/bin/sh", "--serve", "--port=8080"}}) {
		t.Fatal("a swapped command must be rejected")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/app", "--serve"}}) {
		t.Fatal("truncated args must be rejected")
	}
}

func TestIndex_ArgsDenyMeansNoArgs(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/app"}}) {
		t.Fatal("args:deny should admit the command with no extra args")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/app", "--exfil"}}) {
		t.Fatal("args:deny must reject any extra args")
	}
}

func TestIndex_CommandDenyMeansEmptyArgv(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"deny"},"args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: nil}) {
		t.Fatal("command:deny should admit an empty argv")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/bin/sh"}}) {
		t.Fatal("command:deny must reject any argv")
	}
}

// A shared digest may run under several command/args policies; admission is the
// union across entries.
func TestIndex_SharedDigestUnion(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"a":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["busybox","sleep"]},"args":{"policy":"exact","argv":["1"]}}]},
		"b":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["busybox","echo"]},"args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"busybox", "sleep", "1"}}) {
		t.Fatal("first entry's argv should be admitted")
	}
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"busybox", "echo", "hi"}}) {
		t.Fatal("second entry's argv should be admitted")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"busybox", "cat", "/etc/shadow"}}) {
		t.Fatal("an argv no entry permits must be rejected")
	}
}

func TestIndex_UnknownDigestDenied(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`).BuildIndex()
	if idx.AdmitsDigest(digestB) || idx.AdmitsContainer(RunningContainer{Digest: digestB, Argv: nil}) {
		t.Fatal("unknown digest must be denied")
	}
}

func TestDigestIndex_AdmitsListedDigestWhateverItRuns(t *testing.T) {
	idx, warnings := DigestIndex([]string{digestA, strings.ToUpper(digestB[7:]), "ghcr.io/acme/app@" + digestC})
	if len(warnings) != 0 {
		t.Fatalf("DigestIndex warnings = %v, want none", warnings)
	}
	if idx.Size() != 3 {
		t.Fatalf("Size() = %d, want 3", idx.Size())
	}
	for _, d := range []string{digestA, digestB, digestC} {
		if !idx.AdmitsDigest(d) {
			t.Errorf("AdmitsDigest(%s) = false, want true", d)
		}
		if !idx.AdmitsContainer(RunningContainer{
			Digest: d,
			Argv:   []string{"/bin/sh", "-c", "anything"},
		}) {
			t.Errorf("AdmitsContainer(%s) = false, want a digest-alone admission", d)
		}
	}
}

func TestDigestIndex_SkipsMalformedAndWarns(t *testing.T) {
	idx, warnings := DigestIndex([]string{digestA, "not-a-digest", "", "ghcr.io/acme/app:v1"})
	if idx.Size() != 1 {
		t.Fatalf("Size() = %d, want 1", idx.Size())
	}
	if len(warnings) != 3 {
		t.Fatalf("warnings = %v, want one per malformed entry", warnings)
	}
	if idx.AdmitsDigest(digestB) {
		t.Error("an unlisted digest must not be admitted")
	}
}

func TestIndex_NilAdmitsNothing(t *testing.T) {
	var idx *Index
	if idx.AdmitsDigest(digestA) || idx.AdmitsContainer(RunningContainer{Digest: digestA}) || idx.Size() != 0 {
		t.Fatal("a nil *Index must admit nothing and report size 0")
	}
}
