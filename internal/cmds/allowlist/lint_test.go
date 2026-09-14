package allowlist

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/crane/cranetest"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A fully constrained allowlist must lint clean: exactly the ok line, nothing
// else, and --strict must still exit zero.
func TestLintCleanAllowlistReportsOK(t *testing.T) {
	f := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`)

	out, _, err := runCmd("lint", f)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	if out != "ok: no findings\n" {
		t.Fatalf("lint output = %q, want %q", out, "ok: no findings\n")
	}

	if _, _, err := runCmd("lint", "--strict", f); err != nil {
		t.Fatalf("--strict with no warnings must succeed, got %v", err)
	}
}

func TestLintOnlineChecks(t *testing.T) {
	cranetest.Install(t)
	goodRef := "registry.example.com/app@" + digA
	missingRef := "registry.example.com/app@" + digB
	f := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digA+`","image":"`+goodRef+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"}},
		{"digest":"`+digB+`","image":"`+missingRef+`","command":{"policy":"exact","argv":["/b"]},"args":{"policy":"deny"}},
		{"digest":"`+digC+`","command":{"policy":"exact","argv":["/c"]},"args":{"policy":"deny"}},
		{"digest":"`+digD+`","image":"registry.example.com/APP","command":{"policy":"exact","argv":["/d"]},"args":{"policy":"deny"}}]}}}`)

	out, _, err := runCmd("lint", "--online", f)
	if err != nil {
		t.Fatalf("lint --online: %v", err)
	}
	for _, want := range []string{
		"container " + digC + " has no image label",
		`image "registry.example.com/APP"`,
		"container digest not found in registry: registry.example.com/app@" + digB,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lint output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not found in registry: registry.example.com/app@"+digA) {
		t.Errorf("resolvable digest must not warn:\n%s", out)
	}
}

func TestInspectImageText(t *testing.T) {
	cranetest.Install(t)
	out, _, err := runCmd("inspect-image", "registry.example.com/app:v1")
	if err != nil {
		t.Fatalf("inspect-image: %v", err)
	}
	for _, want := range []string{
		"ref:        registry.example.com/app:v1\n",
		"digest:     " + digA + "\n",
		"entrypoint: /bin/app\n",
		"cmd:        serve --port=1\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect-image output missing %q:\n%s", want, out)
		}
	}

	if _, _, err := runCmd("inspect-image", "registry.example.com/unresolvable:v1"); err == nil {
		t.Fatal("expected an unresolvable ref to fail")
	}
}

func TestInspectImageJSON(t *testing.T) {
	cranetest.Install(t)
	out, _, err := runCmd("inspect-image", "registry.example.com/app:v1", "-o", "json")
	if err != nil {
		t.Fatalf("inspect-image -o json: %v", err)
	}
	var got struct {
		Ref        string   `json:"ref"`
		Digest     string   `json:"digest"`
		Entrypoint []string `json:"entrypoint"`
		Cmd        []string `json:"cmd"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if got.Ref != "registry.example.com/app:v1" || got.Digest != digA {
		t.Fatalf("ref/digest = %q / %q", got.Ref, got.Digest)
	}
	if len(got.Entrypoint) != 1 || got.Entrypoint[0] != "/bin/app" {
		t.Fatalf("entrypoint = %v", got.Entrypoint)
	}
	if len(got.Cmd) != 2 || got.Cmd[0] != "serve" || got.Cmd[1] != "--port=1" {
		t.Fatalf("cmd = %v", got.Cmd)
	}
}

// --- shadowed entries ---

// An any-argv entry for a digest shadows a narrower entry declaring only that
// digest: every pod the narrow entry describes matches both, so the narrow
// entry can never be released to.
func TestLintShadowedEntry(t *testing.T) {
	wide := `{"containers":[{"digest":"` + digA + `","command":{"policy":"any"},"args":{"policy":"any"}}]}`
	narrow := `{"containers":[` + ctrJSON(digA, "/app") + `]}`

	errs := func(doc string) []string {
		t.Helper()
		al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{` + doc + `}}`))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range lintOffline(al) {
			if f.err {
				out = append(out, f.msg)
			}
		}
		return out
	}

	got := errs(`"seeded":` + wide + `,"api":` + narrow)
	if len(got) != 1 || !strings.Contains(got[0], `workload "api" can never be the unique match: "seeded"`) {
		t.Fatalf("shadowed entry not reported as an error: %v", got)
	}

	// A narrow entry with a main the wide one does not declare is foreign to
	// it, so it is distinguishable.
	twoMains := `{"containers":[` + ctrJSON(digA, "/app") + `,` + ctrJSON(digB, "/db") + `]}`
	if got := errs(`"seeded":` + wide + `,"api":` + twoMains); len(got) != 0 {
		t.Fatalf("a distinguishable entry was reported: %v", got)
	}

	// Two any-argv entries of the same shape are the indistinguishable case,
	// reported once, not as a shadow in each direction as well.
	if got := errs(`"a":` + wide + `,"b":` + wide); len(got) != 1 || !strings.Contains(got[0], "declare the same containers") {
		t.Fatalf("identical entries should yield one indistinguishable error, got %v", got)
	}
}

// --- indistinguishable entries ---

// entryPair builds a document with two entries whose container lists are given
// as raw JSON, so a test can vary one field at a time.
func entryPair(t *testing.T, a, b string) *pkgallowlist.Allowlist {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"` + pkgallowlist.Schema + `","workloads":{
		"alpha":{"containers":` + a + `},
		"beta":{"containers":` + b + `}}}`))
	if err != nil {
		t.Fatal(err)
	}
	return al
}

func ambiguityErrors(findings []finding) []string {
	var out []string
	for _, f := range findings {
		if f.err && strings.Contains(f.msg, "same containers with the same command, args and env policy") {
			out = append(out, f.msg)
		}
	}
	return out
}

// Two entries no running set can tell apart are refused forever, so this is an
// error rather than something an operator can weigh up.
func TestLintIndistinguishableEntriesIsAnError(t *testing.T) {
	same := `[{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]`
	al := entryPair(t, same, same)

	errs := ambiguityErrors(lintOffline(al))
	if len(errs) != 1 {
		t.Fatalf("expected one ambiguity error, got %v", errs)
	}
	if !strings.Contains(errs[0], "alpha") || !strings.Contains(errs[0], "beta") {
		t.Fatalf("the error must name both entries, got %q", errs[0])
	}
	if countErrors(lintOffline(al)) == 0 {
		t.Fatal("the finding is not flagged as an error")
	}
}

// Argv is carried at release time and matched against each entry's own policy,
// so entries differing only in argv are distinguishable and must not be flagged.
func TestLintDistinctArgvIsNotAmbiguous(t *testing.T) {
	al := entryPair(t,
		`[{"digest":"`+digA+`","command":{"policy":"exact","argv":["/serve"]},"args":{"policy":"deny"}}]`,
		`[{"digest":"`+digA+`","command":{"policy":"exact","argv":["/train"]},"args":{"policy":"deny"}}]`)

	if errs := ambiguityErrors(lintOffline(al)); len(errs) != 0 {
		t.Fatalf("entries differing in argv are distinguishable, got %v", errs)
	}
}

// A main is required to be present and an init is not, so the same digest in
// different lists produces entries a running set can tell apart.
func TestLintMainVersusInitIsNotAmbiguous(t *testing.T) {
	body := `{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}`
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"` + pkgallowlist.Schema + `","workloads":{
		"alpha":{"containers":[` + body + `]},
		"beta":{"initContainers":[` + body + `],"containers":[
			{"digest":"` + digC + `","command":{"policy":"exact","argv":["/x"]},"args":{"policy":"deny"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if errs := ambiguityErrors(lintOffline(al)); len(errs) != 0 {
		t.Fatalf("a container in different lists is distinguishable, got %v", errs)
	}
}

// Declaration order is not a difference: the shape is compared as a set.
func TestLintAmbiguityIgnoresDeclarationOrder(t *testing.T) {
	one := `{"digest":"` + digA + `","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"}}`
	two := `{"digest":"` + digC + `","command":{"policy":"exact","argv":["/c"]},"args":{"policy":"deny"}}`
	al := entryPair(t, `[`+one+`,`+two+`]`, `[`+two+`,`+one+`]`)

	if errs := ambiguityErrors(lintOffline(al)); len(errs) != 1 {
		t.Fatalf("reordered declarations are the same shape, got %v", errs)
	}
}

// The grant is deliberately outside the shape: two entries alike but for their
// secrets are the dangerous case, since the grant an operator wrote is the
// thing that never resolves.
func TestLintAmbiguityIgnoresTheGrant(t *testing.T) {
	body := `[{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]`
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"` + pkgallowlist.Schema + `","workloads":{
		"alpha":{"containers":` + body + `,"secrets":{"policy":"allow","read":["/a/**"]}},
		"beta":{"containers":` + body + `,"secrets":{"policy":"allow","read":["/b/**"]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if errs := ambiguityErrors(lintOffline(al)); len(errs) != 1 {
		t.Fatalf("differing grants do not make entries distinguishable, got %v", errs)
	}
}

// A single entry, and entries that genuinely differ, stay clean.
func TestLintNoFalseAmbiguity(t *testing.T) {
	al := entryPair(t,
		`[{"digest":"`+digA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]`,
		`[{"digest":"`+digC+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]`)
	if errs := ambiguityErrors(lintOffline(al)); len(errs) != 0 {
		t.Fatalf("distinct digests are distinguishable, got %v", errs)
	}
}

// An entry that collides with one already served is the realistic case: an
// operator applies one entry at a time, so the file alone never shows it.
func TestWorkloadApplyRefusesCollisionWithLive(t *testing.T) {
	body := `[{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]`
	live, err := pkgallowlist.ParseJSON([]byte(`{"schema":"` + pkgallowlist.Schema + `","workloads":{
		"served":{"containers":` + body + `}}}`))
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := pkgallowlist.ParseJSON([]byte(`{"schema":"` + pkgallowlist.Schema + `","workloads":{
		"incoming":{"containers":` + body + `}}}`))
	if err != nil {
		t.Fatal(err)
	}

	findings := collisionsWithLive(incoming.Workloads, live)
	if countErrors(findings) != 1 {
		t.Fatalf("expected one collision error, got %v", findings)
	}
	if !strings.Contains(findings[0].msg, "served") || !strings.Contains(findings[0].msg, "incoming") {
		t.Fatalf("the error must name both sides, got %q", findings[0].msg)
	}
}

// Replacing an entry with itself is an ordinary re-apply, not a collision.
func TestWorkloadApplyReplacingItselfIsNotACollision(t *testing.T) {
	body := `[{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]`
	doc, err := pkgallowlist.ParseJSON([]byte(`{"schema":"` + pkgallowlist.Schema + `","workloads":{
		"same":{"containers":` + body + `}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if findings := collisionsWithLive(doc.Workloads, doc); len(findings) != 0 {
		t.Fatalf("re-applying an entry over itself must be clean, got %v", findings)
	}
}

// A collision wholly inside the applied file is reported by the file lint, so
// the live check does not repeat it.
func TestWorkloadApplyDoesNotDoubleReportInFileCollision(t *testing.T) {
	body := `[{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]`
	incoming, err := pkgallowlist.ParseJSON([]byte(`{"schema":"` + pkgallowlist.Schema + `","workloads":{
		"alpha":{"containers":` + body + `},
		"beta":{"containers":` + body + `}}}`))
	if err != nil {
		t.Fatal(err)
	}
	empty := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema}
	if findings := collisionsWithLive(incoming.Workloads, empty); len(findings) != 0 {
		t.Fatalf("an in-file collision belongs to the file lint, got %v", findings)
	}
	if len(ambiguityErrors(lintOffline(incoming))) != 1 {
		t.Fatal("the file lint should have reported it")
	}
}
