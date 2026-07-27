package allowlist

import (
	"encoding/json"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A digest on the floor is admitted by digest alone, so any argv/paths policy an
// operator also wrote for it in a workload is silently not enforced. lint must
// surface that overlap — and only for the overlapping digest.
func TestLintFloorWorkloadOverlap(t *testing.T) {
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1",
		"digests":{"` + digA + `":"base"},
		"workloads":{"w":{"containers":[
			{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}},
			{"digest":"` + digC + `","command":{"policy":"exact","argv":["/x"]},"args":{"policy":"deny"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}

	var overlap []string
	for _, w := range lintOffline(al) {
		if strings.Contains(w, "floor-listed") {
			overlap = append(overlap, w)
		}
	}
	joined := strings.Join(overlap, "\n")
	if !strings.Contains(joined, digA) {
		t.Fatalf("expected a floor-overlap warning naming %s, got:\n%s", digA, joined)
	}
	if strings.Contains(joined, digC) {
		t.Fatalf("digC is workload-only and must not be flagged as floor-listed:\n%s", joined)
	}
}

// A fully constrained allowlist must lint clean: exactly the ok line, nothing
// else, and --strict must still exit zero.
func TestLintCleanAllowlistReportsOK(t *testing.T) {
	f := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`)

	out, _, err := runCmd("lint", f)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	if out != "ok: no warnings\n" {
		t.Fatalf("lint output = %q, want %q", out, "ok: no warnings\n")
	}

	if _, _, err := runCmd("lint", "--strict", f); err != nil {
		t.Fatalf("--strict with no warnings must succeed, got %v", err)
	}
}

// The any-count warning tallies each unconstrained segment (command, args,
// paths) per container; a fully-any container in a single entry produces no
// other warning, so the output is pinned exactly.
func TestLintAnyCountWarning(t *testing.T) {
	cases := []struct {
		name string
		ctr  string
		want string
	}{
		{
			name: "fully unconstrained counts all three segments",
			ctr:  `{"digest":"` + digA + `","command":{"policy":"any"},"args":{"policy":"any"},"paths":{"policy":"any"}}`,
			want: "warning: 3 'any' (unconstrained) policy value(s) across all entries\n",
		},
		{
			name: "single any segment counts once",
			ctr:  `{"digest":"` + digA + `","command":{"policy":"any"},"args":{"policy":"exact","argv":["/x"]},"paths":{"policy":"allow","read":["/data"]}}`,
			want: "warning: 1 'any' (unconstrained) policy value(s) across all entries\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[`+tc.ctr+`]}}}`)
			out, _, err := runCmd("lint", f)
			if err != nil {
				t.Fatalf("lint: %v", err)
			}
			if out != tc.want {
				t.Fatalf("lint output = %q, want %q", out, tc.want)
			}
		})
	}
}

func TestLintOnlineChecks(t *testing.T) {
	fakeCrane(t)
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
	fakeCrane(t)
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
	fakeCrane(t)
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

func TestLintNoFloorOverlap(t *testing.T) {
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1",
		"digests":{"` + digB + `":"infra"},
		"workloads":{"w":{"containers":[
			{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range lintOffline(al) {
		if strings.Contains(w, "floor-listed") {
			t.Fatalf("disjoint floor and workloads must not warn, got: %s", w)
		}
	}
}
