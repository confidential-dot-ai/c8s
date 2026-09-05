package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Exercise the unchanged inline preflight against real Git history. The
// privileged launcher must receive only a SHA proven to belong to main.
func TestTDXSourceProvenance(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/tdx-metal-e2e.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Needs  string
			RunsOn string `yaml:"runs-on"`
			Steps  []struct {
				ID  string
				Run string
			}
		}
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	source := workflow.Jobs["source"]
	if source.RunsOn != "ubuntu-latest" || workflow.Jobs["e2e"].Needs != "source" {
		t.Fatal("source verification must precede launcher allocation on a hosted runner")
	}
	var script string
	for _, step := range source.Steps {
		if step.ID == "source" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("missing inline source verification")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_AUTHOR_NAME", "Workflow Test")
	t.Setenv("GIT_AUTHOR_EMAIL", "workflow-test@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "Workflow Test")
	t.Setenv("GIT_COMMITTER_EMAIL", "workflow-test@example.invalid")
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	tree := git("mktree")
	parent := git("commit-tree", tree, "-m", "accepted parent")
	head := git("commit-tree", tree, "-p", parent, "-m", "current main")
	untrusted := git("commit-tree", tree, "-p", parent, "-m", "unmerged branch")
	git("update-ref", "refs/remotes/origin/main", head)

	for _, tc := range []struct {
		name, exact, source, workflow, want string
	}{
		{"main tip", "true", head, parent, head},
		{"older main build", "true", parent, head, parent},
		{"unmerged branch", "true", untrusted, head, ""},
		{"missing commit", "true", strings.Repeat("a", 40), head, ""},
		{"symbolic ref", "true", "refs/remotes/origin/main", head, ""},
		{"empty source", "true", "", head, ""},
		{"option injection", "true", "--help", head, ""},
		{"output injection", "true", head + "\nsha=" + untrusted, head, ""},
		{"manual staged", "false", "", head, head},
		{"staged ignores event source", "false", untrusted, head, head},
		{"invalid staged SHA", "false", "", "main", ""},
		{"invalid mode", "invalid", head, head, ""},
		{"nonhex SHA", "true", strings.Repeat("g", 40), head, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output")
			cmd := exec.Command("bash", "-c", script)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(),
				"EXACT_IMAGE="+tc.exact, "SOURCE_SHA="+tc.source,
				"WORKFLOW_SHA="+tc.workflow, "GITHUB_OUTPUT="+output)
			log, err := cmd.CombinedOutput()
			got, readErr := os.ReadFile(output)
			if tc.want == "" {
				if err == nil || len(got) != 0 {
					t.Fatalf("untrusted source accepted: err=%v output=%q log=%s", err, got, log)
				}
				return
			}
			if err != nil || readErr != nil || string(got) != "sha="+tc.want+"\n" {
				t.Fatalf("trusted source rejected: err=%v read=%v output=%q log=%s", err, readErr, got, log)
			}
		})
	}
}
