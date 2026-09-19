package workflows

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the real build step: a CLI override or hexadecimal tag must not
// build code from a different commit than the staged SNP image.
func TestSNPBuildUsesPairedImageSource(t *testing.T) {
	doc := readWorkflow(t, "snp-metal-e2e.yml")
	var build workflowStep
	for _, step := range doc.Jobs["e2e"].Steps {
		if step.Name == "build the c8s CLI at the paired ref" {
			build = step
		}
	}
	if build.Run == "" {
		t.Fatal("missing CLI build step")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	t.Setenv("GIT_AUTHOR_NAME", "Workflow Test")
	t.Setenv("GIT_AUTHOR_EMAIL", "workflow-test@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "Workflow Test")
	t.Setenv("GIT_COMMITTER_EMAIL", "workflow-test@example.invalid")
	fixture := t.TempDir()
	repo := filepath.Join(fixture, "repository")
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(repo, "fixture-source"), "paired\n", 0o644)
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("add", "fixture-source")
	git("-c", "commit.gpgsign=false", "commit", "-qm", "paired image publication")
	paired := git("rev-parse", "HEAD")
	git("branch", "paired-cli", paired)
	write(filepath.Join(repo, "fixture-source"), "different\n", 0o644)
	git("add", "fixture-source")
	git("-c", "commit.gpgsign=false", "commit", "-qm", "different source")
	different := git("rev-parse", "HEAD")
	git("tag", paired[:7], different)
	if got := git("rev-parse", paired[:7]); got != different {
		t.Fatalf("fixture does not reproduce tag shadowing: got %s want %s", got, different)
	}

	// Redirect only the known production clone to the local fixture. File-only
	// Git transport also prevents diagnostics or a regression from networking.
	workspace := filepath.Join(fixture, "workspace")
	write(filepath.Join(workspace, "bin/retry.sh"), "retry() {\n"+
		"  if [ \"$1\" = git ] && [ \"$2\" = clone ]; then\n"+
		"    [ \"$#\" = 5 ] && [ \"$3\" = -q ] &&\n"+
		"      [ \"$4\" = https://github.com/confidential-dot-ai/c8s.git ] &&\n"+
		"      [ \"$5\" = \"$SNP_TEST_CHECKOUT\" ] || return 1\n"+
		"    git clone -q \"$SNP_TEST_REPO\" \"$SNP_TEST_CHECKOUT\"\n"+
		"  else\n"+
		"    \"$@\"\n"+
		"  fi\n"+
		"}\n", 0o644)
	bin := filepath.Join(fixture, "bin")
	write(filepath.Join(bin, "go"), "#!/bin/sh\nset -eu\n"+
		"[ \"$*\" = 'install ./cmd/c8s' ]\n"+
		"printf 'build %s %s\\n' \"$(git rev-parse HEAD)\" \"$(cat fixture-source)\" >> \"$SNP_TEST_COMMANDS\"\n"+
		"git rev-parse HEAD > \"$SNP_TEST_BINARY_SOURCE\"\n", 0o755)
	write(filepath.Join(bin, "c8s"), "#!/bin/sh\nset -eu\n"+
		"[ \"$*\" = '--version' ]\n"+
		"printf 'run %s\\n' \"$(cat \"$SNP_TEST_BINARY_SOURCE\")\" >> \"$SNP_TEST_COMMANDS\"\n", 0o755)

	for _, tc := range []struct {
		name, image, source string
		ok                  bool
	}{
		{name: "matching full image revision", image: paired, source: paired, ok: true},
		{name: "matching short image revision", image: paired[:7], source: paired, ok: true},
		{name: "matching branch override", image: paired[:7], source: "paired-cli", ok: true},
		{name: "different source", image: paired, source: different},
		{name: "empty image revision", source: paired},
		{name: "nonhex image revision", image: strings.Repeat("g", 40), source: paired},
		{name: "too short image revision", image: paired[:6], source: paired},
		{name: "too long image revision", image: paired + "0", source: paired},
		{name: "newline image revision", image: paired + "\nOTHER=value", source: paired},
		{name: "tag shadows producer prefix", image: paired[:7], source: paired[:7]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := t.TempDir()
			checkout := filepath.Join(output, "private checkout")
			// Quote the replacement path so this test never accesses /tmp/c8s-src,
			// including when the test's temporary directory contains spaces.
			script := strings.ReplaceAll(build.Run, "/tmp/c8s-src",
				"'"+strings.ReplaceAll(checkout, "'", "'\"'\"'")+"'")
			env := append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GITHUB_WORKSPACE="+workspace, "c8sRef="+tc.source, "IMAGE_C8S_REF="+tc.image,
				"SNP_TEST_REPO="+repo, "SNP_TEST_CHECKOUT="+checkout,
				"SNP_TEST_COMMANDS="+filepath.Join(output, "commands"),
				"SNP_TEST_BINARY_SOURCE="+filepath.Join(output, "binary-source"))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", script)
			cmd.Dir, cmd.Env = workspace, env
			log, err := cmd.CombinedOutput()
			commands, readErr := os.ReadFile(filepath.Join(output, "commands"))
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if !tc.ok {
				if err == nil || len(commands) != 0 ||
					!strings.Contains(string(log), "does not match staged SNP image revision") {
					t.Fatalf("unpaired source was not rejected before build: err=%v commands=%q log=%s", err, commands, log)
				}
				return
			}
			if err != nil {
				t.Fatalf("paired source failed: %v\n%s", err, log)
			}
			want := "build " + paired + " paired\nrun " + paired + "\n"
			if string(commands) != want {
				t.Fatalf("CLI was not built and run from paired source: got %q want %q", commands, want)
			}
		})
	}
}
