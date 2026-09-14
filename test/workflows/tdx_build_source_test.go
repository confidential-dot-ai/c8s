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

// Execute the production build step with real Git references. A tag can shadow
// a short SHA even after the full build SHA passed the hosted ancestry check.
func TestTDXExactBuildUsesVerifiedSource(t *testing.T) {
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	var build workflowStep
	for _, step := range action.Runs.Steps {
		if step.Name == "build the c8s CLI at the paired ref" {
			build = step
		}
	}
	if build.Run == "" {
		t.Fatal("missing CLI build step")
	}
	if build.Env["EXACT_IMAGE"] != "${{ inputs.exact_image == 'true' }}" ||
		build.Env["SOURCE_SHA"] != "${{ github.event.workflow_run.head_sha }}" {
		t.Error("build step must receive exact mode and the full publication source SHA")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_ALLOW_PROTOCOL", "") // A regression must never contact the network.
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	t.Setenv("GIT_AUTHOR_NAME", "Workflow Test")
	t.Setenv("GIT_AUTHOR_EMAIL", "workflow-test@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "Workflow Test")
	t.Setenv("GIT_COMMITTER_EMAIL", "workflow-test@example.invalid")
	fixture := t.TempDir()
	workspace := filepath.Join(fixture, "verified checkout")
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(workspace, "fixture-source"), "trusted\n", 0o644)
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = workspace
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("add", "fixture-source")
	git("-c", "commit.gpgsign=false", "commit", "-qm", "trusted publication")
	trusted := git("rev-parse", "HEAD")
	git("update-ref", "refs/remotes/origin/main", trusted)
	write(filepath.Join(workspace, "fixture-source"), "unreviewed\n", 0o644)
	git("add", "fixture-source")
	git("-c", "commit.gpgsign=false", "commit", "-qm", "unreviewed tag target")
	untrusted := git("rev-parse", "HEAD")
	git("tag", trusted[:7], untrusted)
	git("checkout", "-q", "--detach", trusted)
	git("merge-base", "--is-ancestor", trusted, "refs/remotes/origin/main")
	if got := git("rev-parse", trusted[:7]); got != untrusted {
		t.Fatalf("fixture does not reproduce short-ref tag shadowing: got %s want %s", got, untrusted)
	}

	// The earlier tools step supplies retry.sh. Refuse cloning/deletion here so
	// a failing regression cannot touch the launcher's absolute /tmp/c8s-src.
	write(filepath.Join(workspace, "bin/retry.sh"), `retry() {
  printf '%s\n' "$1" >> "$TDX_TEST_RETRIES"
  case "$1" in *clone*|*'rm '*) return 1 ;; esac
  eval "$1"
}
`, 0o644)
	bin := filepath.Join(fixture, "bin")
	write(filepath.Join(bin, "go"), `#!/bin/sh
set -eu
[ "$*" = 'install ./cmd/c8s' ]
printf 'build %s %s\n' "$(git rev-parse HEAD)" "$(cat fixture-source)" >> "$TDX_TEST_COMMANDS"
git rev-parse HEAD > "$TDX_TEST_BINARY_SOURCE"
`, 0o755)
	write(filepath.Join(bin, "c8s"), `#!/bin/sh
set -eu
[ "$*" = '--version' ]
printf 'run %s\n' "$(cat "$TDX_TEST_BINARY_SOURCE")" >> "$TDX_TEST_COMMANDS"
`, 0o755)
	for _, name := range []string{"components-ready.sh", "allowlist-enforcement.sh", "cw-workload.sh"} {
		write(filepath.Join(workspace, "test/e2e", name),
			"printf '%s\\n' '"+name+"' >> \"$TDX_TEST_ROUTING\"\n", 0o644)
	}

	for _, tc := range []struct {
		name, source string
		missing, ok  bool
	}{
		{name: "tag shadows source prefix", source: trusted, ok: true},
		{name: "different full SHA", source: untrusted},
		{name: "short SHA", source: trusted[:7]},
		{name: "nonhex SHA", source: strings.Repeat("g", 40)},
		{name: "newline injection", source: trusted + "\nOTHER=value"},
		{name: "empty SHA"},
		{name: "missing SHA", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := t.TempDir()
			env := make([]string, 0, len(os.Environ())+12)
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "SOURCE_SHA=") && !strings.HasPrefix(entry, "C8S_SOURCE_DIR=") {
					env = append(env, entry)
				}
			}
			env = append(env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"EXACT_IMAGE=true", "GITHUB_WORKSPACE="+workspace, "c8sRef="+trusted[:7],
				"GITHUB_ENV="+filepath.Join(output, "env"), "TDX_TEST_RETRIES="+filepath.Join(output, "retries"),
				"TDX_TEST_COMMANDS="+filepath.Join(output, "commands"),
				"TDX_TEST_BINARY_SOURCE="+filepath.Join(output, "binary-source"),
				"TDX_TEST_ROUTING="+filepath.Join(output, "routing"), "GUEST_IP=127.0.0.1", "mrtd=unused")
			if !tc.missing {
				env = append(env, "SOURCE_SHA="+tc.source)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", build.Run)
			cmd.Dir, cmd.Env = workspace, env
			log, err := cmd.CombinedOutput()
			read := func(name string) string {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(output, name))
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				return string(data)
			}
			if strings.Contains(read("retries"), "clone") {
				t.Error("exact mode attempted a second source clone")
			}
			commands, exported := read("commands"), read("env")
			if !tc.ok {
				if err == nil || commands != "" || strings.Contains(exported, "C8S_SOURCE_DIR=") {
					t.Fatalf("invalid source reached execution: err=%v commands=%q env=%q log=%s", err, commands, exported, log)
				}
				return
			}
			if err != nil {
				t.Fatalf("verified source failed: %v\n%s", err, log)
			}
			want := "build " + trusted + " trusted\nrun " + trusted + "\n"
			if commands != want {
				t.Fatalf("CLI was not built and run from verified source: got %q want %q", commands, want)
			}
			if exported != "C8S_SOURCE_DIR="+workspace+"\n" {
				t.Fatalf("wrong source passed to later steps: %q", exported)
			}
			env = append(env, strings.TrimSpace(exported))
			var ran []string
			for _, step := range action.Runs.Steps {
				switch step.Name {
				case "assert components converged", "assert the image floor denies, then opens to a signed write", "assert a confidential workload runs with an injected cert":
					cmd := exec.CommandContext(ctx, "bash", "-c", step.Run)
					cmd.Dir, cmd.Env = output, env
					if log, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("%s did not use verified source: %v\n%s", step.Name, err, log)
					}
					ran = append(ran, step.Name)
				}
			}
			if len(ran) != 3 || read("routing") != "components-ready.sh\nallowlist-enforcement.sh\ncw-workload.sh\n" {
				t.Fatalf("downstream tests did not all use verified source: steps=%v routing=%q", ran, read("routing"))
			}
		})
	}
}
