package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Run the unchanged staged-ref step with kubectl replaced at its boundary.
func TestTDXStagedImageRefs(t *testing.T) {
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	var script string
	for _, step := range action.Runs.Steps {
		if step.Name == "resolve image refs + the paired c8s ref" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("missing staged image-ref resolution step")
	}

	fixture := t.TempDir()
	kubectl := `#!/usr/bin/env bash
set -euo pipefail
[[ $# == 7 && $1 == -n && $2 == confai-images && $3 == get &&
   $4 == cm && $5 == tdx-rke2-image-refs && $6 == -o ]] || exit 1
[[ $7 != "jsonpath={.data.$FIXTURE_MISSING}" ]] || exit 0
case "$7" in
  'jsonpath={.data.image}') printf '%s' 'published-image' ;;
  'jsonpath={.data.rootPvc}') printf '%s' 'staged-root' ;;
  'jsonpath={.data.mrtd}') printf '%s' 'measurement-0' ;;
  'jsonpath={.data.rtmr1}') printf '%s' 'measurement-1' ;;
  'jsonpath={.data.rtmr2}') printf '%s' 'measurement-2' ;;
  'jsonpath={.data.c8sRef}') printf '%s' 'paired-ref' ;;
  'jsonpath={.data.imageTag}') printf '%s' "$FIXTURE_IMAGE_TAG" ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(fixture, "kubectl"), []byte(kubectl), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, imageTag, override, missing string
	}{
		{"tag present", "rke2-tdx-manifest", "", ""},
		{"tag absent", "", "", ""},
		{"tag present with override", "rke2-tdx-manifest", "caller-ref", ""},
		{"tag absent with override", "", "caller-ref", ""},
		{"required measurement missing", "rke2-tdx-manifest", "caller-ref", "mrtd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "environment")
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"PATH="+fixture+string(os.PathListSeparator)+os.Getenv("PATH"),
				"NS=confai-images", "REFS_CM=tdx-rke2-image-refs",
				"GITHUB_ENV="+output, "C8S_REF_OVERRIDE="+tc.override,
				"FIXTURE_IMAGE_TAG="+tc.imageTag, "FIXTURE_MISSING="+tc.missing)
			log, err := cmd.CombinedOutput()
			if tc.missing != "" {
				if err == nil || !strings.Contains(string(log), "missing '"+tc.missing+"'") {
					t.Fatalf("missing required ref was not rejected: err=%v log=%s", err, log)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve staged refs: %v\n%s", err, log)
			}
			raw, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[string]string)
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				key, value, ok := strings.Cut(line, "=")
				if !ok {
					t.Fatalf("invalid environment assignment %q", line)
				}
				got[key] = value
			}
			want := map[string]string{
				"image": "published-image", "rootPvc": "staged-root",
				"mrtd": "measurement-0", "rtmr1": "measurement-1",
				"rtmr2": "measurement-2", "c8sRef": "paired-ref",
			}
			if tc.imageTag != "" {
				want["imageTag"] = tc.imageTag
			}
			if tc.override != "" {
				want["c8sRef"] = tc.override
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("staged environment: got %v, want %v", got, want)
			}
		})
	}
}
