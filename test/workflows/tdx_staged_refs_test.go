package workflows

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Run image resolution with registry requests replaced at the curl boundary.
func TestTDXStagedImageRefs(t *testing.T) {
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	var script string
	for _, step := range action.Runs.Steps {
		if step.Name == "resolve the node image built from the commit under test" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("missing commit image-resolution step")
	}

	fixture := t.TempDir()
	if err := os.Mkdir(filepath.Join(fixture, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "bin/retry.sh"), []byte(`retry() { eval "$1"; }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	curl := `#!/usr/bin/env bash
set -euo pipefail
url=${!#}
printf '%s\n' "$url" >> "$FIXTURE_REQUESTS"
case "$url" in
  'https://ghcr.io/token?scope=repository:confidential-dot-ai/node-guest-base:pull')
    printf '%s' '{"token":"fixture-token"}' ;;
  'https://ghcr.io/v2/confidential-dot-ai/node-guest-base/manifests/rke2-tdx-cdi-abcdef0')
    [[ $1 == -sI ]] || exit 1
    printf 'HTTP/2 %s\r\ndocker-content-digest: %s\r\n' "$FIXTURE_STATUS" "$FIXTURE_DIGEST" ;;
  'https://ghcr.io/v2/confidential-dot-ai/node-guest-base/manifests/rke2-tdx-abcdef0')
    printf '%s' '{"layers":[{"annotations":{"org.opencontainers.image.title":"manifest.json"},"digest":"sha256:manifest-layer"}]}' ;;
  'https://ghcr.io/v2/confidential-dot-ai/node-guest-base/blobs/sha256:manifest-layer')
    printf '{"build":{"platform":"%s"},"tdx":{"mrtd":"%s","rtmr1":"measurement-1","rtmr2":"measurement-2"}}' "$FIXTURE_PLATFORM" "$FIXTURE_MRTD" ;;
  *) echo "unexpected registry request: $url" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(fixture, "curl"), []byte(curl), 0o755); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	mrtd := strings.Repeat("b", 96)

	for _, tc := range []struct {
		name, status, digest, platform, mrtd, failure string
		requests                                      int
	}{
		{"exact commit image", "200", digest, "tdx", mrtd, "", 4},
		{"commit image absent", "404", "", "tdx", mrtd, "no node image for the commit under test", 2},
		{"digest missing", "200", "", "tdx", mrtd, "ghcr answered 200", 2},
		{"digest malformed", "200", "sha256:bad", "tdx", mrtd, "ghcr answered 200", 2},
		{"wrong platform", "200", digest, "snp", mrtd, "is not a TDX node image manifest", 4},
		{"measurement missing", "200", digest, "tdx", "", "is not a TDX node image manifest", 4},
		{"measurement truncated", "200", digest, "tdx", mrtd[:95], "is not a TDX node image manifest", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			output := filepath.Join(dir, "environment")
			requests := filepath.Join(dir, "requests")
			// Isolate the action's fixed output path for concurrent test processes.
			isolated := strings.ReplaceAll(script, "/tmp/image-manifest.json", filepath.Join(dir, "manifest.json"))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", isolated)
			cmd.Env = append(os.Environ(),
				"PATH="+fixture+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GITHUB_WORKSPACE="+fixture, "GITHUB_ENV="+output,
				"IMAGE_REPO=ghcr.io/confidential-dot-ai/node-guest-base", "c8sRef=abcdef0",
				"FIXTURE_REQUESTS="+requests, "FIXTURE_STATUS="+tc.status,
				"FIXTURE_DIGEST="+tc.digest, "FIXTURE_PLATFORM="+tc.platform, "FIXTURE_MRTD="+tc.mrtd)
			log, err := cmd.CombinedOutput()
			if tc.failure != "" {
				if err == nil || !strings.Contains(string(log), tc.failure) {
					t.Fatalf("invalid image was not rejected: err=%v log=%s", err, log)
				}
				if raw, readErr := os.ReadFile(output); !os.IsNotExist(readErr) {
					t.Fatalf("rejected image exported environment: %s (err=%v)", raw, readErr)
				}
			} else {
				if err != nil {
					t.Fatalf("resolve commit image: %v\n%s", err, log)
				}
				raw, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				got := make(map[string]string)
				for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
					key, value, ok := strings.Cut(line, "=")
					if !ok {
						t.Fatalf("invalid environment assignment %q", line)
					}
					got[key] = value
				}
				want := map[string]string{
					"image":   "ghcr.io/confidential-dot-ai/node-guest-base@" + digest,
					"rootPvc": "c8s-root-aaaaaaaaaaaa", "mrtd": mrtd,
					"rtmr1": "measurement-1", "rtmr2": "measurement-2",
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("image environment: got %v, want %v", got, want)
				}
			}
			raw, err := os.ReadFile(requests)
			if err != nil {
				t.Fatal(err)
			}
			wantRequests := []string{
				"https://ghcr.io/token?scope=repository:confidential-dot-ai/node-guest-base:pull",
				"https://ghcr.io/v2/confidential-dot-ai/node-guest-base/manifests/rke2-tdx-cdi-abcdef0",
				"https://ghcr.io/v2/confidential-dot-ai/node-guest-base/manifests/rke2-tdx-abcdef0",
				"https://ghcr.io/v2/confidential-dot-ai/node-guest-base/blobs/sha256:manifest-layer",
			}
			if got := strings.Split(strings.TrimSpace(string(raw)), "\n"); !reflect.DeepEqual(got, wantRequests[:tc.requests]) {
				t.Fatalf("registry requests: got %v, want %v", got, wantRequests[:tc.requests])
			}
		})
	}
}
