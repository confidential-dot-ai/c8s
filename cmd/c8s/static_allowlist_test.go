package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/initdata"
)

const bootstrapDoc = `{
  "schema": "c8s.allowlist/v1",
  "digests": {"sha256:1111111111111111111111111111111111111111111111111111111111111111": "ghcr.io/x/base:v1"},
  "workloads": {
    "api.v2": {
      "containers": [{
        "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "command": {"policy": "any"}, "args": {"policy": "any"}
      }]
    }
  }
}`

func TestAppendBootstrapAllowlistArgs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(path, []byte(bootstrapDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	args, err := appendBootstrapAllowlistArgs(nil, path)
	if err != nil {
		t.Fatalf("appendBootstrapAllowlistArgs: %v", err)
	}
	tree, err := valueArgsToTree(args)
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	if v, err := stringAtPath(tree, "nriImagePolicy.bootstrapAllowlist.digests.sha256:1111111111111111111111111111111111111111111111111111111111111111"); err != nil || v != "ghcr.io/x/base:v1" {
		t.Fatalf("floor digest not folded into the seed: %v %q", err, v)
	}
	workloads, ok := nestedMap(tree, "nriImagePolicy", "bootstrapAllowlist", "workloads")
	if !ok {
		t.Fatalf("workloads missing from the seed: %+v", tree)
	}
	// A dotted workload name survives as one key — the JSON subtree is set
	// whole, never spelled as a dotted path.
	if _, ok := workloads["api.v2"]; !ok {
		t.Fatalf("workload api.v2 missing: %+v", workloads)
	}
	if len(workloadDigests(workloads["api.v2"])) != 1 {
		t.Fatalf("workload containers not preserved: %+v", workloads["api.v2"])
	}
}

func TestAppendBootstrapAllowlistArgs_RejectsBadDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"schema":"nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := appendBootstrapAllowlistArgs(nil, path); err == nil {
		t.Fatal("a non-allowlist document must be refused")
	}
	if _, err := appendBootstrapAllowlistArgs(nil, filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("a missing file must be refused")
	}
}

func TestValueArgsToTree_SetJSON(t *testing.T) {
	tree, err := valueArgsToTree([]string{"--set-json", `a.b={"k.with.dots": {"n": 1}}`})
	if err != nil {
		t.Fatal(err)
	}
	b, ok := nestedMap(tree, "a", "b")
	if !ok {
		t.Fatalf("subtree missing: %+v", tree)
	}
	if _, ok := b["k.with.dots"]; !ok {
		t.Fatalf("dotted key not preserved: %+v", b)
	}
	if _, err := valueArgsToTree([]string{"--set-json", "a.b={not json"}); err == nil {
		t.Fatal("malformed JSON must be refused")
	}
}

func TestPrintStaticAllowlistHint(t *testing.T) {
	var out strings.Builder
	printStaticAllowlistHint(&out, false)
	if out.Len() != 0 {
		t.Fatalf("unsealed install printed a hint: %q", out.String())
	}
	printStaticAllowlistHint(&out, true)
	if !strings.Contains(out.String(), "c8s allowlist digest") || !strings.Contains(out.String(), "--static-allowlist") {
		t.Fatalf("hint missing the pin instructions: %q", out.String())
	}
}

const renderedSeedManifests = `---
# Source: c8s/templates/cds.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: c8s-cds
---
# Source: c8s/templates/cds.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: c8s-cds-allowlist-seed
data:
  allowlist-seed.json: '{"schema":"c8s.allowlist/v1","digests":{"sha256:1111111111111111111111111111111111111111111111111111111111111111":"ghcr.io/x/cds"},"workloads":{}}'
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: c8s-cds
`

func TestSeedFromRenderedManifests(t *testing.T) {
	seed, err := seedFromRenderedManifests([]byte(renderedSeedManifests))
	if err != nil {
		t.Fatalf("seedFromRenderedManifests: %v", err)
	}
	if !strings.Contains(string(seed), `"schema":"c8s.allowlist/v1"`) {
		t.Fatalf("seed = %s", seed)
	}
	if _, err := seedFromRenderedManifests([]byte("kind: Deployment\n")); err == nil {
		t.Fatal("a stream with no seed ConfigMap must be refused")
	}
}

func TestAppendNodeSealArgs(t *testing.T) {
	if _, err := appendNodeSealArgs(nil, "", nodeStaticSeedPath); err == nil {
		t.Fatal("node seal without --bootstrap-allowlist must be refused")
	}
	path := filepath.Join(t.TempDir(), "static-allowlist.json")
	if err := os.WriteFile(path, []byte(bootstrapDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	_, digest, err := bootstrapDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	args, err := appendNodeSealArgs(nil, path, nodeStaticSeedPath)
	if err != nil {
		t.Fatalf("appendNodeSealArgs: %v", err)
	}
	tree, err := valueArgsToTree(args)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := stringAtPath(tree, "cds.allowlistSeedHostPath"); v != nodeStaticSeedPath {
		t.Fatalf("cds.allowlistSeedHostPath = %q", v)
	}
	if v, _ := stringAtPath(tree, "cds.staticAllowlistDigest"); v != digest || len(v) != 64 {
		t.Fatalf("cds.staticAllowlistDigest = %q, want %q", v, digest)
	}
}

func TestAppendPodSealArgs(t *testing.T) {
	f := newFakeBin(t)
	// The stub stands in for `helm template`: it prints the chart's CDS
	// manifests, seed ConfigMap included.
	f.tool(t, "helm", "cat <<'MANIFESTS'\n"+renderedSeedManifests+"\nMANIFESTS")
	computed := filepath.Join(t.TempDir(), "computed.yaml")
	if err := os.WriteFile(computed, []byte("cds: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args, err := appendPodSealArgs(context.Background(), nil, "/chart", nil, computed)
	if err != nil {
		t.Fatalf("appendPodSealArgs: %v", err)
	}
	tree, err := valueArgsToTree(args)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := seedFromRenderedManifests([]byte(renderedSeedManifests))
	doc, _ := pkgallowlist.ParseJSON(seed)
	want, _ := doc.CanonicalDigest()
	if v, _ := stringAtPath(tree, "cds.staticAllowlistDigest"); v != hex.EncodeToString(want) {
		t.Fatalf("cds.staticAllowlistDigest = %q, want %x", v, want)
	}
	annotation, _ := stringAtPath(tree, "cds.initDataAnnotation")
	raw, err := initdata.Decode(annotation)
	if err != nil {
		t.Fatalf("decode init-data annotation: %v", err)
	}
	parsed, err := initdata.Parse(raw)
	if err != nil {
		t.Fatalf("parse init-data: %v", err)
	}
	if parsed.Data[initdata.KeyRole] != initdata.RoleCDS || parsed.Data[initdata.KeyCDSAllowlistSeedSHA256] != hex.EncodeToString(want) {
		t.Fatalf("init-data does not launch-commit the sealed digest: %+v", parsed.Data)
	}
	mustContainLine(t, f.calls(t), "helm template c8s /chart --show-only templates/cds.yaml -f "+computed)
}

func TestBootstrapDocument_Errors(t *testing.T) {
	if _, _, err := bootstrapDocument(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing document was accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bootstrapDocument(bad); err == nil {
		t.Fatal("malformed document was accepted")
	}
	if _, err := appendNodeSealArgs(nil, bad, nodeStaticSeedPath); err == nil {
		t.Fatal("node seal over a malformed document was accepted")
	}
}

func TestAppendPodSealArgs_Errors(t *testing.T) {
	computed := filepath.Join(t.TempDir(), "computed.yaml")
	if err := os.WriteFile(computed, []byte("cds: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		helm string
		want string
	}{
		"helm fails": {
			helm: "echo 'Error: chart not found' >&2; exit 1",
			want: "chart not found",
		},
		"seed is not an allowlist": {
			helm: "printf 'kind: ConfigMap\\ndata:\\n  allowlist-seed.json: \"{not json\"\\n'",
			want: "rendered allowlist seed",
		},
		"no seed rendered": {
			helm: "echo 'kind: Deployment'",
			want: "no allowlist seed ConfigMap",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeBin(t)
			f.tool(t, "helm", tc.helm)
			_, err := appendPodSealArgs(context.Background(), nil, "/chart", nil, computed)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("appendPodSealArgs = %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("helm missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := appendPodSealArgs(context.Background(), nil, "/chart", nil, computed); err == nil {
			t.Fatal("a missing helm binary was accepted")
		}
	})
}
