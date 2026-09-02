package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
