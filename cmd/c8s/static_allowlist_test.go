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
