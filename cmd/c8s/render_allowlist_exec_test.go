//go:build !c8s_node

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// renderAllowlistHelmBody stands in for both helm calls the command makes:
// `helm show values` for the component set and `helm template` for the seed.
const renderAllowlistHelmBody = `case "$1" in
show) /bin/cat "$3/values.yaml" ;;
template) /bin/cat <<'MANIFESTS'
` + renderedSeedManifests + `
MANIFESTS
;;
esac`

func TestRenderAllowlistEmitsCanonicalDocument(t *testing.T) {
	f := newFakeBin(t)
	f.tool(t, "helm", renderAllowlistHelmBody)
	f.tool(t, "crane", "echo "+testDigest)
	bootstrap := filepath.Join(t.TempDir(), "workloads.json")
	if err := os.WriteFile(bootstrap, []byte(bootstrapDoc), 0o600); err != nil {
		t.Fatal(err)
	}

	var err error
	out := captureStdout(t, func() {
		err = runC8s(t, "render-allowlist", "--cvm-mode=node", "--image-tag=v1", "--kube-version=1.32.0", "--bootstrap-allowlist", bootstrap)
	})
	if err != nil {
		t.Fatalf("render-allowlist: %v", err)
	}
	doc, err := pkgallowlist.ParseJSON([]byte(out))
	if err != nil {
		t.Fatalf("output is not an allowlist document: %v\n%s", err, out)
	}
	canonical, err := doc.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != string(canonical) {
		t.Fatalf("output is not the canonical encoding:\n%s", out)
	}
	calls := f.calls(t)
	var templated, versioned bool
	for _, c := range calls {
		templated = templated || strings.HasPrefix(c, "helm template c8s ")
		versioned = versioned || strings.Contains(c, " --kube-version 1.32.0 ")
	}
	if !templated {
		t.Errorf("helm template was not run:\n%s", strings.Join(calls, "\n"))
	}
	if !versioned {
		t.Errorf("helm template did not use the requested Kubernetes version:\n%s", strings.Join(calls, "\n"))
	}
}

func TestRenderAllowlistRequiresCvmModeAndHelm(t *testing.T) {
	newFakeBin(t)
	if err := runC8s(t, "render-allowlist", "--cvm-mode=node"); err == nil || !strings.Contains(err.Error(), "helm CLI not found") {
		t.Fatalf("want a helm-not-found error, got %v", err)
	}
	f := newFakeBin(t)
	f.tool(t, "helm", renderAllowlistHelmBody)
	if err := runC8s(t, "render-allowlist"); err == nil {
		t.Fatal("want error without --cvm-mode")
	}
}
