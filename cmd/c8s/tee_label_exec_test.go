//go:build !c8s_node

package main

import (
	"context"
	"strings"
	"testing"
)

func TestAutoLabelTEENodesExec(t *testing.T) {
	values := map[string]any{"kata": map[string]any{
		"nodeSelector":    map[string]any{},
		"snpNodeSelector": map[string]any{"confidential.ai/sev-snp": "true"},
		"tdxNodeSelector": map[string]any{"confidential.ai/tdx": "true"},
	}}

	t.Run("sev-snp labels the kata node set", func(t *testing.T) {
		f := newFakeBin(t)
		// No node carries the other platform's label; the bulk label runs.
		f.tool(t, "kubectl", "")
		if err := autoLabelTEENodes(context.Background(), values, "sev-snp"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		calls := f.calls(t)
		mustContainLine(t, calls, "kubectl get nodes -l "+tdxHostLabelKey+" -o name")
		mustContainLine(t, calls, "kubectl label nodes -l kubernetes.io/os=linux confidential.ai/sev-snp=true --overwrite")
	})

	t.Run("tdx labels with the tdx key and checks the snp key", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "")
		if err := autoLabelTEENodes(context.Background(), values, "tdx"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		calls := f.calls(t)
		mustContainLine(t, calls, "kubectl get nodes -l "+snpCapabilityNodeLabel+" -o name")
		mustContainLine(t, calls, "kubectl label nodes -l kubernetes.io/os=linux "+tdxHostLabelKey+"=true --overwrite")
	})

	t.Run("other platform label still present refuses", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `case "$*" in
"get nodes -l `+tdxHostLabelKey+` -o name") echo node/node-b ;;
esac`)
		err := autoLabelTEENodes(context.Background(), values, "sev-snp")
		if err == nil {
			t.Fatal("want a refusal while the other platform's label is present")
		}
		for _, want := range []string{"node/node-b", "kubectl label nodes -l " + tdxHostLabelKey + " " + tdxHostLabelKey + "-"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q missing %q", err, want)
			}
		}
		mustNotContainPrefix(t, f.calls(t), "kubectl label")
	})

	t.Run("conflict check failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "exit 1")
		if err := autoLabelTEENodes(context.Background(), values, "sev-snp"); err == nil {
			t.Fatal("want error when the conflict check fails")
		}
	})

	t.Run("label command failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `case "$*" in
"label nodes"*) exit 1 ;;
esac`)
		err := autoLabelTEENodes(context.Background(), values, "sev-snp")
		if err == nil || !strings.Contains(err.Error(), "labelling sev-snp nodes") {
			t.Fatalf("want the labelling failure surfaced, got %v", err)
		}
	})

	t.Run("cleared selector skips all cluster calls", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "")
		cleared := map[string]any{"kata": map[string]any{"snpNodeSelector": map[string]any{}}}
		if err := autoLabelTEENodes(context.Background(), cleared, "sev-snp"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustNotContainPrefix(t, f.calls(t), "kubectl")
	})

	t.Run("malformed kata.nodeSelector errors", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "")
		malformed := map[string]any{"kata": map[string]any{
			"nodeSelector":    map[string]any{"pool": 3},
			"snpNodeSelector": map[string]any{"confidential.ai/sev-snp": "true"},
		}}
		if err := autoLabelTEENodes(context.Background(), malformed, "sev-snp"); err == nil {
			t.Fatal("want error for a non-string kata.nodeSelector value")
		}
	})
}
