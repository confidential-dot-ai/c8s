//go:build !c8s_node

package main

import (
	"context"
	"strings"
	"testing"
)

func TestPreflightMeshDatapath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		agents string
		want   string
	}{
		{"cilium label", `{"items":[{"spec":{"template":{"metadata":{"namespace":"kube-system","name":"cilium-a","labels":{"k8s-app":"cilium"}}}}}]}`, "cannot enforce traffic on Cilium"},
		{"renamed hardened agent", `{"items":[{"spec":{"template":{"spec":{"containers":[{"image":"registry.example:5000/rancher/hardened-cilium:v1"}]}}}}]}`, "cannot enforce traffic on Cilium"},
		{"digest agent", `{"items":[{"spec":{"template":{"spec":{"containers":[{"image":"quay.io/cilium/cilium@sha256:abc"}]}}}}]}`, "cannot enforce traffic on Cilium"},
		{"rke2 mirrored agent", `{"items":[{"spec":{"template":{"spec":{"containers":[{"image":"rancher/mirrored-cilium-cilium:v1.19.6"}]}}}}]}`, "cannot enforce traffic on Cilium"},
		{"operator only", `{"items":[{"spec":{"template":{"spec":{"containers":[{"image":"quay.io/cilium/operator-generic:v1"}]}}}}]}`, ""},
		{"canal", `{"items":[{"spec":{"template":{"metadata":{"labels":{"k8s-app":"canal"}}}}}]}`, ""},
		{"invalid response", `invalid`, "decode mesh datapath agents"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBin(t)
			f.tool(t, "kubectl", "cat <<'JSON'\n"+tc.agents+"\nJSON")
			err := preflightMeshDatapath(context.Background(), map[string]any{"ratlsMesh": map[string]any{"enabled": true}})
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("disabled mesh skips inspection", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "exit 1")
		if err := preflightMeshDatapath(context.Background(), map[string]any{"ratlsMesh": map[string]any{"enabled": false}}); err != nil {
			t.Fatal(err)
		}
		if len(f.calls(t)) != 0 {
			t.Fatal("disabled mesh inspected cluster")
		}
	})
	t.Run("inspection fails closed", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "echo forbidden >&2; exit 1")
		if err := preflightMeshDatapath(context.Background(), map[string]any{"ratlsMesh": map[string]any{"enabled": true}}); err == nil || !strings.Contains(err.Error(), "forbidden") {
			t.Fatalf("error must explain failed datapath inspection: %v", err)
		}
	})
}
