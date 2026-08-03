//go:build !c8s_node

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// singleLabelPair feeds the auto-labeller: only the chart's single-pair
// default shape may be applied automatically; the opt-out ({}), multi-pair,
// and non-string shapes must report ok=false so the labeller skips instead of
// guessing which label the operator owns.
func TestSingleLabelPair(t *testing.T) {
	tests := []struct {
		name   string
		sel    map[string]any
		wantK  string
		wantV  string
		wantOK bool
	}{
		{name: "chart default", sel: map[string]any{"confidential.ai/sev-snp": "true"}, wantK: "confidential.ai/sev-snp", wantV: "true", wantOK: true},
		{name: "empty is the opt-out", sel: map[string]any{}, wantOK: false},
		{name: "nil is the opt-out", sel: nil, wantOK: false},
		{name: "multi-pair is operator-owned", sel: map[string]any{"a": "1", "b": "2"}, wantOK: false},
		{name: "non-string value", sel: map[string]any{"a": true}, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, v, ok := singleLabelPair(tt.sel)
			if k != tt.wantK || v != tt.wantV || ok != tt.wantOK {
				t.Fatalf("singleLabelPair(%v) = (%q, %q, %t), want (%q, %q, %t)", tt.sel, k, v, ok, tt.wantK, tt.wantV, tt.wantOK)
			}
		})
	}
}

// planTEELabels maps the declared --hardware-platform to the label to apply
// and the other platform's label whose presence aborts the install. The two
// c8s-owned keys are a fixed contract with templates/kata.yaml (RC
// nodeSelectors) and the uninstall sweep — these tests pin the mapping.
func TestPlanTEELabels(t *testing.T) {
	chartDefaults := map[string]any{
		"kata": map[string]any{
			"nodeSelector":    map[string]any{},
			"snpNodeSelector": map[string]any{"confidential.ai/sev-snp": "true"},
			"tdxNodeSelector": map[string]any{"confidential.ai/tdx": "true"},
		},
	}

	t.Run("sev-snp applies the chart selector and conflict-checks the tdx label", func(t *testing.T) {
		plan, ok, err := planTEELabels(chartDefaults, "sev-snp")
		if err != nil || !ok {
			t.Fatalf("planTEELabels = ok=%t err=%v, want ok", ok, err)
		}
		if plan.targetKey != "confidential.ai/sev-snp" || plan.targetValue != "true" {
			t.Errorf("target = %s=%s, want confidential.ai/sev-snp=true", plan.targetKey, plan.targetValue)
		}
		if plan.otherKey != tdxHostLabelKey {
			t.Errorf("otherKey = %q, want %q", plan.otherKey, tdxHostLabelKey)
		}
		if plan.nodeSelector != "kubernetes.io/os=linux" {
			t.Errorf("nodeSelector = %q, want kubernetes.io/os=linux", plan.nodeSelector)
		}
	})

	t.Run("tdx applies the chart selector and conflict-checks the snp label", func(t *testing.T) {
		plan, ok, err := planTEELabels(chartDefaults, "tdx")
		if err != nil || !ok {
			t.Fatalf("planTEELabels = ok=%t err=%v, want ok", ok, err)
		}
		if plan.targetKey != tdxHostLabelKey || plan.targetValue != "true" {
			t.Errorf("target = %s=%s, want %s=true", plan.targetKey, plan.targetValue, tdxHostLabelKey)
		}
		if plan.otherKey != snpCapabilityNodeLabel {
			t.Errorf("otherKey = %q, want %q", plan.otherKey, snpCapabilityNodeLabel)
		}
	})

	t.Run("cleared snpNodeSelector skips labelling on sev-snp", func(t *testing.T) {
		tree := map[string]any{
			"kata": map[string]any{"snpNodeSelector": map[string]any{}},
		}
		if _, ok, err := planTEELabels(tree, "sev-snp"); ok || err != nil {
			t.Fatalf("planTEELabels = ok=%t err=%v, want skip (unrestricted-scheduling opt-out)", ok, err)
		}
	})

	t.Run("cleared tdxNodeSelector skips labelling on tdx", func(t *testing.T) {
		tree := map[string]any{
			"kata": map[string]any{"tdxNodeSelector": map[string]any{}},
		}
		if _, ok, err := planTEELabels(tree, "tdx"); ok || err != nil {
			t.Fatalf("planTEELabels = ok=%t err=%v, want skip (unrestricted-scheduling opt-out)", ok, err)
		}
	})

	t.Run("kata.nodeSelector narrows the labelled node set", func(t *testing.T) {
		tree := map[string]any{
			"kata": map[string]any{
				"nodeSelector":    map[string]any{"pool": "kata"},
				"snpNodeSelector": map[string]any{"confidential.ai/sev-snp": "true"},
			},
		}
		plan, ok, err := planTEELabels(tree, "sev-snp")
		if err != nil || !ok {
			t.Fatalf("planTEELabels = ok=%t err=%v, want ok", ok, err)
		}
		if plan.nodeSelector != "kubernetes.io/os=linux,pool=kata" {
			t.Errorf("nodeSelector = %q, want kubernetes.io/os=linux,pool=kata", plan.nodeSelector)
		}
	})

	t.Run("non-string kata.nodeSelector value errors", func(t *testing.T) {
		tree := map[string]any{
			"kata": map[string]any{
				"nodeSelector":    map[string]any{"pool": 3},
				"snpNodeSelector": map[string]any{"confidential.ai/sev-snp": "true"},
			},
		}
		if _, _, err := planTEELabels(tree, "sev-snp"); err == nil {
			t.Fatal("planTEELabels accepted a non-string kata.nodeSelector value, want error")
		}
	})
}

// valuesFilesSetTEESelector decides whether -f owns the TEE node label. Any -f
// used to disable auto-labelling wholesale, which broke the flow the tls-lb
// host-port preflight itself recommends on RKE2 (`-f` setting
// tlsLb.hostPort.enabled=false): confidential pods then sat Pending with no
// message naming the missing label. Only the platform's own selector counts.
func TestValuesFilesSetTEESelector(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	tlsLB := write("tlslb.yaml", "tlsLb:\n  hostPort:\n    enabled: false\n")
	kataNodes := write("kata-nodes.yaml", "kata:\n  nodeSelector:\n    pool: kata\n")
	snp := write("snp.yaml", "kata:\n  snpNodeSelector:\n    feature.node.kubernetes.io/cpu-security.sev.snp.enabled: \"true\"\n")
	snpCleared := write("snp-cleared.yaml", "kata:\n  snpNodeSelector: {}\n")
	snpNull := write("snp-null.yaml", "kata:\n  snpNodeSelector:\n")
	tdx := write("tdx.yaml", "kata:\n  tdxNodeSelector:\n    nfd/tdx: \"true\"\n")
	empty := write("empty.yaml", "")

	tests := []struct {
		name     string
		files    []string
		platform string
		want     bool
	}{
		{name: "no values files", platform: "sev-snp"},
		{name: "RKE2 tls-lb host-port opt-out does not disown the label", files: []string{tlsLB}, platform: "sev-snp"},
		{name: "kata.nodeSelector only narrows the labelled set", files: []string{kataNodes}, platform: "sev-snp"},
		{name: "empty file", files: []string{empty}, platform: "sev-snp"},
		{name: "custom snpNodeSelector is operator-owned", files: []string{snp}, platform: "sev-snp", want: true},
		{name: "cleared snpNodeSelector is operator-owned", files: []string{snpCleared}, platform: "sev-snp", want: true},
		{name: "explicit null snpNodeSelector is operator-owned", files: []string{snpNull}, platform: "sev-snp", want: true},
		{name: "later file in the list still counts", files: []string{tlsLB, snp}, platform: "sev-snp", want: true},
		{name: "snpNodeSelector says nothing about tdx", files: []string{snp}, platform: "tdx"},
		{name: "tdxNodeSelector is operator-owned on tdx", files: []string{tdx}, platform: "tdx", want: true},
		{name: "tdxNodeSelector says nothing about sev-snp", files: []string{tdx}, platform: "sev-snp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := valuesFilesSetTEESelector(tt.files, tt.platform)
			if err != nil {
				t.Fatalf("valuesFilesSetTEESelector: %v", err)
			}
			if got != tt.want {
				t.Fatalf("valuesFilesSetTEESelector(%v, %q) = %t, want %t", tt.files, tt.platform, got, tt.want)
			}
		})
	}

	t.Run("missing file errors", func(t *testing.T) {
		if _, err := valuesFilesSetTEESelector([]string{filepath.Join(dir, "nope.yaml")}, "sev-snp"); err == nil {
			t.Fatal("missing values file accepted, want error")
		}
	})
	t.Run("malformed yaml errors", func(t *testing.T) {
		bad := write("bad.yaml", "kata: [oops\n")
		if _, err := valuesFilesSetTEESelector([]string{bad}, "sev-snp"); err == nil {
			t.Fatal("malformed values file accepted, want error")
		}
	})
}

// Skipping auto-labelling must be LOUD and actionable: the silent skip is what
// forced an operator to read the source to find the missing label.
func TestReportTEELabelSkipNamesTheKubectlCommand(t *testing.T) {
	var buf bytes.Buffer
	reportTEELabelSkip(&buf, map[string]any{
		"kata": map[string]any{
			"snpNodeSelector": map[string]any{"feature.node.kubernetes.io/cpu-security.sev.snp.enabled": "true"},
		},
	}, "sev-snp")
	got := buf.String()
	for _, want := range []string{
		"kata.snpNodeSelector is set by -f",
		"kubectl label node <node> feature.node.kubernetes.io/cpu-security.sev.snp.enabled=true",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("skip notice missing %q:\n%s", want, got)
		}
	}

	// A cleared selector has no label to name — say that, don't print a
	// kubectl command with an empty selector.
	buf.Reset()
	reportTEELabelSkip(&buf, map[string]any{"kata": map[string]any{"tdxNodeSelector": map[string]any{}}}, "tdx")
	if got := buf.String(); !strings.Contains(got, "unrestricted") || strings.Contains(got, "kubectl label node") {
		t.Fatalf("cleared selector notice = %q, want the unrestricted-scheduling wording and no kubectl command", got)
	}
}
