package allowlist

import (
	"bytes"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestDiffAllowlistsWorkloads(t *testing.T) {
	mk := func(argv string) pkgallowlist.Container {
		return pkgallowlist.Container{
			Digest:  mustDigest(t, digB),
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{argv}},
			Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
		}
	}
	live := &pkgallowlist.Allowlist{
		Schema:  pkgallowlist.Schema,
		Digests: map[string]string{digA: "img"},
		Workloads: map[string]pkgallowlist.Workload{
			"web":  {Containers: []pkgallowlist.Container{mk("/old")}},
			"gone": {Containers: []pkgallowlist.Container{{Digest: mustDigest(t, digC)}}},
		},
	}
	desired := &pkgallowlist.Allowlist{
		Schema:  pkgallowlist.Schema,
		Digests: map[string]string{digA: "img", digD: "img2"},
		Workloads: map[string]pkgallowlist.Workload{
			"web": {Containers: []pkgallowlist.Container{mk("/new")}},
			"new": {Containers: []pkgallowlist.Container{{Digest: mustDigest(t, digD)}}},
		},
	}

	d := diffAllowlists(live, desired)
	if d.empty() {
		t.Fatal("expected differences")
	}
	if d.Floor.Added[digD] != "img2" {
		t.Fatalf("floor added = %#v", d.Floor.Added)
	}
	if len(d.WorkloadsAdded) != 1 || d.WorkloadsAdded[0] != "new" {
		t.Fatalf("workloadsAdded = %#v", d.WorkloadsAdded)
	}
	if len(d.WorkloadsRemoved) != 1 || d.WorkloadsRemoved[0] != "gone" {
		t.Fatalf("workloadsRemoved = %#v", d.WorkloadsRemoved)
	}
	web, ok := d.WorkloadsChanged["web"]
	if !ok || len(web.Changed) != 1 {
		t.Fatalf("web changed = %#v", web)
	}
	if web.Changed[0].Digest != digB || web.Changed[0].From == web.Changed[0].To {
		t.Fatalf("web container change = %#v", web.Changed[0])
	}
}

func TestMultisetSubRespectsMultiplicity(t *testing.T) {
	got := multisetSub([]string{"x", "x", "y"}, []string{"x"})
	if len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Fatalf("multisetSub = %v, want [x y]", got)
	}
	if got := multisetSub([]string{"x", "x"}, []string{"x", "x"}); len(got) != 0 {
		t.Fatalf("full overlap must subtract to empty, got %v", got)
	}
}

func TestComputeDiffIgnoresIdenticalEntries(t *testing.T) {
	current := map[string]string{digA: "same", digB: "old"}
	desired := map[string]string{digA: "same", digB: "new"}

	d := computeDiff(current, desired)
	if len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatalf("added/removed = %#v / %#v", d.Added, d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[digB].From != "old" || d.Changed[digB].To != "new" {
		t.Fatalf("changed = %#v", d.Changed)
	}
	if _, ok := d.Changed[digA]; ok {
		t.Fatal("an identical entry must not be reported as changed")
	}
}

func TestPrintDiffTextSectionPlaceholders(t *testing.T) {
	mk := func(argv string) pkgallowlist.Container {
		return pkgallowlist.Container{
			Digest:  mustDigest(t, digB),
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{argv}},
			Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
		}
	}
	base := func(ctr pkgallowlist.Container, digests map[string]string) *pkgallowlist.Allowlist {
		return &pkgallowlist.Allowlist{
			Schema:    pkgallowlist.Schema,
			Digests:   digests,
			Workloads: map[string]pkgallowlist.Workload{"web": {Containers: []pkgallowlist.Container{ctr}}},
		}
	}

	t.Run("floor change only", func(t *testing.T) {
		live := base(mk("/app"), map[string]string{digA: "img"})
		desired := base(mk("/app"), map[string]string{digA: "img", digD: "img2"})
		var buf bytes.Buffer
		if err := printDiff(&buf, "text", diffAllowlists(live, desired)); err != nil {
			t.Fatalf("printDiff: %v", err)
		}
		want := "floor:\n+ " + digD + "  img2\nworkloads:\n  (no changes)\n"
		if buf.String() != want {
			t.Fatalf("printDiff output:\n%s\nwant:\n%s", buf.String(), want)
		}
	})

	t.Run("workload change only", func(t *testing.T) {
		live := base(mk("/old"), map[string]string{digA: "img"})
		desired := base(mk("/new"), map[string]string{digA: "img"})
		var buf bytes.Buffer
		if err := printDiff(&buf, "text", diffAllowlists(live, desired)); err != nil {
			t.Fatalf("printDiff: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "floor:\n  (no changes)\n") {
			t.Fatalf("missing floor placeholder:\n%s", out)
		}
		if strings.Contains(out, "workloads:\n  (no changes)") {
			t.Fatalf("changed workloads must not print the placeholder:\n%s", out)
		}
		if !strings.Contains(out, "~ web") {
			t.Fatalf("missing changed workload line:\n%s", out)
		}
	})
}
