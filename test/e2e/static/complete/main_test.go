package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	appDigest   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	floorDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dropDigest  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func str(s string) *string { return &s }

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// rendered is the shape `render --sealed` leaves behind: an unprivileged
// workload whose nodeState bind has no review, and two floor entries pinned
// to their image-config argv with an empty review.
func rendered(t *testing.T) []byte {
	t.Helper()
	app := allowlist.Container{
		Digest:  mustDigest(t, appDigest),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/app"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
		Env:     allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Names: []string{"PATH"}, Values: map[string]allowlist.EnvValue{"PATH": {Value: str("/bin")}}},
		Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Destinations: []string{"/etc/hosts", "/run/confai"}, Rules: map[string]allowlist.MountRule{
			"/etc/hosts":  {Source: allowlist.SourcePlatform},
			"/run/confai": {Source: allowlist.SourceNodeState},
		}},
	}
	floor := func(d string) allowlist.Container {
		return allowlist.Container{
			Digest:     mustDigest(t, d),
			Command:    allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/agent"}},
			Args:       allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
			Env:        allowlist.EnvPolicy{Policy: allowlist.PolicyAny},
			Mounts:     allowlist.MountPolicy{Policy: allowlist.PolicyAny},
			Privileges: &allowlist.Privileges{},
		}
	}
	al := allowlist.Allowlist{
		Schema:  allowlist.Schema,
		Digests: map[string]string{},
		Workloads: map[string]allowlist.Workload{
			"app":          {Containers: []allowlist.Container{app}},
			"system-agent": {Containers: []allowlist.Container{floor(floorDigest)}},
			"system-spare": {Containers: []allowlist.Container{floor(dropDigest)}},
		},
	}
	doc, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func fullReviews() Reviews {
	return Reviews{
		Entries: map[string]EntryReview{"app": {Mounts: map[string]string{"/run/confai": "dials the node verifier"}}},
		Floor: map[string]FloorReview{"system-agent": {
			// Unsorted on purpose: the output must be the normalized form.
			Privileges: allowlist.Privileges{Privileged: true, HostNamespaces: []string{"pid", "net"}, HostPaths: []string{"/sys/fs/bpf", "/proc"}, Review: "node TCB"},
			Argv:       "any",
		}},
		Drop: []string{"system-spare"},
	}
}

func TestComplete(t *testing.T) {
	doc := rendered(t)
	out, err := complete(doc, fullReviews())
	if err != nil {
		t.Fatalf("complete() error = %v", err)
	}
	if err := allowlist.LintSealed(out); err != nil {
		t.Fatalf("LintSealed(complete()) = %v, want nil", err)
	}
	al, err := allowlist.ParseJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := al.Workloads["system-spare"]; ok {
		t.Errorf("complete() kept dropped entry system-spare")
	}
	agent := al.Workloads["system-agent"].Containers[0]
	if agent.Command.Policy != allowlist.PolicyAny || agent.Args.Policy != allowlist.PolicyAny {
		t.Errorf("system-agent argv = %s/%s, want any/any", agent.Command.Policy, agent.Args.Policy)
	}
	if !agent.Privileges.Privileged || agent.Privileges.Review != "node TCB" {
		t.Errorf("system-agent privileges = %+v, want the reviewed block", agent.Privileges)
	}
	if got := agent.Privileges.HostNamespaces; len(got) != 2 || got[0] != "net" || got[1] != "pid" {
		t.Errorf("system-agent hostNamespaces = %v, want the sorted [net pid]", got)
	}
	if got := al.Workloads["app"].Containers[0].Mounts.Rules["/run/confai"].Review; got != "dials the node verifier" {
		t.Errorf("app /run/confai review = %q, want the reviewed string", got)
	}
}

func TestCompleteErrors(t *testing.T) {
	cases := []struct {
		name string
		edit func(r *Reviews)
		want string
	}{
		{"unreviewed floor entry", func(r *Reviews) { delete(r.Floor, "system-agent") }, `floor entry "system-agent" is neither reviewed`},
		{"unknown drop", func(r *Reviews) { r.Drop = append(r.Drop, "system-gone") }, `drop: entry "system-gone" is not in the document`},
		{"unknown floor", func(r *Reviews) { r.Floor["system-gone"] = r.Floor["system-agent"] }, `floor: entry "system-gone" is not in the document`},
		{"unknown entry", func(r *Reviews) { r.Entries["gone"] = EntryReview{Privileges: "x"} }, `entries: entry "gone" is not in the document`},
		{"privileges review without a slot", func(r *Reviews) { r.Entries["app"] = EntryReview{Privileges: "x"} }, `no container has a privileges block`},
		{"mount review without a slot", func(r *Reviews) { r.Entries["app"] = EntryReview{Mounts: map[string]string{"/etc/hosts": "x"}} }, `no container binds a pvc or nodeState source`},
		{"bad argv policy", func(r *Reviews) {
			fr := r.Floor["system-agent"]
			fr.Argv = "exact"
			r.Floor["system-agent"] = fr
		}, `argv must be "any" or empty`},
		{"empty floor review fails lint", func(r *Reviews) {
			fr := r.Floor["system-agent"]
			fr.Privileges.Review = ""
			r.Floor["system-agent"] = fr
		}, `privileges.review is empty`},
		{"missing mount review fails lint", func(r *Reviews) { delete(r.Entries, "app") }, `nodeState bind without a review`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fullReviews()
			tc.edit(&r)
			_, err := complete(rendered(t), r)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("complete() error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestRunReadsFilesAndWritesCanonicalBytes(t *testing.T) {
	dir := t.TempDir()
	docPath := filepath.Join(dir, "rendered.json")
	if err := os.WriteFile(docPath, rendered(t), 0o600); err != nil {
		t.Fatal(err)
	}
	reviewsPath := filepath.Join(dir, "reviews.json")
	reviews := `{"entries":{"app":{"mounts":{"/run/confai":"dials the node verifier"}}},` +
		`"floor":{"system-agent":{"privileges":{"privileged":true,"review":"node TCB"},"argv":"any"}},"drop":["system-spare"]}`
	if err := os.WriteFile(reviewsPath, []byte(reviews), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := run(reviewsPath, docPath, &out); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if strings.HasSuffix(out.String(), "\n") {
		t.Errorf("run() output ends with a newline; the node measures canonical bytes, which carry none")
	}
	if err := allowlist.LintSealed([]byte(out.String())); err != nil {
		t.Errorf("LintSealed(run()) = %v, want nil", err)
	}
}

func TestLoadReviewsRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reviews.json")
	if err := os.WriteFile(path, []byte(`{"entries":{},"floor":{},"drop":[],"extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReviews(path); err == nil || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("loadReviews() error = %v, want an unknown-field error naming extra", err)
	}
}
