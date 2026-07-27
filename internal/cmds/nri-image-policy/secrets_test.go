package nriimagepolicy

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// grantingAllowlist admits pushDigestA running exactly `/app/serve` and grants
// it a read subtree; the same digest also runs unconstrained under a second
// entry that grants nothing.
func grantingAllowlist(t *testing.T) *allowlist.Allowlist {
	t.Helper()
	al, err := allowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{
		"app":{"containers":[{"digest":"` + pushDigestA + `","command":{"policy":"exact","argv":["/app/serve"]},
		 "args":{"policy":"any"},"paths":{"policy":"allow","read":["/secret/model/**"]}}]},
		"debug":{"containers":[{"digest":"` + pushDigestA + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	if err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	return al
}

// The subject is read from the admission record: the digest off the CRI image
// annotation and the effective argv NRI carries, never from the container.
func TestSecretSubjectFromAdmissionRecord(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, grantingAllowlist(t))
	argv := []string{"/app/serve", "--port=8080"}
	ctr := &api.Container{Id: "c1", Name: "app", Args: argv}

	subj, ok := p.secretSubject(context.Background(), ctr, "registry/repo@"+pushDigestA)
	if !ok {
		t.Fatal("a digest-bearing reference must yield a subject")
	}
	if subj.Digest.String() != pushDigestA {
		t.Fatalf("digest = %q, want %q", subj.Digest, pushDigestA)
	}
	if len(subj.Argv) != len(argv) || subj.Argv[0] != argv[0] {
		t.Fatalf("argv = %v, want the container's effective argv %v", subj.Argv, argv)
	}
}

// An unidentifiable container yields no subject, so a caller fails closed
// rather than authorizing it.
func TestSecretSubjectFailsClosed(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, grantingAllowlist(t))
	ctr := &api.Container{Id: "c1", Name: "app"}

	if _, ok := p.secretSubject(context.Background(), ctr, ""); ok {
		t.Fatal("a container with no image reference must yield no subject")
	}
}

// The grant follows the argv the granting entry pins. The same digest admitted
// through the permissive entry holds nothing — admission and entitlement must
// not come from different entries.
func TestGrantsFollowTheAdmittedArgv(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, grantingAllowlist(t))
	idx := p.policy.current().index
	imageRef := "registry/repo@" + pushDigestA

	serve, ok := p.secretSubject(context.Background(), &api.Container{Args: []string{"/app/serve"}}, imageRef)
	if !ok {
		t.Fatal("subject expected")
	}
	if g := idx.PathGrants(serve.Digest.String(), serve.Argv); g.Policy != allowlist.PolicyAllow || len(g.Read) != 1 {
		t.Fatalf("pinned argv grants = %+v, want one read glob", g)
	}

	shell, _ := p.secretSubject(context.Background(), &api.Container{Args: []string{"/bin/sh", "-c", "cat /secret/model/key"}}, imageRef)
	if g := idx.PathGrants(shell.Digest.String(), shell.Argv); g.Policy != allowlist.PolicyDeny {
		t.Fatalf("argv admitted only by the permissive entry grants = %+v, want deny", g)
	}
}

// recordGrants must never block or fail the create path, whatever it finds.
func TestRecordGrantsIsSideEffectFree(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, grantingAllowlist(t))
	pod := &api.PodSandbox{Id: "s1", Name: "pod", Namespace: "default"}

	for _, ctr := range []*api.Container{
		{Id: "granted", Name: "app", Args: []string{"/app/serve"}},
		{Id: "ungranted", Name: "app", Args: []string{"/bin/sh"}},
		{Id: "unidentified", Name: "app"},
	} {
		ref := "registry/repo@" + pushDigestA
		if ctr.Id == "unidentified" {
			ref = ""
		}
		p.recordGrants(context.Background(), pod, ctr, ref)
	}
}

// A tag-form reference resolves through containerd, which returns a bare
// sha256:<hex>. Feeding that back through extractDigest (which needs an @)
// yielded "" and cost the pod its whole workload claim.
func TestResolveDigestKeepsPinnedDigest(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, grantingAllowlist(t))

	got, err := p.resolveDigest(context.Background(), "registry/repo@"+pushDigestA)
	if err != nil || got != pushDigestA {
		t.Fatalf("resolveDigest = %q, %v — want the pinned digest", got, err)
	}
	if got, err := p.resolveDigest(context.Background(), ""); err != nil || got != "" {
		t.Fatalf("empty reference = %q, %v — want an empty digest and no error", got, err)
	}
}
