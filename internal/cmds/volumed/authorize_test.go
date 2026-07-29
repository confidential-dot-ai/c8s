package volumed

import (
	"context"
	"errors"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	appDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	certDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	sandboxID  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	storePath  = "/tenant-a/volumes/weights"
)

type fakeInventory struct {
	containers []workloadclaims.SandboxContainer
	err        error
}

func (f fakeInventory) FetchSandbox(context.Context, string) (workloadclaims.SandboxDigestsResponse, error) {
	if f.err != nil {
		return workloadclaims.SandboxDigestsResponse{}, f.err
	}
	return workloadclaims.SandboxDigestsResponse{Containers: f.containers}, nil
}

type fakePolicy struct {
	al  *pkgallowlist.Allowlist
	err error
}

func (f fakePolicy) Allowlist() (*pkgallowlist.Allowlist, error) { return f.al, f.err }

// allowlistWith builds a document whose single entry declares the app container
// and, optionally, a read grant on storePath. The cert sidecar's digest is in
// the floor, so it is dropped before matching.
func allowlistWith(grant *pkgallowlist.SecretsPolicy) *pkgallowlist.Allowlist {
	return &pkgallowlist.Allowlist{
		Schema:  pkgallowlist.Schema,
		Digests: map[string]string{certDigest: "ghcr.io/confidential-dot-ai/c8s"},
		Workloads: map[string]pkgallowlist.Workload{
			"vllm": {
				Containers: []pkgallowlist.Container{{
					Digest:  mustDigest(appDigest),
					Command: pkgallowlist.ArgvPolicy{Policy: "exact", Argv: []string{"serve"}},
					Args:    pkgallowlist.ArgvPolicy{Policy: "any"},
				}},
				Secrets: grant,
			},
		},
	}
}

func mustDigest(s string) types.Digest {
	d, err := types.ParseDigest(s)
	if err != nil {
		panic(err)
	}
	return d
}

func readGrant(paths ...string) *pkgallowlist.SecretsPolicy {
	return &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: paths}
}

func runningApp() []workloadclaims.SandboxContainer {
	return []workloadclaims.SandboxContainer{{Digest: appDigest, Argv: []string{"serve", "--port", "8000"}}}
}

func authorizerFor(containers []workloadclaims.SandboxContainer, grant *pkgallowlist.SecretsPolicy) Authorizer {
	return Authorizer{
		Inventory: fakeInventory{containers: containers},
		Policy:    fakePolicy{al: allowlistWith(grant)},
	}
}

func TestAuthorizeAllowsGrantedPath(t *testing.T) {
	a := authorizerFor(runningApp(), readGrant(storePath))
	if err := a.Authorize(t.Context(), sandboxID, storePath); err != nil {
		t.Fatalf("refused a granted path: %v", err)
	}
}

func TestAuthorizeRefusesUngrantedPath(t *testing.T) {
	a := authorizerFor(runningApp(), readGrant("/tenant-b/volumes/other"))
	if err := a.Authorize(t.Context(), sandboxID, storePath); err == nil {
		t.Fatal("allowed a path the grant does not cover")
	}
}

func TestAuthorizeRefusesEntryWithNoGrant(t *testing.T) {
	a := authorizerFor(runningApp(), nil)
	if err := a.Authorize(t.Context(), sandboxID, storePath); err == nil {
		t.Fatal("allowed a workload holding no grant")
	}
}

// A volume is mounted read-only, so a write grant says nothing about whether
// this sandbox may see the plaintext.
func TestAuthorizeIgnoresWriteOnlyGrant(t *testing.T) {
	a := authorizerFor(runningApp(), &pkgallowlist.SecretsPolicy{
		Policy: pkgallowlist.PolicyAllow,
		Read:   []string{"/tenant-a/volumes/other"},
		Write:  []string{storePath},
	})
	if err := a.Authorize(t.Context(), sandboxID, storePath); err == nil {
		t.Fatal("a write grant authorized a read")
	}
}

// A pod running anything its entry does not declare matches no entry at all —
// which is what stops a workload adding a container to exfiltrate the plaintext.
func TestAuthorizeRefusesForeignContainer(t *testing.T) {
	containers := append(runningApp(), workloadclaims.SandboxContainer{
		Digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		Argv:   []string{"/bin/sh"},
	})
	a := authorizerFor(containers, readGrant(storePath))
	if err := a.Authorize(t.Context(), sandboxID, storePath); err == nil {
		t.Fatal("matched an entry despite an undeclared container")
	}
}

// c8s's own injected containers are dropped before matching, so an entry never
// enumerates them.
func TestAuthorizeDropsInjectedContainers(t *testing.T) {
	containers := append(runningApp(), workloadclaims.SandboxContainer{
		Digest: certDigest, Argv: []string{"get-cert", "--cds-url=https://cds"},
	}, workloadclaims.SandboxContainer{
		Digest: certDigest, Argv: []string{"get-volume", "--name=weights"},
	})
	a := authorizerFor(containers, readGrant(storePath))
	if err := a.Authorize(t.Context(), sandboxID, storePath); err != nil {
		t.Fatalf("injected containers were not dropped: %v", err)
	}
}

// Floor membership alone is not enough to be dropped: a floor image running
// something c8s does not inject is a workload container.
func TestAuthorizeDoesNotDropFloorImageRunningSomethingElse(t *testing.T) {
	containers := append(runningApp(), workloadclaims.SandboxContainer{
		Digest: certDigest, Argv: []string{"/bin/sh", "-c", "cat /models/*"},
	})
	a := authorizerFor(containers, readGrant(storePath))
	if err := a.Authorize(t.Context(), sandboxID, storePath); err == nil {
		t.Fatal("dropped a floor image that was not running an injected entrypoint")
	}
}

func TestAuthorizeRefusesUnreachableInventory(t *testing.T) {
	a := Authorizer{
		Inventory: fakeInventory{err: errors.New("dial refused")},
		Policy:    fakePolicy{al: allowlistWith(readGrant(storePath))},
	}
	if err := a.Authorize(t.Context(), sandboxID, storePath); err == nil {
		t.Fatal("allowed a release with no inventory answer")
	}
}

func TestAuthorizeRefusesEmptySandboxReport(t *testing.T) {
	a := authorizerFor(nil, readGrant(storePath))
	if err := a.Authorize(t.Context(), sandboxID, storePath); err == nil {
		t.Fatal("allowed a sandbox reporting no containers")
	}
}

func TestAuthorizeRefusesUnloadableAllowlist(t *testing.T) {
	a := Authorizer{
		Inventory: fakeInventory{containers: runningApp()},
		Policy:    fakePolicy{err: errors.New("store closed")},
	}
	if err := a.Authorize(t.Context(), sandboxID, storePath); err == nil {
		t.Fatal("allowed a release with no allowlist")
	}
}

func TestAuthorizeRefusesMalformedInput(t *testing.T) {
	a := authorizerFor(runningApp(), readGrant(storePath))
	if err := a.Authorize(t.Context(), "", storePath); err == nil {
		t.Error("accepted an empty sandbox id")
	}
	for _, p := range []string{"", "tenant-a/volumes", "/tenant-a/../weights", "/tenant-a/volumes/"} {
		if err := a.Authorize(t.Context(), sandboxID, p); err == nil {
			t.Errorf("path %q: accepted", p)
		}
	}
}

func TestAuthorizeRefusesUnconfigured(t *testing.T) {
	if err := (Authorizer{}).Authorize(t.Context(), sandboxID, storePath); err == nil {
		t.Fatal("an unconfigured authorizer allowed a release")
	}
}

// A subtree grant covers paths beneath its base but not the base itself.
func TestAuthorizeHonoursSubtreeGrantSemantics(t *testing.T) {
	a := authorizerFor(runningApp(), readGrant("/tenant-a/volumes/**"))
	if err := a.Authorize(t.Context(), sandboxID, storePath); err != nil {
		t.Fatalf("subtree grant refused a path beneath its base: %v", err)
	}
	if err := a.Authorize(t.Context(), sandboxID, "/tenant-a/volumes"); err == nil {
		t.Fatal("subtree grant covered its own base")
	}
}

func TestAuthorizeErrorsNameTheSandbox(t *testing.T) {
	a := authorizerFor(runningApp(), readGrant("/elsewhere"))
	err := a.Authorize(t.Context(), sandboxID, storePath)
	if err == nil || !strings.Contains(err.Error(), "no read grant") {
		t.Fatalf("got %v, want an error naming the missing grant", err)
	}
}
