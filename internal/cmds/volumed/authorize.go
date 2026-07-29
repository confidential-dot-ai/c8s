package volumed

import (
	"context"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Inventory reports what a sandbox has run. On node-CVM this is
// nri-image-policy, the component that admitted those containers.
type Inventory interface {
	FetchSandbox(ctx context.Context, sandboxID string) (workloadclaims.SandboxDigestsResponse, error)
}

// Policy supplies the current allowlist.
type Policy interface {
	Allowlist() (*pkgallowlist.Allowlist, error)
}

// Authorizer decides whether a sandbox may open the volume keyed at a store
// path.
//
// This repeats a decision CDS already made when it released the blob, and that
// is the point. The caller hands this daemon a key, a device name and a
// geometry; without its own check the first open of any name would be
// authorized by nothing but possession of a blob, and the daemon performs
// privileged device-mapper and mount work on the strength of it.
type Authorizer struct {
	Inventory Inventory
	Policy    Policy
}

// Authorize refuses unless the sandbox's admitted container set matches exactly
// one workload entry, and that entry's grant covers path for reading.
//
// Read only: a volume key is delivered to a read-only device, so a write grant
// says nothing about whether this sandbox may see the plaintext.
func (a Authorizer) Authorize(ctx context.Context, sandboxID, path string) error {
	if a.Inventory == nil || a.Policy == nil {
		return fmt.Errorf("volumed: authorizer is not configured")
	}
	if sandboxID == "" {
		return fmt.Errorf("volumed: no sandbox for the calling process")
	}
	canonical, err := pkgallowlist.CanonicalSecretPath(path)
	if err != nil {
		return fmt.Errorf("volumed: %w", err)
	}

	al, err := a.Policy.Allowlist()
	if err != nil {
		return fmt.Errorf("volumed: load allowlist: %w", err)
	}
	containers, err := a.workloadContainers(ctx, al, sandboxID)
	if err != nil {
		return err
	}
	name, workload, err := al.MatchWorkload(containers)
	if err != nil {
		return fmt.Errorf("volumed: sandbox %s: %w", sandboxID, err)
	}
	if !workload.Secrets.Allows(canonical, pkgallowlist.OpRead) {
		return fmt.Errorf("volumed: workload %q holds no read grant for %s", name, canonical)
	}
	return nil
}

// workloadContainers asks the inventory what the sandbox has run and removes
// c8s's own injected containers, so a workload entry never has to enumerate
// them. Mirrors the drop set CDS applies at release (docs/secrets.md).
func (a Authorizer) workloadContainers(ctx context.Context, al *pkgallowlist.Allowlist, sandboxID string) ([]pkgallowlist.RunningContainer, error) {
	resp, err := a.Inventory.FetchSandbox(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("volumed: resolve sandbox containers: %w", err)
	}
	reported, err := resp.RequireContainers()
	if err != nil {
		return nil, fmt.Errorf("volumed: %w", err)
	}
	out := make([]pkgallowlist.RunningContainer, 0, len(reported))
	for _, c := range reported {
		if isInjected(al, c) {
			continue
		}
		out = append(out, pkgallowlist.RunningContainer{Digest: c.Digest, Argv: c.Argv})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("volumed: sandbox %s reports no workload containers", sandboxID)
	}
	return out, nil
}

// isInjected reports whether a reported container is one c8s injected: an
// allowlist floor digest AND an entrypoint c8s injects. Floor membership alone
// would let a pod add busybox — also a floor entry — and have it ignored.
func isInjected(al *pkgallowlist.Allowlist, c workloadclaims.SandboxContainer) bool {
	if len(c.Argv) == 0 {
		return false
	}
	if _, floor := al.Digests[c.Digest]; !floor {
		return false
	}
	return slices.Contains(secrets.InjectedEntrypoints, c.Argv[0])
}
