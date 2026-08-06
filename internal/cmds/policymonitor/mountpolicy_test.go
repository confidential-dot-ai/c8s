//go:build linux

package policymonitor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	allowlistpkg "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// writeSpec writes a bundle config.json carrying the fields workload policy is
// evaluated against.
func writeSpec(t *testing.T, watchDir, cid string, annotations map[string]string, args, env []string, mounts []ociMount) {
	t.Helper()
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ociSpec{
		Annotations: annotations,
		Process:     &ociProcess{Args: args, Env: env},
		Mounts:      mounts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mountPolicyOverlay(t *testing.T, digest string, destinations []string) *allowlistpkg.Allowlist {
	t.Helper()
	return &allowlistpkg.Allowlist{
		Schema: allowlistpkg.Schema,
		Workloads: map[string]allowlistpkg.Workload{"w": {Containers: []allowlistpkg.Container{{
			Digest:  mustParseDigest(t, digest),
			Command: allowlistpkg.ArgvPolicy{Policy: allowlistpkg.PolicyAny},
			Args:    allowlistpkg.ArgvPolicy{Policy: allowlistpkg.PolicyAny},
			Mounts:  allowlistpkg.MountPolicy{Policy: allowlistpkg.PolicyExact, Destinations: destinations},
		}}}},
	}
}

// The whole point of the policy: the host stages bytes in the sandbox seeding
// directory — a legitimate CopyFile destination, and an allowed mount source —
// then binds them over a path inside an allowlisted image. The digest still
// matches, so only the mount policy can refuse it.
func TestWorkloadMountPolicy(t *testing.T) {
	wl := strings.Repeat("b", 64)
	ann := map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/tenant/app@sha256:" + wl,
	}
	seeded := "/run/kata-containers/shared/containers/pod-abc-cm"
	floor := []string{"sha256:" + strings.Repeat("a", 64)}

	t.Run("declared destinations admitted", func(t *testing.T) {
		m, killer, watchDir := newTestMonitor(t, floor)
		m.overlay.apply(mountPolicyOverlay(t, "sha256:"+wl, []string{"/etc/hosts", "/config"}), 1)
		writeSpec(t, watchDir, "ok", ann, []string{"/serve"}, []string{"PATH=/bin"}, []ociMount{
			{Destination: "/proc", Source: "proc"},
			{Destination: "/etc/hosts", Source: seeded},
			{Destination: "/config", Source: seeded},
		})
		m.handleNewContainer(context.Background(), filepath.Join(watchDir, "ok"))
		if calls := killer.snapshot(); len(calls) != 0 {
			t.Fatalf("declared mounts were refused: %+v", calls)
		}
	})

	t.Run("bind over an image path refused", func(t *testing.T) {
		m, killer, watchDir := newTestMonitor(t, floor)
		m.overlay.apply(mountPolicyOverlay(t, "sha256:"+wl, []string{"/etc/hosts", "/config"}), 1)
		writeSpec(t, watchDir, "shadowed", ann, []string{"/serve"}, nil, []ociMount{
			{Destination: "/etc/hosts", Source: seeded},
			{Destination: "/usr/local/bin/serve", Source: seeded},
		})
		m.handleNewContainer(context.Background(), filepath.Join(watchDir, "shadowed"))
		if calls := killer.snapshot(); len(calls) != 1 {
			t.Fatalf("a bind over an image path was admitted: %+v", calls)
		}
	})

	// Pseudo-filesystem mounts are not binds and carry nothing in, so gating
	// them would only make an operator restate the OCI base set.
	t.Run("pseudo-filesystem mounts are not gated", func(t *testing.T) {
		m, killer, watchDir := newTestMonitor(t, floor)
		m.overlay.apply(mountPolicyOverlay(t, "sha256:"+wl, []string{"/etc/hosts"}), 1)
		writeSpec(t, watchDir, "pseudo", ann, []string{"/serve"}, nil, []ociMount{
			{Destination: "/etc/hosts", Source: seeded},
			{Destination: "/sys/fs/cgroup", Source: "cgroup"},
			{Destination: "/dev/mqueue", Source: "mqueue"},
		})
		m.handleNewContainer(context.Background(), filepath.Join(watchDir, "pseudo"))
		if calls := killer.snapshot(); len(calls) != 0 {
			t.Fatalf("a pseudo-filesystem mount was refused: %+v", calls)
		}
	})

	// A floor digest is admitted on the digest alone, by design — the mount
	// policy only binds digests an entry names.
	t.Run("floor digests stay unconstrained", func(t *testing.T) {
		m, killer, watchDir := newTestMonitor(t, floor)
		m.overlay.apply(mountPolicyOverlay(t, "sha256:"+wl, []string{"/etc/hosts"}), 1)
		writeSpec(t, watchDir, "floored", map[string]string{
			"io.kubernetes.cri.container-type": "container",
			"io.kubernetes.cri.image-name":     "ghcr.io/c8s/get-cert@" + floor[0],
		}, []string{"/get-cert"}, nil, []ociMount{{Destination: "/anywhere", Source: seeded}})
		m.handleNewContainer(context.Background(), filepath.Join(watchDir, "floored"))
		if calls := killer.snapshot(); len(calls) != 0 {
			t.Fatalf("a floor digest was gated on mounts: %+v", calls)
		}
	})
}

func TestEnvNamesDropValues(t *testing.T) {
	got := envNames([]string{"PATH=/bin", "TOKEN=s3cret", "NOEQUALS"})
	if strings.Join(got, ",") != "PATH,TOKEN" {
		t.Errorf("envNames = %v, want the names of the two NAME=value entries", got)
	}
	for _, n := range got {
		if strings.Contains(n, "s3cret") {
			t.Fatal("a value leaked into the observation policy matches on")
		}
	}
}

func TestBindMountDestinationsIgnoresPseudoFilesystems(t *testing.T) {
	got := bindMountDestinations([]ociMount{
		{Destination: "/proc", Source: "proc"},
		{Destination: "/data", Source: "/run/kata-containers/sandbox/storage/x"},
		{Destination: "/dev/shm", Source: "/run/kata-containers/sandbox/shm"},
	})
	if strings.Join(got, ",") != "/data,/dev/shm" {
		t.Errorf("bindMountDestinations = %v, want only the bind destinations", got)
	}
}
