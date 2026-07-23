//go:build linux

package policymonitor

// RT-003 repro + regression test (docs/security/RT-003-policy-monitor-host-annotations.md).
//
// The vulnerability: policy-monitor's allowlist decision consumed
// host-authored OCI annotations (io.kubernetes.cri.image-id et al.), which
// the adversarial host can forge to name any allowlisted digest while the
// guest pulls something else — a full bypass of the in-guest enforcer.
// The fix: decide on the kata-agent-stamped pull reference when present,
// deny digest-less stamps, and optionally fail closed without a stamp.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const (
	rt003AllowedDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	rt003EvilDigest    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

func rt003Monitor(t *testing.T, requireStamp bool) (*monitor, *fakeKiller) {
	t.Helper()
	fk := &fakeKiller{}
	m := &monitor{
		cfg:       &Config{RequirePulledImageStamp: requireStamp},
		logger:    testLogger(t),
		allowlist: &allowlist{digests: map[string]struct{}{rt003AllowedDigest: {}}},
		killer:    fk,
	}
	return m, fk
}

// writeBundle materializes a fake kata bundle: config.json with the given
// annotations, plus an optional pulled-image stamp file.
func writeBundle(t *testing.T, annotationsJSON string, stamp string) string {
	t.Helper()
	dir := t.TempDir()
	cidDir := filepath.Join(dir, "evilcid")
	if err := os.MkdirAll(cidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := `{"annotations":` + annotationsJSON + `}`
	if err := os.WriteFile(filepath.Join(cidDir, "config.json"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if stamp != "" {
		if err := os.WriteFile(filepath.Join(cidDir, pulledImageStampName), []byte(stamp), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return cidDir
}

// TestRT003ForgedAnnotationsAreTrusted documents the vulnerability: a
// host-forged bundle whose image-name is a digest-less tag but whose
// image-id names an allowlisted digest is ALLOWED by the legacy path —
// while the guest could have pulled anything. This is the exploit; it must
// keep passing until the legacy path is removed, to document the hole.
func TestRT003ForgedAnnotationsAreTrusted(t *testing.T) {
	m, fk := rt003Monitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-name": "attacker.example/malware:latest",
		"io.kubernetes.cri.image-id": "sha256:`+rt003AllowedDigest+`"
	}`, "")

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) != 0 {
		t.Fatal("VULNERABILITY DOCUMENTED: forged image-id annotation was trusted — " +
			"host runs arbitrary pulled content under an allowlisted digest")
	}
}

// TestRT003StampedNonAllowlistedPullIsDenied proves the fix: the same
// forged annotations, but with a kata-agent stamp showing the real pull
// reference (a non-allowlisted digest) — the container is killed.
func TestRT003StampedNonAllowlistedPullIsDenied(t *testing.T) {
	m, fk := rt003Monitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-name": "attacker.example/malware:latest",
		"io.kubernetes.cri.image-id": "sha256:`+rt003AllowedDigest+`"
	}`, "attacker.example/malware@sha256:"+rt003EvilDigest)

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) == 0 {
		t.Fatal("stamped non-allowlisted pull reference must be denied")
	}
}

// TestRT003StampedTagPullIsDenied: a tag-only stamped pull reference binds
// nothing — fail closed even when the forged annotations look allowlisted.
func TestRT003StampedTagPullIsDenied(t *testing.T) {
	m, fk := rt003Monitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-name": "attacker.example/malware:latest",
		"io.kubernetes.cri.image-id": "sha256:`+rt003AllowedDigest+`"
	}`, "attacker.example/malware:latest")

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) == 0 {
		t.Fatal("digest-less stamped pull reference must be denied (no content binding)")
	}
}

// TestRT003StampedAllowlistedPullIsAllowed: honest digest-pinned pull of an
// allowlisted image passes.
func TestRT003StampedAllowlistedPullIsAllowed(t *testing.T) {
	m, fk := rt003Monitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-name": "registry.example/app@sha256:`+rt003AllowedDigest+`"
	}`, "registry.example/app@sha256:"+rt003AllowedDigest)

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) != 0 {
		t.Fatal("stamped allowlisted pull must be allowed")
	}
}

// TestRT003RequireStampFailsClosed: with --require-pulled-image-stamp, a
// bundle without any stamp is denied even if its (forgeable) annotations
// name an allowlisted digest.
func TestRT003RequireStampFailsClosed(t *testing.T) {
	m, fk := rt003Monitor(t, true)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-id": "sha256:`+rt003AllowedDigest+`"
	}`, "")

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) == 0 {
		t.Fatal("require-pulled-image-stamp must deny stamp-less bundles")
	}
}
