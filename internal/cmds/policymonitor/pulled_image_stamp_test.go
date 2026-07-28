//go:build linux

package policymonitor

// Repro + regression tests for the host-forged annotation bypass.
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
	stampAllowedDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	stampEvilDigest    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

func stampTestMonitor(t *testing.T, requireStamp bool) (*monitor, *fakeKiller) {
	t.Helper()
	fk := &fakeKiller{}
	m := &monitor{
		cfg:       &Config{RequirePulledImageStamp: requireStamp},
		logger:    testLogger(t),
		allowlist: &allowlist{digests: map[string]struct{}{stampAllowedDigest: {}}},
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

// TestForgedAnnotationsAreTrustedByLegacyPath documents the vulnerability: a
// host-forged bundle whose image-name is a digest-less tag but whose
// image-id names an allowlisted digest is ALLOWED by the legacy path —
// while the guest could have pulled anything. This is the exploit; it must
// keep passing until the legacy path is removed, to document the hole.
func TestForgedAnnotationsAreTrustedByLegacyPath(t *testing.T) {
	m, fk := stampTestMonitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-name": "attacker.example/malware:latest",
		"io.kubernetes.cri.image-id": "sha256:`+stampAllowedDigest+`"
	}`, "")

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) != 0 {
		t.Fatal("VULNERABILITY DOCUMENTED: forged image-id annotation was trusted — " +
			"host runs arbitrary pulled content under an allowlisted digest")
	}
}

// TestStampedNonAllowlistedPullIsDenied proves the fix: the same
// forged annotations, but with a kata-agent stamp showing the real pull
// reference (a non-allowlisted digest) — the container is killed.
func TestStampedNonAllowlistedPullIsDenied(t *testing.T) {
	m, fk := stampTestMonitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-name": "attacker.example/malware:latest",
		"io.kubernetes.cri.image-id": "sha256:`+stampAllowedDigest+`"
	}`, "attacker.example/malware@sha256:"+stampEvilDigest)

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) == 0 {
		t.Fatal("stamped non-allowlisted pull reference must be denied")
	}
}

// TestStampedTagPullIsDenied: a tag-only stamped pull reference binds
// nothing — fail closed even when the forged annotations look allowlisted.
func TestStampedTagPullIsDenied(t *testing.T) {
	m, fk := stampTestMonitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-name": "attacker.example/malware:latest",
		"io.kubernetes.cri.image-id": "sha256:`+stampAllowedDigest+`"
	}`, "attacker.example/malware:latest")

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) == 0 {
		t.Fatal("digest-less stamped pull reference must be denied (no content binding)")
	}
}

// TestStampedAllowlistedPullIsAllowed: honest digest-pinned pull of an
// allowlisted image passes.
func TestStampedAllowlistedPullIsAllowed(t *testing.T) {
	m, fk := stampTestMonitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-name": "registry.example/app@sha256:`+stampAllowedDigest+`"
	}`, "registry.example/app@sha256:"+stampAllowedDigest)

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) != 0 {
		t.Fatal("stamped allowlisted pull must be allowed")
	}
}

// TestUnreadableStampFailsClosed: a stamp path that exists but cannot be
// read (here: a directory) must deny, not fall back to the forgeable
// legacy annotation path.
func TestUnreadableStampFailsClosed(t *testing.T) {
	m, fk := stampTestMonitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-id": "sha256:`+stampAllowedDigest+`"
	}`, "")
	if err := os.Mkdir(filepath.Join(dir, pulledImageStampName), 0o755); err != nil {
		t.Fatal(err)
	}

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) == 0 {
		t.Fatal("unreadable stamp must fail closed, not fall back to host-authored annotations")
	}
}

// TestOversizedStampFailsClosed: a stamp larger than any real image
// reference is not a stamp the agent wrote; deny.
func TestOversizedStampFailsClosed(t *testing.T) {
	m, fk := stampTestMonitor(t, false)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-id": "sha256:`+stampAllowedDigest+`"
	}`, "")
	if err := os.WriteFile(filepath.Join(dir, pulledImageStampName),
		make([]byte, maxPulledImageStampSize+1), 0o644); err != nil {
		t.Fatal(err)
	}

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) == 0 {
		t.Fatal("oversized stamp must fail closed")
	}
}

// TestRequireStampAllowlistedStampAllowed: under fail-closed mode an
// honest digest-pinned pull of an allowlisted image still passes (the
// flag must not break honest workloads).
func TestRequireStampAllowlistedStampAllowed(t *testing.T) {
	m, fk := stampTestMonitor(t, true)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-name": "registry.example/app@sha256:`+stampAllowedDigest+`"
	}`, "registry.example/app@sha256:"+stampAllowedDigest)

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) != 0 {
		t.Fatal("require-pulled-image-stamp must allow an allowlisted digest-pinned stamp")
	}
}

// TestRequireStampFailsClosed: with --require-pulled-image-stamp, a
// bundle without any stamp is denied even if its (forgeable) annotations
// name an allowlisted digest.
func TestRequireStampFailsClosed(t *testing.T) {
	m, fk := stampTestMonitor(t, true)
	dir := writeBundle(t, `{
		"io.kubernetes.cri.image-id": "sha256:`+stampAllowedDigest+`"
	}`, "")

	m.handleNewContainer(context.Background(), dir)
	if len(fk.snapshot()) == 0 {
		t.Fatal("require-pulled-image-stamp must deny stamp-less bundles")
	}
}
