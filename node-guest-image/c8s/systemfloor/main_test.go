package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// writeZstdBundle compresses the synthetic bundle the way RKE2 ships its
// airgap images, for tests that go through bundleEntries.
func writeZstdBundle(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(writeSyntheticBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.tar.zst")
	if err := os.WriteFile(path, enc.EncodeAll(raw, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeSyntheticBundle builds a minimal deterministic docker-archive bundle:
// one image, one layer, fixed bytes and zeroed tar metadata.
func writeSyntheticBundle(t *testing.T) string {
	t.Helper()

	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	body := []byte("systemfloor fixture layer\n")
	if err := tw.WriteHeader(&tar.Header{Name: "etc/fixture", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layerDigest := sha256.Sum256(layer.Bytes())

	config := []byte(fmt.Sprintf(
		`{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/bin/fixture"]},"rootfs":{"type":"layers","diff_ids":["sha256:%x"]}}`,
		layerDigest))
	configDigest := sha256.Sum256(config)

	manifest, err := json.Marshal([]map[string]any{{
		"Config":   fmt.Sprintf("blobs/sha256/%x", configDigest),
		"RepoTags": []string{"example.com/library/fixture:1.2.3"},
		"Layers":   []string{fmt.Sprintf("blobs/sha256/%x", layerDigest)},
	}})
	if err != nil {
		t.Fatal(err)
	}

	var bundle bytes.Buffer
	tw = tar.NewWriter(&bundle)
	write := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.json", manifest)
	write(fmt.Sprintf("blobs/sha256/%x", configDigest), config)
	write(fmt.Sprintf("blobs/sha256/%x", layerDigest), layer.Bytes())
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "bundle.tar")
	if err := os.WriteFile(path, bundle.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The golden digest is what the vendored containerd (containerd/v2 in go.mod)
// reconstructs importing this exact bundle. It matches a real containerd
// 2.1.4 daemon's `ctr images import` of the rke2 airgap bundles (26/26), so
// the import digest is stable across that range. A library bump that changes
// the reconstruction breaks here before it silently wedges a node boot.
func TestBundleEntries_MatchesDaemonImport(t *testing.T) {
	f, err := os.Open(writeSyntheticBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, err := importEntries(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %v", entries)
	}
	const want = "sha256:087f0ac20596efe1fa93dad0f2467e5ad1b6f84bb57a3e8d5dd5c196f9708b33"
	if entries[0].digest != want {
		t.Fatalf("import digest = %s, want the daemon-computed %s", entries[0].digest, want)
	}
	if entries[0].ref != "example.com/library/fixture:1.2.3" {
		t.Fatalf("ref = %q", entries[0].ref)
	}
}

func TestManifestEntries_DigestPinnedOnly(t *testing.T) {
	yaml := `
          image: rancher/local-path-provisioner:v0.0.36@sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f
          imagePullPolicy: IfNotPresent
        image: busybox:1.38.0
`
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := manifestEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want exactly the digest-pinned ref, got %v", entries)
	}
	if entries[0].digest != "sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f" {
		t.Fatalf("digest = %q", entries[0].digest)
	}
}

func TestRender_DedupesAliasedDigests(t *testing.T) {
	// Two tags on one manifest (or a bundle/manifest overlap) must not emit a
	// duplicate YAML key.
	out := render([]entry{
		{digest: "sha256:aaa", ref: "example.com/a:1"},
		{digest: "sha256:aaa", ref: "example.com/a:2"},
		{digest: "sha256:bbb", ref: "example.com/b:1"},
	})
	if strings.Count(out, `"sha256:aaa"`) != 1 || strings.Count(out, `"sha256:bbb"`) != 1 {
		t.Fatalf("aliased digest produced duplicate keys:\n%s", out)
	}
}

func TestSplice_ReplacesBetweenMarkers(t *testing.T) {
	template := strings.Join([]string{
		"head",
		"    " + beginMarker,
		"    stale",
		"    " + endMarker,
		"tail",
	}, "\n")
	got, err := splice(template, "    fresh\n")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"head",
		"    " + beginMarker,
		"    fresh",
		"    " + endMarker,
		"tail",
	}, "\n")
	if got != want {
		t.Fatalf("splice =\n%s\nwant\n%s", got, want)
	}
	if _, err := splice("no markers", "x"); err == nil {
		t.Fatal("missing markers must error")
	}
}

// The -floor skeleton carries the config argv the bundle bakes and leaves
// env, mounts and the review empty for the reviewer.
func TestFloorFile_SkeletonFromBundle(t *testing.T) {
	entries, err := bundleEntries(writeZstdBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := entries[0].entrypoint; len(got) != 1 || got[0] != "/bin/fixture" {
		t.Fatalf("bundle entry entrypoint = %v, want [/bin/fixture]", got)
	}
	out, err := floorFile(append(entries, entry{digest: entries[0].digest, ref: "example.com/library/fixture:alias"}))
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "schema": "c8s.system-floor/v1",
  "images": [
    {
      "ref": "example.com/library/fixture:1.2.3",
      "digest": "sha256:087f0ac20596efe1fa93dad0f2467e5ad1b6f84bb57a3e8d5dd5c196f9708b33",
      "entrypoint": [
        "/bin/fixture"
      ],
      "cmd": null,
      "env": {},
      "mounts": {},
      "privileges": {
        "review": ""
      }
    }
  ]
}`
	if string(out) != want {
		t.Fatalf("floorFile =\n%s\nwant\n%s", out, want)
	}
}

func TestRun_WritesFloor(t *testing.T) {
	bundle := writeZstdBundle(t)
	floor := filepath.Join(t.TempDir(), "system-floor.json")
	var stdout bytes.Buffer
	if err := run([]string{"-bundle", bundle, "-floor", floor}, &stdout); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(floor)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"ref": "example.com/library/fixture:1.2.3"`) || !strings.HasSuffix(string(data), "}\n") {
		t.Fatalf("system-floor.json =\n%s", data)
	}
	if !strings.Contains(stdout.String(), `"sha256:087f0ac2`) {
		t.Fatalf("stdout lost the YAML block:\n%s", stdout.String())
	}
}

// Manifest refs have no bundle to read a config from; -floor needs crane.
func TestRun_FloorWithManifestNeedsCrane(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(manifest, []byte("image: rancher/x:1@sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	err := run([]string{"-manifest", manifest, "-floor", filepath.Join(t.TempDir(), "f.json")}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "crane") {
		t.Fatalf("run(-floor with manifest, no crane) = %v, want a crane error", err)
	}
	if err := run([]string{"-manifest", manifest}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run(-manifest without -floor) = %v, want nil (crane not needed)", err)
	}
}
