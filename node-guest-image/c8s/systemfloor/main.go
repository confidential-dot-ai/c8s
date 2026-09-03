// Command systemfloor regenerates the RKE2 system-image floor in
// image-policy.yaml.in: the always_allow entries that admit the node's baked
// system components (rke2 static pods, Cilium, CoreDNS, local-path-storage).
//
// The digests are the ones containerd computes when it IMPORTS the airgap
// bundles at rke2 boot, not the registry's: the bundles are docker-archive
// tarballs and the import rebuilds each manifest, so the digest only exists
// in the store. This tool runs the same code the daemon's import does
// (images/archive.ImportIndex, vendored with the c8s module) against a
// scratch content store, so the floor matches what the plugin resolves at
// runtime.
//
//	systemfloor -bundle rke2-images-core.linux-amd64.tar.zst \
//	    -bundle rke2-images-cilium.linux-amd64.tar.zst \
//	    -manifest .../server/manifests/local-path-storage.yaml \
//	    -manifest .../server/manifests/nvidia-device-plugin.yaml
//
// prints the always_allow block. With -template pointing at
// image-policy.yaml.in, -check reports drift and -write rewrites the block
// between the BEGIN/END markers in place. -floor writes system-floor.json,
// the rule skeleton `c8s allowlist render --sealed --system-floor` consumes:
// one image per entry with the argv its config bakes, and empty env, mounts
// and review for the reviewer to complete.
package main

import (
	"context"
	_ "crypto/sha256" // go-digest's canonical algorithm
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/archive"
	localcontent "github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// entry is one floor line: a digest admitted under an image reference, with
// the argv the image config bakes (known for bundle images; fetched for
// manifest refs only when -floor asks for it).
type entry struct {
	digest     string
	ref        string
	entrypoint []string
	cmd        []string
}

// bundleEntries imports a docker-archive airgap bundle the way containerd's
// import does and returns one entry per named image: the rebuilt manifest
// digest under its normalized repo:tag name.
func bundleEntries(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("zstd decoder: %w", err)
	}
	defer zr.Close()

	entries, err := importEntries(zr)
	if err != nil {
		return nil, fmt.Errorf("import %s: %w", filepath.Base(path), err)
	}
	return entries, nil
}

// importEntries runs containerd's docker-archive import over a tar stream
// against a scratch content store and reads the resulting index.
func importEntries(r io.Reader) ([]entry, error) {
	root, err := os.MkdirTemp("", "systemfloor-content")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	store, err := localcontent.NewStore(root)
	if err != nil {
		return nil, fmt.Errorf("content store: %w", err)
	}

	idxDesc, err := archive.ImportIndex(context.Background(), store, r)
	if err != nil {
		return nil, err
	}

	idxJSON, err := content.ReadBlob(context.Background(), store, idxDesc)
	if err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(idxJSON, &idx); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}

	var out []entry
	for _, m := range idx.Manifests {
		name := m.Annotations[images.AnnotationImageName]
		if name == "" {
			continue
		}
		e := entry{digest: m.Digest.String(), ref: name}
		if e.entrypoint, e.cmd, err = imageArgv(store, m); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// imageArgv reads the imported image's config blob for its Entrypoint and Cmd.
func imageArgv(store content.Store, desc ocispec.Descriptor) (entrypoint, cmd []string, err error) {
	ctx := context.Background()
	configDesc, err := images.Config(ctx, store, desc, platforms.Default())
	if err != nil {
		return nil, nil, fmt.Errorf("config descriptor: %w", err)
	}
	blob, err := content.ReadBlob(ctx, store, configDesc)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	var img ocispec.Image
	if err := json.Unmarshal(blob, &img); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	return img.Config.Entrypoint, img.Config.Cmd, nil
}

// imageRefRE matches an `image:` value pinned by digest.
var imageRefRE = regexp.MustCompile(`\bimage:\s*"?([^\s"]+@(sha256:[0-9a-f]{64}))"?`)

// manifestEntries scans a YAML manifest for digest-pinned image references;
// indented blocks (the local-path helper pod template inside a ConfigMap)
// match the same way.
func manifestEntries(path string) ([]entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []entry
	for _, m := range imageRefRE.FindAllSubmatch(data, -1) {
		out = append(out, entry{digest: string(m[2]), ref: string(m[1])})
	}
	return out, nil
}

// render formats the entries as always_allow YAML lines at the template's
// indent, one line per digest, sorted by image reference.
func render(entries []entry) string {
	byRef := make(map[string]string, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if seen[e.digest] {
			continue
		}
		seen[e.digest] = true
		byRef[e.ref] = e.digest
	}
	refs := make([]string, 0, len(byRef))
	for r := range byRef {
		refs = append(refs, r)
	}
	sort.Strings(refs)

	var b strings.Builder
	for _, r := range refs {
		fmt.Fprintf(&b, "    %q: %q\n", byRef[r], r)
	}
	return b.String()
}

// floorFile renders the system-floor.json skeleton: one image per entry,
// sorted by reference and deduped by digest like render, with the config
// argv and everything the build cannot see left for the reviewer.
func floorFile(entries []entry) ([]byte, error) {
	byRef := make(map[string]entry, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if seen[e.digest] {
			continue
		}
		seen[e.digest] = true
		byRef[e.ref] = e
	}
	refs := make([]string, 0, len(byRef))
	for r := range byRef {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	floor := allowlist.SystemFloor{Schema: allowlist.SystemFloorSchema, Images: make([]allowlist.SystemFloorImage, 0, len(refs))}
	for _, r := range refs {
		e := byRef[r]
		floor.Images = append(floor.Images, allowlist.SystemFloorImage{
			Ref:        e.ref,
			Digest:     e.digest,
			Entrypoint: e.entrypoint,
			Cmd:        e.cmd,
			Env:        map[string]allowlist.EnvValue{},
			Mounts:     map[string]allowlist.MountRule{},
			Privileges: &allowlist.Privileges{},
		})
	}
	return json.MarshalIndent(floor, "", "  ")
}

// resolveManifestArgv fills the config argv of manifest-sourced entries from
// the registry; bundle entries already carry theirs.
func resolveManifestArgv(entries []entry) error {
	if err := crane.Require(); err != nil {
		return fmt.Errorf("-floor needs the config of manifest-pinned images: %w", err)
	}
	for i := range entries {
		e := &entries[i]
		if e.entrypoint != nil || e.cmd != nil {
			continue
		}
		cfg, err := crane.Config(context.Background(), e.ref)
		if err != nil {
			return err
		}
		e.entrypoint, e.cmd = cfg.Config.Entrypoint, cfg.Config.Cmd
	}
	return nil
}

const (
	beginMarker = "# BEGIN rke2 system floor"
	endMarker   = "# END rke2 system floor"
)

// splice returns the template with the lines between the marker lines
// replaced by body.
func splice(template, body string) (string, error) {
	lines := strings.Split(template, "\n")
	begin, end := -1, -1
	for i, l := range lines {
		if strings.Contains(l, beginMarker) {
			begin = i
		}
		if strings.Contains(l, endMarker) {
			end = i
		}
	}
	if begin < 0 {
		return "", fmt.Errorf("no %q marker in template", beginMarker)
	}
	if end < 0 || end <= begin {
		return "", fmt.Errorf("no %q marker after the begin marker", endMarker)
	}
	out := append([]string{}, lines[:begin+1]...)
	out = append(out, strings.TrimSuffix(body, "\n"))
	out = append(out, lines[end:]...)
	return strings.Join(out, "\n"), nil
}

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ", ") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "systemfloor:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("systemfloor", flag.ContinueOnError)
	var bundles, manifests stringList
	var templatePath, floorPath string
	var check, write bool
	fs.Var(&bundles, "bundle", "RKE2 airgap image bundle (*.tar.zst); repeatable")
	fs.Var(&manifests, "manifest", "YAML manifest to scan for digest-pinned image refs; repeatable")
	fs.StringVar(&templatePath, "template", "", "image-policy.yaml.in to splice the block into")
	fs.BoolVar(&check, "check", false, "exit non-zero when the template block is stale")
	fs.BoolVar(&write, "write", false, "rewrite the template block in place")
	fs.StringVar(&floorPath, "floor", "", "write the system-floor.json rule skeleton here (manifest refs are resolved through crane)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(bundles) == 0 && len(manifests) == 0 {
		return fmt.Errorf("no inputs: pass -bundle and/or -manifest")
	}

	var entries []entry
	for _, b := range bundles {
		e, err := bundleEntries(b)
		if err != nil {
			return err
		}
		entries = append(entries, e...)
	}
	for _, m := range manifests {
		e, err := manifestEntries(m)
		if err != nil {
			return err
		}
		entries = append(entries, e...)
	}
	if len(entries) == 0 {
		return fmt.Errorf("no images found in the inputs")
	}
	if floorPath != "" {
		if len(manifests) > 0 {
			if err := resolveManifestArgv(entries); err != nil {
				return err
			}
		}
		floor, err := floorFile(entries)
		if err != nil {
			return err
		}
		if err := os.WriteFile(floorPath, append(floor, '\n'), 0o644); err != nil {
			return err
		}
	}
	block := render(entries)

	if templatePath == "" {
		_, err := io.WriteString(stdout, block)
		return err
	}

	data, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	updated, err := splice(string(data), block)
	if err != nil {
		return err
	}
	switch {
	case check:
		if updated != string(data) {
			return fmt.Errorf("%s: system floor is stale; regenerate with systemfloor -write", templatePath)
		}
	case write:
		if err := os.WriteFile(templatePath, []byte(updated), 0o644); err != nil {
			return err
		}
	default:
		_, err := io.WriteString(stdout, block)
		return err
	}
	return nil
}
