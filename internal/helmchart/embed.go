//go:build !c8s_node

// Package helmchart bundles the c8s shape Helm charts into the Go binary so
// `c8s install` is a single-file install tool — no side chart download.
//
// The charts live in this package: one chart per install shape (pod/,
// node-cloud/, node-metal/, node-image/), the shared library chart they all
// vendor (lib/), the CRDs (crds/), and the host scripts (scripts/, per-shape
// sets in scripts/MANIFEST). sync.sh materializes the same tree in-repo for
// development (helm template, go test); ExtractChart does it at install time.
//
// Build tag: dropped from `-tags c8s_node` builds along with the
// `c8s install` subcommand that consumes it.
package helmchart

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ChartFS contains the full chart tree: the four shape charts, the library
// chart, the CRDs, and the host scripts.
//
//go:embed all:pod all:node-cloud all:node-metal all:node-image all:lib all:crds all:scripts
var ChartFS embed.FS

// Shape is the install shape: which trust boundary the platform runs. It
// selects the chart `c8s install` deploys.
type Shape string

const (
	// ShapePod is pod-as-CVM: every workload pod is a kata confidential VM;
	// host-side attestation/mesh/policy run inside the guest image.
	ShapePod Shape = "pod"
	// ShapeNodeCloud is node-as-CVM on cloud-managed confidential VM nodes
	// (GKE, AKS): the chart installs the host-side DaemonSets.
	ShapeNodeCloud Shape = "node-cloud"
	// ShapeNodeMetal is node-as-CVM on self-managed bare-metal CVM nodes: the
	// chart installs the host-side DaemonSets (RKE2 defaults).
	ShapeNodeMetal Shape = "node-metal"
	// ShapeNodeImage is node-as-CVM on nodes booted from the c8s
	// node-guest-image: the image bakes attestation-api and the NRI plugin, so
	// the chart renders a pins-only installer.
	ShapeNodeImage Shape = "node-image"
)

// Shapes lists every valid shape in stable order.
var Shapes = []Shape{ShapePod, ShapeNodeCloud, ShapeNodeMetal, ShapeNodeImage}

// ParseShape accepts the shape names and the pre-split --cvm-mode aliases:
// gke -> node-cloud (native evidence), aks -> node-cloud (vTPM evidence),
// node -> node-image. The second return value reports the evidence source the
// alias pins: "native", "vtpm", or "" (shape-native).
func ParseShape(s string) (Shape, string, error) {
	switch s {
	case "pod":
		return ShapePod, "", nil
	case "node-cloud":
		return ShapeNodeCloud, "", nil
	case "gke":
		return ShapeNodeCloud, "native", nil
	case "aks":
		return ShapeNodeCloud, "vtpm", nil
	case "node-metal":
		return ShapeNodeMetal, "", nil
	case "node-image", "node":
		return ShapeNodeImage, "", nil
	}
	return "", "", fmt.Errorf("unknown shape %q: one of pod, node-cloud, node-metal, node-image (gke/aks/node accepted as aliases)", s)
}

// IsNode reports whether the shape is a node-as-CVM shape (host-side mesh,
// attestation, and image policy).
func (s Shape) IsNode() bool { return s != ShapePod }

// ChartDir is the directory name of the shape's chart inside ChartFS (and the
// chart name prefix: c8s-<dir>).
func (s Shape) ChartDir() string { return string(s) }

// ChartName is the Helm chart name, e.g. c8s-node-image.
func (s Shape) ChartName() string { return "c8s-" + string(s) }

// ShapeForChartName maps a chart name back to its shape, for reading a
// deployed release's chart identity.
func ShapeForChartName(name string) (Shape, error) {
	for _, s := range Shapes {
		if s.ChartName() == name {
			return s, nil
		}
	}
	return "", fmt.Errorf("unknown c8s chart name %q", name)
}

// shapeScripts parses scripts/MANIFEST lazily into per-shape script sets.
func shapeScripts() (map[Shape][]string, error) {
	data, err := ChartFS.ReadFile("scripts/MANIFEST")
	if err != nil {
		return nil, fmt.Errorf("read scripts/MANIFEST: %w", err)
	}
	out := map[Shape][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		shape, scripts, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("scripts/MANIFEST: malformed line %q", line)
		}
		out[Shape(strings.TrimSpace(shape))] = strings.Fields(scripts)
	}
	return out, nil
}

// ExtractChart writes the embedded tree to a fresh tmpdir and materializes the
// given shape's chart: the library chart vendored into charts/c8s-lib, the
// CRDs into crds/, and the shape's host scripts into files/scripts/. It
// returns the chart directory; the caller removes parent (the tmpdir root).
func ExtractChart(shape Shape) (chartPath, tmpRoot string, err error) {
	tmpRoot, err = os.MkdirTemp("", "c8s-chart-*")
	if err != nil {
		return "", "", err
	}
	if err := os.CopyFS(tmpRoot, ChartFS); err != nil {
		os.RemoveAll(tmpRoot)
		return "", "", err
	}
	chartPath = filepath.Join(tmpRoot, shape.ChartDir())
	if err := Materialize(chartPath, tmpRoot, shape); err != nil {
		os.RemoveAll(tmpRoot)
		return "", "", err
	}
	return chartPath, tmpRoot, nil
}

// Materialize copies the shared tree into the extracted shape chart dir. It is
// the Extract-time twin of sync.sh. Target dirs are removed first: the
// embedded FS captures the working tree, which may carry the gitignored
// vendored copies sync.sh produced at an older revision.
func Materialize(chartPath, root string, shape Shape) error {
	for _, dir := range []string{"charts", "crds", "files"} {
		if err := os.RemoveAll(filepath.Join(chartPath, dir)); err != nil {
			return err
		}
	}
	libDst := filepath.Join(chartPath, "charts", "c8s-lib")
	if err := copyTree(filepath.Join(root, "lib"), libDst); err != nil {
		return err
	}
	crds, err := os.ReadDir(filepath.Join(root, "crds"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(chartPath, "crds"), 0o755); err != nil {
		return err
	}
	for _, e := range crds {
		if err := copyFile(filepath.Join(root, "crds", e.Name()), filepath.Join(chartPath, "crds", e.Name())); err != nil {
			return err
		}
	}
	sets, err := shapeScripts()
	if err != nil {
		return err
	}
	dst := filepath.Join(chartPath, "files", "scripts")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, s := range sets[shape] {
		if err := copyFile(filepath.Join(root, "scripts", s), filepath.Join(dst, s)); err != nil {
			return err
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode())
}
