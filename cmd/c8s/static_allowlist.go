package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// valuesFilesSetWritePolicy reports what the operator's -f values files say
// about allowlist writes: whether one pins cds.operatorKeys (writes enabled)
// and whether one seals the allowlist with cds.staticAllowlist (no write path
// by design). Both are read so the operator-keys guard can judge a values-file
// install instead of waving it through.
func valuesFilesSetWritePolicy(files []string) (keys, static bool, err error) {
	for _, f := range files {
		tree, err := decodeValuesFile(f)
		if err != nil {
			return false, false, err
		}
		if v, err := stringAtPath(tree, "cds.operatorKeys"); err == nil && v != "" {
			keys = true
		}
		if v, ok := valueAtPath(tree, "cds.staticAllowlist"); ok {
			if b, isBool := v.(bool); isBool && b {
				static = true
			}
		}
	}
	return keys, static, nil
}

// staticAllowlistPreflight rejects a sealed install that also pins operator
// keys — from the flag or from a -f values file — before helm does, with the
// reason instead of a render error: a sealed allowlist has no write path.
func staticAllowlistPreflight(staticAllowlist bool, operatorKeys string, valuesFiles []string) error {
	if !staticAllowlist {
		return nil
	}
	if operatorKeys != "" {
		return fmt.Errorf("--static-allowlist and --operator-keys are mutually exclusive: a sealed allowlist has no write path (docs/static-allowlist.md)")
	}
	keys, _, err := valuesFilesSetWritePolicy(valuesFiles)
	if err != nil {
		return err
	}
	if keys {
		return fmt.Errorf("--static-allowlist cannot be combined with a values file that sets cds.operatorKeys: a sealed allowlist has no write path (docs/static-allowlist.md)")
	}
	return nil
}

// appendBootstrapAllowlistArgs folds a c8s.allowlist/v1 document into the
// chart's seed: its floor digests join nriImagePolicy.bootstrapAllowlist.digests
// and its workload entries become nriImagePolicy.bootstrapAllowlist.workloads.
// Under --static-allowlist this is the only way a workload entry enters the
// sealed policy, since nothing can be written after CDS starts.
func appendBootstrapAllowlistArgs(setArgs []string, path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --bootstrap-allowlist: %w", err)
	}
	doc, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("--bootstrap-allowlist %s: %w", path, err)
	}
	for _, digest := range slices.Sorted(maps.Keys(doc.Digests)) {
		setArgs = append(setArgs, "--set-string", "nriImagePolicy.bootstrapAllowlist.digests."+digest+"="+doc.Digests[digest])
	}
	if len(doc.Workloads) > 0 {
		encoded, err := json.Marshal(doc.Workloads)
		if err != nil {
			return nil, fmt.Errorf("encode --bootstrap-allowlist workloads: %w", err)
		}
		setArgs = append(setArgs, "--set-json", "nriImagePolicy.bootstrapAllowlist.workloads="+string(encoded))
	}
	return setArgs, nil
}

// printStaticAllowlistHint tells a sealed install's operator what relying
// parties pin and where to get it: the served document and its canonical
// digest, which CDS stamped into the mesh CA at startup.
func printStaticAllowlistHint(w io.Writer, staticAllowlist bool) {
	if !staticAllowlist {
		return
	}
	fmt.Fprintln(w, "+ allowlist SEALED (--static-allowlist): writes are disabled; the policy digest is stamped into")
	fmt.Fprintln(w, "  the mesh CA next to CDS's own evidence. Publish the policy for relying parties:")
	fmt.Fprintln(w, "    c8s allowlist export --url https://<tls-lb> --measurements <M> > allowlist.json")
	fmt.Fprintln(w, "    c8s allowlist digest allowlist.json")
	fmt.Fprintln(w, "  Clients pin it: c8s verify https://<tls-lb> --measurements <M> --mesh-ca mesh-ca.pem \\")
	fmt.Fprintln(w, "    --static-allowlist --allowlist allowlist.json   (docs/static-allowlist.md)")
}

// nodeStaticSeedPath is where a sealed node image bakes the policy document
// (node-guest-image/build C8S_STATIC_ALLOWLIST) and therefore where CDS reads
// its seed from on a node-as-CVM install.
const nodeStaticSeedPath = "/etc/c8s/static-allowlist.json"

// bootstrapDocument reads a c8s.allowlist/v1 document and returns its hex
// canonical digest — the value CDS seals and relying parties pin.
func bootstrapDocument(path string) (*pkgallowlist.Allowlist, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read --bootstrap-allowlist: %w", err)
	}
	doc, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, "", fmt.Errorf("--bootstrap-allowlist %s: %w", path, err)
	}
	digest, err := doc.CanonicalDigest()
	if err != nil {
		return nil, "", fmt.Errorf("--bootstrap-allowlist %s: %w", path, err)
	}
	return doc, hex.EncodeToString(digest), nil
}

// appendNodeSealArgs wires a node-as-CVM seal: CDS reads its seed from the
// document the node image baked, and refuses to start unless that document
// hashes to the one this install was given. The baked file is what the launch
// measurement covers and what the baked NRI plugin enforces, so a mismatch is
// the operator installing against an image that does not carry their policy —
// which must fail, not seal the wrong thing.
func appendNodeSealArgs(setArgs []string, bootstrapPath, seedPath string) ([]string, error) {
	if bootstrapPath == "" {
		return nil, fmt.Errorf("--static-allowlist under --cvm-mode=node requires --bootstrap-allowlist: the document the node image baked (node-guest-image/build C8S_STATIC_ALLOWLIST, composed with `c8s render-allowlist`) is the whole policy, and the install pins its digest")
	}
	_, digest, err := bootstrapDocument(bootstrapPath)
	if err != nil {
		return nil, err
	}
	return append(setArgs,
		"--set-string", "cds.allowlistSeedHostPath="+seedPath,
		"--set-string", "cds.staticAllowlistDigest="+digest,
	), nil
}

// renderSeedDocument runs `helm template` with the install's exact values
// ordering and returns the allowlist seed the chart would put in the CDS
// ConfigMap — the document `c8s render-allowlist` emits for a node image to
// bake.
func renderSeedDocument(ctx context.Context, chartPath string, valueFiles []string, computedValues, kubeVersion string) ([]byte, error) {
	args := []string{"template", "c8s", chartPath, "--kube-version", kubeVersion, "--show-only", "templates/cds.yaml"}
	for _, f := range valueFiles {
		args = append(args, "-f", f)
	}
	args = append(args, "-f", computedValues)
	out, err := exec.CommandContext(ctx, "helm", args...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("helm template: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("helm template: %w", err)
	}
	return seedFromRenderedManifests(out)
}

// seedFromRenderedManifests picks the allowlist seed out of a rendered
// multi-document manifest stream: the ConfigMap carrying allowlist-seed.json.
func seedFromRenderedManifests(rendered []byte) ([]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(rendered))
	for {
		var doc struct {
			Kind string            `yaml:"kind"`
			Data map[string]string `yaml:"data"`
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse rendered manifests: %w", err)
		}
		if doc.Kind != "ConfigMap" {
			continue
		}
		if seed, ok := doc.Data["allowlist-seed.json"]; ok {
			return []byte(seed), nil
		}
	}
	return nil, fmt.Errorf("the rendered chart carries no allowlist seed ConfigMap (is the seed served for this shape, and no cds.allowlistSeedHostPath set?)")
}
