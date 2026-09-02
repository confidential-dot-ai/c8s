package main

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"

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
