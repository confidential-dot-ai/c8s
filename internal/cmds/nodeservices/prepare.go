package nodeservices

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"gopkg.in/yaml.v3"
)

// Prepare writes only fixed service inputs. rootDir rebases paths for tests;
// production calls it with an empty root after authenticating launch.yaml.
func Prepare(rootDir string, d *launchconfig.Document) error {
	if d == nil {
		return fmt.Errorf("missing staged launch configuration")
	}
	path := func(name string) string { return filepath.Join(rootDir, name) }
	read := func(name string) ([]byte, error) { return os.ReadFile(path(name)) }
	write := func(name string, data []byte) error {
		p := path(name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			return err
		}
		return fileutil.WriteAtomic(p, data, 0600)
	}
	data, err := read("/usr/lib/c8s/image-policy.yaml")
	if err != nil {
		return err
	}
	var floor map[string]any
	if err := yaml.Unmarshal(data, &floor); err != nil {
		return fmt.Errorf("baked NRI policy: %w", err)
	}
	a, ok := floor["allowlist"].(map[string]any)
	if !ok {
		return fmt.Errorf("baked NRI policy missing allowlist")
	}
	pull, ok := a["pull"].(map[string]any)
	if !ok {
		return fmt.Errorf("baked NRI policy missing pull")
	}
	pull["url"] = d.CDSURL()
	pull["cds_measurements_config"] = launchDir + "cds.json"
	delete(pull, "cds_measurements")
	delete(pull, "cds_rtmrs")
	data, err = yaml.Marshal(floor)
	if err != nil {
		return err
	}
	if err := write("/etc/nri/conf.d/image-policy.yaml", data); err != nil {
		return err
	}
	if d.Role != launchconfig.Server {
		return nil
	}

	data, err = read("/usr/lib/c8s/nginx.conf.in")
	if err != nil {
		return err
	}
	if !strings.Contains(string(data), "c8s-node.invalid") {
		return fmt.Errorf("baked nginx template missing hostname")
	}
	if err := write(launchDir+"nginx.conf", []byte(strings.ReplaceAll(string(data), "c8s-node.invalid", d.TLSSAN))); err != nil {
		return err
	}
	if err := os.MkdirAll(path("/run/c8s-tls"), 0755); err != nil {
		return err
	}
	data, err = read("/usr/lib/c8s/allowlist-seed.json")
	if err != nil {
		return err
	}
	seed, err := allowlist.ParseJSON(data)
	if err != nil {
		return fmt.Errorf("baked workload seed: %w", err)
	}
	if d.Workloads != "" {
		extra, err := allowlist.ParseJSON([]byte(d.Workloads))
		if err != nil {
			return fmt.Errorf("launch workloads: %w", err)
		}
		for name, workload := range extra.Workloads {
			if _, exists := seed.Workloads[name]; exists {
				return fmt.Errorf("launch workload %q replaces a baked component", name)
			}
			seed.Workloads[name] = workload
		}
	}
	// Normalize the combined document too: per-document validation alone would
	// miss conflicting policies for one digest across the baked and launch sets.
	data, err = json.Marshal(seed)
	if err != nil {
		return err
	}
	seed, err = allowlist.ParseJSON(data)
	if err != nil {
		return fmt.Errorf("combined workload policy: %w", err)
	}
	data, err = seed.Canonical()
	if err != nil {
		return err
	}
	return write(launchDir+"allowlist-seed.json", data)
}
