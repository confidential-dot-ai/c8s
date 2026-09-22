package nodeservices

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"gopkg.in/yaml.v3"
)

// Prepare publishes a fixed set of nonsecret workload inputs from the
// verified launch document loaded by LoadStaged. rootDir rebases paths for tests.
// The root bootstrap service owns these files; pods mount them read-only.
func Prepare(rootDir string, d *launchconfig.Document) error {
	if err := validateRole(d); err != nil {
		return err
	}
	path := func(name string) string { return filepath.Join(rootDir, name) }
	outputs := make(map[string][]byte)
	for _, name := range []string{"peers.json", "cds.json"} {
		data, err := readPolicy(path(launchDir+name), d.Image.Platform, name == "cds.json")
		if err != nil {
			return err
		}
		outputs[name] = data
	}
	bakedData, err := os.ReadFile(path("/usr/lib/c8s/allowlist-seed.json"))
	if err != nil {
		return err
	}
	bakedSeed, err := allowlist.ParseJSON(bakedData)
	if err != nil {
		return fmt.Errorf("baked workload seed: %w", err)
	}
	if d.Role == launchconfig.Server {
		server, err := serverOutputs(d, bakedData)
		if err != nil {
			return err
		}
		for name, data := range server.files() {
			outputs[name] = data
		}
	}

	data, err := os.ReadFile(path("/usr/lib/c8s/image-policy.yaml"))
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
	baseData, err := json.Marshal(a["base"])
	if err != nil {
		return fmt.Errorf("baked NRI base: %w", err)
	}
	base, err := allowlist.ParseJSON(baseData)
	if err != nil {
		return fmt.Errorf("baked NRI base: %w", err)
	}
	if err := mergeWorkloads(base, bakedSeed, true); err != nil {
		return fmt.Errorf("merge chart seed into NRI base: %w", err)
	}
	a["base"] = base
	pull["url"] = d.CDSURL()
	pull["cds_measurements_config"] = launchDir + "cds.json"
	delete(pull, "cds_measurements")
	delete(pull, "cds_rtmrs")
	data, err = yaml.Marshal(floor)
	if err != nil {
		return err
	}

	// Validate every input before publishing anything. RKE2 only starts after
	// this preparation succeeds, so pods never observe partially staged input.
	publicPath := path(PublicDir)
	if err := os.MkdirAll(publicPath, 0755); err != nil {
		return err
	}
	if err := os.Chmod(publicPath, 0755); err != nil {
		return err
	}
	if d.Role == launchconfig.Agent {
		if err := removeServerOutputs(publicPath); err != nil {
			return err
		}
	}
	for name, data := range outputs {
		if err := fileutil.WriteAtomic(filepath.Join(publicPath, name), data, 0644); err != nil {
			return err
		}
	}
	policyPath := path("/etc/nri/conf.d/image-policy.yaml")
	if err := os.MkdirAll(filepath.Dir(policyPath), 0755); err != nil {
		return err
	}
	return fileutil.WriteAtomic(policyPath, data, 0600)
}

// serverConfig holds the inputs only a server publishes. An agent must never
// carry them, so they are produced and removed as one named set rather than
// as loose strings spread across Prepare.
type serverConfig struct {
	operatorPubKey []byte
	allowlistSeed  []byte
	tlsSAN         string
}

// serverOutputNames is the set both roles agree on: a server writes exactly
// these, and an agent clears exactly these.
var serverOutputNames = []string{"operator-pubkey", "allowlist-seed.json", "tls-san"}

func (c serverConfig) files() map[string][]byte {
	files := map[string][]byte{
		"operator-pubkey":     c.operatorPubKey,
		"allowlist-seed.json": c.allowlistSeed,
		"tls-san":             []byte(c.tlsSAN + "\n"),
	}
	// A server output an agent does not clear would survive a demotion, so
	// the two sets must not drift apart.
	if len(files) != len(serverOutputNames) {
		panic("serverConfig.files and serverOutputNames disagree")
	}
	for _, name := range serverOutputNames {
		if _, ok := files[name]; !ok {
			panic("serverOutputNames lists an unwritten server output: " + name)
		}
	}
	return files
}

// serverOutputs validates the server-only fields of the staged document and
// merges the operator's workloads over the baked seed. It writes nothing:
// Prepare publishes only after every input has been validated.
func serverOutputs(d *launchconfig.Document, bakedData []byte) (serverConfig, error) {
	if net.ParseIP(d.TLSSAN) != nil {
		return serverConfig{}, fmt.Errorf("staged TLS SAN must be a DNS hostname")
	}
	if err := cmdsutil.ValidateDNSName(d.TLSSAN); err != nil {
		return serverConfig{}, fmt.Errorf("staged TLS SAN: %w", err)
	}
	pub := []byte(d.Server.OperatorPublicKey)
	if _, err := operatorauth.ParsePublicKeysPEM(pub); err != nil {
		return serverConfig{}, fmt.Errorf("staged server operator key: %w", err)
	}
	seed, err := mergedSeed(bakedData, d.Workloads)
	if err != nil {
		return serverConfig{}, err
	}
	return serverConfig{operatorPubKey: pub, allowlistSeed: seed, tlsSAN: d.TLSSAN}, nil
}

// removeServerOutputs clears the server-only inputs from an agent's public
// directory, so a node demoted to agent cannot keep serving stale ones.
func removeServerOutputs(publicPath string) error {
	for _, name := range serverOutputNames {
		if err := os.Remove(filepath.Join(publicPath, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// readPolicy refuses partial pins even when the staged file parses. The
// authenticated launcher emits an anchored tuple for every permitted role.
func readPolicy(path, platform string, serverOnly bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pins, err := refvalues.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("staged identity policy %s: %w", path, err)
	}
	family, err := teetypes.ParseFamily(platform)
	if err != nil || pins.Family != family || len(pins.Images) == 0 || (serverOnly && len(pins.Images) != 1) {
		return nil, fmt.Errorf("staged identity policy %s has invalid family or image count", path)
	}
	for _, pin := range pins.Images {
		if len(pin.Anchor) == 0 || (family == teetypes.FamilyTDX && (len(pin.Registers[1]) == 0 || len(pin.Registers[2]) == 0)) {
			return nil, fmt.Errorf("staged identity policy %s requires complete image and operator pins", path)
		}
	}
	return data, nil
}

func mergedSeed(data []byte, workloads string) ([]byte, error) {
	seed, err := allowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("baked workload seed: %w", err)
	}
	if workloads != "" {
		extra, err := allowlist.ParseJSON([]byte(workloads))
		if err != nil {
			return nil, fmt.Errorf("launch workloads: %w", err)
		}
		if err := mergeWorkloads(seed, extra, false); err != nil {
			return nil, fmt.Errorf("launch workloads: %w", err)
		}
	}
	return seed.Canonical()
}

// allowIdentical is used only for the two measured bootstrap sources. Signed
// tenant workloads may never replace a component, even with identical content.
func mergeWorkloads(base, extra *allowlist.Allowlist, allowIdentical bool) error {
	for name, workload := range extra.Workloads {
		if existing, exists := base.Workloads[name]; exists {
			if allowIdentical {
				old, err := json.Marshal(existing)
				if err != nil {
					return err
				}
				incoming, err := json.Marshal(workload)
				if err != nil {
					return err
				}
				// Both inputs were normalized by ParseJSON. Compare every
				// field, so a collision cannot loosen the measured policy.
				if bytes.Equal(old, incoming) {
					continue
				}
			}
			return fmt.Errorf("workload %q replaces a baked component", name)
		}
		base.Workloads[name] = workload
	}
	// Validate the combined document as well as each individual input.
	if err := base.Normalize(); err != nil {
		return fmt.Errorf("combined workload policy: %w", err)
	}
	return nil
}
