package launchconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	utilnet "k8s.io/apimachinery/pkg/util/net"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

const (
	launchDir           = "/run/confos/launch"
	serverMarker        = "/run/confos/role-server"
	agentMarker         = "/run/confos/role-agent"
	serverTokenPath     = "/run/confos/rke2-server-token"
	agentTokenPath      = "/run/confos/rke2-agent-token"
	rke2FragmentPath    = "/etc/rancher/rke2/config.yaml.d/50-role.yaml"
	runtimeManifestPath = "/var/lib/rancher/rke2/server/manifests/c8s-node-runtime.yaml"
)

// Stage authenticates the launch document and writes only fixed boot paths.
// Both role markers are cleared before verification, and the selected marker
// is written last: an invalid document or failed write cannot start a role.
// Services require the oneshot stage unit and must never consume these files
// independently of its successful completion. Role changes require relaunch.
func Stage(ctx context.Context, cfg Config) error {
	if err := clearOutputs(cfg); err != nil {
		return err
	}
	verified, err := Verify(ctx, cfg)
	if err != nil {
		return err
	}
	return stageVerified(cfg, verified)
}

func (c Config) path(absolute string) string {
	if c.RootDir == "" {
		return absolute
	}
	return filepath.Join(c.RootDir, strings.TrimPrefix(absolute, "/"))
}

func clearOutputs(cfg Config) error {
	// Clear authorization verdicts first, even when removing another stale
	// output fails. Collect errors so a blocked first marker never prevents
	// attempting to remove the other.
	var errs []error
	paths := []string{serverMarker, agentMarker, serverTokenPath, agentTokenPath, rke2FragmentPath, runtimeManifestPath}
	for _, name := range []string{"peers.json", "cds.json", "operator-pubkey", "config.json", "env", "workloads.json"} {
		paths = append(paths, launchDir+"/"+name)
	}
	for _, path := range paths {
		if err := os.Remove(cfg.path(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove stale %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

type outputFile struct {
	path string
	data []byte
}

func stageVerified(cfg Config, v *Verified) error {
	doc := &v.document
	if doc.Role == Leader && doc.Leader.Address == "" {
		address := doc.Node.IP
		if address == "" {
			resolve := cfg.ResolveNodeIP
			if resolve == nil {
				resolve = primaryIPv4
			}
			var err error
			address, err = resolve()
			if err != nil {
				return fmt.Errorf("resolve leader address: %w", err)
			}
		}
		if err := ipv4(address, true); err != nil {
			return fmt.Errorf("resolved leader address: %w", err)
		}
		doc.Leader.Address = address
		doc.Node.IP = address
	}
	peers, err := measurements.Format(v.pins)
	if err != nil {
		return fmt.Errorf("format node peer policy: %w", err)
	}
	cds, err := measurements.Format(v.cdsPins)
	if err != nil {
		return fmt.Errorf("format leader policy: %w", err)
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode staged config: %w", err)
	}
	fragment, err := yaml.Marshal(rke2Fragment(doc))
	if err != nil {
		return fmt.Errorf("encode RKE2 role fragment: %w", err)
	}
	outputs := []outputFile{
		{launchDir + "/peers.json", peers},
		{launchDir + "/cds.json", cds},
		{launchDir + "/operator-pubkey", v.operatorPub},
		{launchDir + "/config.json", append(encoded, '\n')},
		{launchDir + "/env", environment(doc)},
		{agentTokenPath, []byte(doc.RKE2.AgentToken)},
		{rke2FragmentPath, fragment},
	}
	if doc.Workloads != "" {
		outputs = append(outputs, outputFile{launchDir + "/workloads.json", []byte(doc.Workloads)})
	}
	marker := agentMarker
	if doc.Role == Leader {
		manifest, err := runtimeManifest(doc, cds)
		if err != nil {
			return err
		}
		outputs = append(outputs,
			outputFile{serverTokenPath, []byte(doc.RKE2.ServerToken)},
			outputFile{runtimeManifestPath, manifest},
		)
		marker = serverMarker
	}
	for _, out := range outputs {
		path := cfg.path(out.path)
		// /run/confos/launch contains a copy of the signed join credentials.
		// Existing parent directories retain their established permissions.
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create output parent: %w", err)
		}
		if err := fileutil.WriteAtomic(path, out.data, 0o600); err != nil {
			return fmt.Errorf("stage %s: %w", out.path, err)
		}
	}
	// No fallible work follows publishing the role authorization verdict.
	return fileutil.WriteAtomic(cfg.path(marker), nil, 0o600)
}

type roleFragment struct {
	TokenFile      string `yaml:"token-file"`
	AgentTokenFile string `yaml:"agent-token-file,omitempty"`
	Server         string `yaml:"server,omitempty"`
	NodeName       string `yaml:"node-name"`
	NodeIP         string `yaml:"node-ip,omitempty"`
	NodeExternalIP string `yaml:"node-external-ip,omitempty"`
}

func rke2Fragment(doc *Document) roleFragment {
	out := roleFragment{TokenFile: agentTokenPath, NodeName: doc.Node.Name, NodeIP: doc.Node.IP, NodeExternalIP: doc.Node.ExternalIP}
	if doc.Role == Leader {
		out.TokenFile = serverTokenPath
		out.AgentTokenFile = agentTokenPath
	} else {
		out.Server = "https://" + doc.Leader.Address + ":9345"
	}
	return out
}

func environment(doc *Document) []byte {
	// Every value is either fixed or constrained by validation to a single
	// hostname/address/label. Tokens and arbitrary workload JSON never enter
	// an environment file or command line.
	return []byte(fmt.Sprintf("ROLE=%s\nCLUSTER_ID=%s\nNODE_NAME=%s\nNODE_IP=%s\nLEADER_ADDRESS=%s\nCDS_URL=%s\nTLS_SAN=%s\n",
		doc.Role, doc.ClusterID, doc.Node.Name, doc.Node.IP, doc.Leader.Address, doc.CDSURL(), doc.TLSSAN))
}

func runtimeManifest(doc *Document, cds []byte) ([]byte, error) {
	manifest := struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Metadata   struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"metadata"`
		Data map[string]string `yaml:"data"`
	}{APIVersion: "v1", Kind: "ConfigMap", Data: map[string]string{"cds-url": doc.CDSURL(), "cds.json": string(cds)}}
	manifest.Metadata.Name = "c8s-node-runtime"
	manifest.Metadata.Namespace = "c8s-system"
	out, err := yaml.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode node runtime ConfigMap: %w", err)
	}
	return out, nil
}

// primaryIPv4 uses Kubernetes' route-aware host-address selection, so the
// address published to followers matches the node's own RKE2 registration.
func primaryIPv4() (string, error) {
	ip, err := utilnet.ChooseHostInterface()
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}
