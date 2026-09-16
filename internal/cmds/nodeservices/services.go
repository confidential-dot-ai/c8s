// Package nodeservices starts the measured host services from an authenticated
// launch artifact. Its fixed argument lists are not a general service override.
package nodeservices

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

const (
	launchDir     = launchconfig.Dir + "/"
	apiURL        = launchconfig.DefaultAttestationAPIURL
	kubeletConfig = "/var/lib/rancher/rke2/agent/kubelet.kubeconfig"
	nodeIPPath    = "/var/run/nri-image-policy/node-ip"
)

// Arguments uses a typed document that has already passed LoadStaged. Every
// CDS client receives the server-only policy; peer listeners use the peer policy.
func Arguments(service string, d *launchconfig.Document, nodeIP string) ([]string, error) {
	if d == nil {
		return nil, fmt.Errorf("missing staged launch configuration")
	}
	if d.Role != launchconfig.Server && d.Role != launchconfig.Agent {
		return nil, fmt.Errorf("invalid staged role")
	}
	switch {
	case NeedsNodeIP(service):
		if err := launchconfig.ValidateIPv4(nodeIP, true); err != nil {
			return nil, fmt.Errorf("mesh requires the routable node IPv4 address")
		}
	case service == "join":
	case service == "attest-proxy":
	case d.Role != launchconfig.Server:
		return nil, fmt.Errorf("%s is a server-only service", service)
	}
	cds := "--cds-url=" + d.CDSURL()
	api := "--attestation-api-url=" + apiURL
	pins := "--measurements-config=" + launchDir + "cds.json"
	switch service {
	case "join-release":
		if len(d.AgentOperatorPublicKeys) == 0 {
			return nil, fmt.Errorf("join-release requires authorized agents")
		}
		return []string{"join-release", "--listen=:8444", "--platform=" + d.Image.Platform, api,
			"--measurements-config=" + launchDir + "agents.json",
			"--token-path=/var/lib/rancher/rke2/server/agent-token"}, nil
	case "join":
		if d.Role != launchconfig.Agent {
			return nil, fmt.Errorf("join is an agent-only service")
		}
		return []string{"join", "--server=" + d.Server.Address + ":8444", "--platform=" + d.Image.Platform, api,
			pins, "--token-out=/run/confos/rke2-agent-token"}, nil
	case "attest-proxy":
		return []string{"attest-proxy", "--socket=/var/run/nri-image-policy/attestation-api.sock", "--socket-gid=65532", "--upstream=" + apiURL}, nil
	case "cds":
		return []string{"cds", "--port=30808", "--ratls-platform=" + d.Image.Platform, api,
			"--kubeconfig=/etc/rancher/rke2/rke2.yaml",
			"--allowlist-db=/run/c8s-cds/allowlist.db",
			"--allowlist-persistent=false", "--allowlist-seed=" + launchDir + "allowlist-seed.json",
			"--measurements-config=" + launchDir + "peers.json", "--operator-keys=" + launchDir + "operator-pubkey",
			"--max-request-size=262144", "--san-validation=false",
			"--dns-san-pattern=^[a-z0-9-]+[.][a-z0-9-]+[.]svc$",
			"--dns-san-pattern=^" + regexp.QuoteMeta(d.TLSSAN) + "$"}, nil
	case "mesh":
		return []string{"ratls-mesh", "--platform=" + d.Image.Platform, api,
			"--kubeconfig=" + kubeletConfig, "--node-ip=" + nodeIP,
			"--measurements-config=" + launchDir + "peers.json",
			"--cds-measurements-config=" + launchDir + "cds.json", cds,
			"--cert-mode=cds", "--cert-dns-san=ratls-mesh.c8s.svc",
			"--max-conns=10000",
			"--iptables-metrics-file=/run/ratls-mesh/iptables-metrics.json"}, nil
	case "mesh-sync":
		return []string{"ratls-mesh", "iptables-sync", "--kubeconfig=" + kubeletConfig,
			"--node-ip=" + nodeIP, "--uid=1337", "--exclude-uids=0",
			"--exclude-source-namespaces=kube-system", "--ready-file=/run/ratls-mesh/iptables-ready",
			"--iptables-metrics-file=/run/ratls-mesh/iptables-metrics.json"}, nil
	case "get-cert":
		return []string{"get-cert", cds, api, pins, "--san=" + d.TLSSAN,
			"--out=/run/c8s-tls/cert.pem", "--key-out=/run/c8s-tls/key.pem",
			"--ca-out=/run/c8s-tls/ca.pem", "--continue-on-initial-error",
			"--renew-interval=1h", "--ca-watch-interval=1m",
			"--discovery-out=/run/c8s-tls/discovery.json", "--discovery-public-tls-mode=cds",
			"--discovery-cds-cert-url=/.well-known/cds-cert.pem",
			"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem", "--reload-nginx"}, nil
	case "cds-attest":
		return []string{"cds-attest", "--host=127.0.0.1", "--port=8800",
			"--platform=" + d.Image.Platform, api, "--front-door-mode=cds",
			"--serving-cert-file=/run/c8s-tls/cert.pem",
			"--mesh-identity-cert-file=/run/c8s-tls/cert.pem",
			"--mesh-identity-key-file=/run/c8s-tls/key.pem",
			"--mesh-identity-ca-file=/run/c8s-tls/ca.pem"}, nil
	case "allowlist-proxy":
		return []string{"allowlist-proxy", "--host=127.0.0.1", "--port=8801", cds, api, pins}, nil
	default:
		return nil, fmt.Errorf("unknown measured node service %q", service)
	}
}

// NeedsNodeIP reports the services that bind the node's own routable address.
func NeedsNodeIP(service string) bool { return service == "mesh" || service == "mesh-sync" }

// primaryIPv4 is a package var so tests can fake the host's routes.
var primaryIPv4 = launchconfig.PrimaryIPv4

// NodeIP reads the address selected before containerd starts its NRI plugin.
func NodeIP() (string, error) { return readNodeIP("") }

// readNodeIP reads PublishNodeIP's output. rootDir only rebases the fixed
// path for tests.
func readNodeIP(rootDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(rootDir, nodeIPPath))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// PublishNodeIP selects the same address as RKE2, including an explicit
// authenticated node.ip. RootDir only rebases the fixed output for tests.
func PublishNodeIP(rootDir string, d *launchconfig.Document) error {
	address := d.Node.IP
	if address == "" {
		var err error
		if address, err = primaryIPv4(); err != nil {
			return fmt.Errorf("resolve node address: %w", err)
		}
	}
	if err := launchconfig.ValidateIPv4(address, true); err != nil {
		return fmt.Errorf("node inventory requires a routable IPv4 address")
	}
	dst := filepath.Join(rootDir, nodeIPPath)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return fileutil.WriteAtomic(dst, []byte(address+"\n"), 0600)
}
