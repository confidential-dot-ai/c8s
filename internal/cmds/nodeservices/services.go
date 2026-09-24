// Package nodeservices prepares authenticated launch inputs for the image's
// Kubernetes workloads and host bootstrap services.
package nodeservices

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

const (
	launchDir  = launchconfig.Dir + "/"
	nodeIPPath = "/var/run/nri-image-policy/node-ip"

	// PublicDir contains only authenticated, nonsecret workload inputs. Core
	// pods mount it read-only; the token-bearing launch directory stays private.
	PublicDir = "/run/c8s-node"
)

func validateRole(d *launchconfig.Document) error {
	if d == nil {
		return fmt.Errorf("missing staged launch configuration")
	}
	if d.Role != launchconfig.Server && d.Role != launchconfig.Agent {
		return fmt.Errorf("invalid staged role")
	}
	return nil
}

// primaryIPv4 is a package var so tests can fake the host's routes.
var primaryIPv4 = launchconfig.PrimaryIPv4

// PublishNodeIP selects the same address as RKE2, including an explicit
// authenticated node.ip. RootDir only rebases the fixed output for tests.
func PublishNodeIP(rootDir string, d *launchconfig.Document) error {
	if err := validateRole(d); err != nil {
		return err
	}
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

const (
	attestationAPIURL = launchconfig.DefaultAttestationAPIURL
	// enrollmentPort is where a server releases the agent token to attested
	// agents and where agents connect. It is fixed in the measured units.
	enrollmentPort = "8444"
	// releasedTokenPath is the full agent token RKE2 derives from the minted
	// password once the server is up: it carries the cluster CA pin an agent
	// needs, which is why release waits for rke2-server.
	releasedTokenPath = "/var/lib/rancher/rke2/server/agent-token"
	// enrolledTokenPath is where an agent stages the token it enrolled for.
	// RKE2's role fragment points token-file at it; it must stay RAM-backed.
	enrolledTokenPath = "/run/confos/rke2-agent-token"
)

// Arguments builds the argv for the attested enrollment host services from a
// document that already passed LoadStaged. Only the two enrollment services
// remain host processes with role-dependent arguments; every other core
// service is a baked Kubernetes workload or has a fixed ExecStart.
func Arguments(service string, d *launchconfig.Document) ([]string, error) {
	if err := validateRole(d); err != nil {
		return nil, err
	}
	api := "--attestation-api-url=" + attestationAPIURL
	switch service {
	case "join-release":
		if d.Role != launchconfig.Server {
			return nil, fmt.Errorf("join-release is a server-only service")
		}
		if len(d.AgentOperatorPublicKeys) == 0 {
			return nil, fmt.Errorf("join-release requires authorized agents")
		}
		return []string{"join-release", "--listen=:" + enrollmentPort, "--platform=" + d.Image.Platform, api,
			"--measurements-config=" + launchDir + "agents.json",
			"--token-path=" + releasedTokenPath}, nil
	case "join":
		if d.Role != launchconfig.Agent {
			return nil, fmt.Errorf("join is an agent-only service")
		}
		return []string{"join", "--server=" + d.Server.Address + ":" + enrollmentPort, "--platform=" + d.Image.Platform, api,
			"--measurements-config=" + launchDir + "cds.json",
			"--token-out=" + enrolledTokenPath}, nil
	}
	return nil, fmt.Errorf("unknown host service %q", service)
}
