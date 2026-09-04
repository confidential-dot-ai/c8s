//go:build !c8s_node

package allowlist

import (
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
)

func TestHostPathClass(t *testing.T) {
	cluster := clusterFacts{platformDir: "/run/nri-image-policy"}
	for _, tc := range []struct {
		name, hostPath, want string
	}{
		{"plugin socket dir", "/run/nri-image-policy", pkgallowlist.SourcePlatform},
		{"plugin socket dir file", "/run/nri-image-policy/inventory.sock", pkgallowlist.SourcePlatform},
		{"plugin socket dir sibling", "/run/nri-image-policy-evil/x", pkgallowlist.SourceHostPath},
		{"node state dir", policybundle.NodeStateDir, pkgallowlist.SourceNodeState},
		{"attestation socket", policybundle.NodeStateDir + "/attestation-api.sock", pkgallowlist.SourceNodeState},
		{"policy dir member", policybundle.DefaultPolicyDir + "/static-allowlist.json", pkgallowlist.SourceNodeState},
		{"node state dir sibling", policybundle.NodeStateDir + "-evil/attestation-api.sock", pkgallowlist.SourceHostPath},
		{"host path", "/lib/modules", pkgallowlist.SourceHostPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cluster.hostPathClass(tc.hostPath); got != tc.want {
				t.Fatalf("hostPathClass(%s) = %q, want %q", tc.hostPath, got, tc.want)
			}
		})
	}
	if got := (clusterFacts{}).hostPathClass("/run/nri-image-policy"); got != pkgallowlist.SourceHostPath {
		t.Fatalf("hostPathClass(plugin dir) = %q with no chart rendered, want hostPath", got)
	}
}
