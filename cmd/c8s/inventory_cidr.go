package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	corev1 "k8s.io/api/core/v1"
)

// resolveInventoryCIDRs returns the operator's --node-cidr when given.
// Unset, the answer depends on where the sandbox inventory lives:
//
//   - node/gke/aks: a host process, reachable on the node address. The
//     install preflights what CDS will derive at runtime and renders nothing:
//     CDS bounds the callback from the live node list itself
//     (docs/operator.md), so there is no install-time snapshot to go stale on
//     scale-up.
//   - pod: inside each kata guest, answering on the guest's pod IP. The live
//     node-list bound would then cover addresses no inventory ever uses and
//     CDS would refuse every sandbox token, so the install infers the
//     cluster's pod range(s) and pins them statically.
//
// Detection failing is fatal: the alternative is installing with sandbox
// identity silently off, which reads as success and leaves workload
// certificates carrying no sandbox ID and no issuance-time image gate.
func resolveInventoryCIDRs(ctx context.Context, explicit []string, cvmMode string) ([]string, error) {
	if len(explicit) > 0 {
		return explicit, nil
	}
	if cvmModeIsPod(cvmMode) {
		cidrs, err := inferPodInventoryCIDRs(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not determine this cluster's pod ranges for the sandbox-digests callback (under --cvm-mode=pod the inventory runs inside each kata guest and answers on its pod IP): %w\n\nPass --node-cidr <pod-cidr> to set them explicitly", err)
		}
		fmt.Printf("==> sandbox-digests callback bounded to the pod range(s): %s\n", strings.Join(cidrs, ", "))
		fmt.Println("    (--cvm-mode=pod: the inventory answers from inside each kata guest, on the guest's pod IP)")
		return cidrs, nil
	}
	if err := preflightNodeAddressBound(ctx); err != nil {
		return nil, fmt.Errorf("could not preflight this cluster's node addresses for the sandbox-digests callback: %w\n\nPass --node-cidr <cidr> to set them explicitly", err)
	}
	fmt.Println("==> sandbox-digests callback will be bounded by CDS from the live node list")
	return nil, nil
}

// preflightNodeAddressBound checks at install time what CDS derives at
// runtime — that nodes report routable InternalIPs separable from the pod
// ranges — so a cluster that cannot support the bound fails here, where the
// operator sees it, rather than refusing sandbox tokens at runtime.
func preflightNodeAddressBound(ctx context.Context) error {
	nodes, err := fetchNodes(ctx)
	if err != nil {
		return err
	}
	items := make([]*corev1.Node, 0, len(nodes.Items))
	for i := range nodes.Items {
		items = append(items, &nodes.Items[i])
	}
	hosts, excluded := workloadclaims.NodeHostCIDRs(items)
	if len(excluded) > 0 {
		return fmt.Errorf("node address(es) inside the pod range: %s — node and pod addresses are not separable on this cluster, so the sandbox-digests callback cannot be bounded by address", strings.Join(excluded, ", "))
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no node reported a routable InternalIP")
	}
	return nil
}

// inferPodInventoryCIDRs derives the pod range(s) CDS may dial for a sandbox's
// admission inventory under --cvm-mode=pod.
//
// The pod range is the right boundary here, not a weaker one: what stops a
// workload standing in for its guest's inventory in pod mode is not the
// address (workload and inventory share the guest's IP) but the RA-TLS
// handshake CDS runs against the inventory endpoint, whose leaf only the
// guest's own attested mesh identity can present. The address bound keeps the
// callback inside the cluster's pod network and nothing else.
//
// Read from spec.podCIDRs, which the cluster populates when kube-controller-
// manager allocates node ranges. CNIs with their own IPAM (Calico, Cilium
// cluster-pool) leave it empty; that is a hard error pointing at --node-cidr
// rather than a guess.
func inferPodInventoryCIDRs(ctx context.Context) ([]string, error) {
	nodes, err := fetchNodes(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var cidrs []string
	for _, n := range nodes.Items {
		for _, c := range append([]string{n.Spec.PodCIDR}, n.Spec.PodCIDRs...) {
			if c == "" {
				continue
			}
			_, network, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("node %s: podCIDR %q: %w", n.Name, c, err)
			}
			if !seen[network.String()] {
				seen[network.String()] = true
				cidrs = append(cidrs, network.String())
			}
		}
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no node reports a spec.podCIDR (the CNI runs its own IPAM)")
	}
	return cidrs, nil
}

func fetchNodes(ctx context.Context) (*corev1.NodeList, error) {
	out, err := fetchNodeJSON(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubectl get nodes: %w", withStderr(err))
	}
	var nodes corev1.NodeList
	if err := json.Unmarshal(out, &nodes); err != nil {
		return nil, fmt.Errorf("parse node list: %w", err)
	}
	return &nodes, nil
}

// fetchNodeJSON reads the cluster's node list. It is a package variable only so
// tests can drive the parse and failure paths without a cluster.
var fetchNodeJSON = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "json").Output()
}
