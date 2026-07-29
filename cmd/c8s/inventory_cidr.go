package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// inferInventoryCIDRs derives the node addresses CDS may dial for a sandbox's
// admission inventory, as one /32 (or /128) per node.
//
// A /32 per node rather than a covering range, deliberately. The value exists to
// separate node addresses from pod addresses, and on clusters whose CNI assigns
// pod IPs from the node subnet (AWS VPC CNI, Azure CNI) every range that covers
// the nodes also covers the pods — the boundary would look configured and be
// absent. A host route matches the node and nothing else, whatever the CNI does.
//
// The cost is that this is a point-in-time snapshot: a node added later is not
// covered, and workloads on it get certificates with no sandbox ID until the
// value is refreshed. See docs/operator.md.
func inferInventoryCIDRs(ctx context.Context) ([]string, error) {
	out, err := fetchNodeJSON(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubectl get nodes: %w", err)
	}
	return inventoryCIDRsFromNodeJSON(out)
}

// fetchNodeJSON reads the cluster's node list. It is a package variable only so
// tests can drive the parse and failure paths without a cluster.
var fetchNodeJSON = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "json").Output()
}

// nodeList is the subset of `kubectl get nodes -o json` this needs.
type nodeList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			PodCIDR  string   `json:"podCIDR"`
			PodCIDRs []string `json:"podCIDRs"`
		} `json:"spec"`
		Status struct {
			Addresses []struct {
				Type    string `json:"type"`
				Address string `json:"address"`
			} `json:"addresses"`
		} `json:"status"`
	} `json:"items"`
}

// inventoryCIDRsFromNodeJSON is the parsing half, split out so it is testable
// without a cluster.
func inventoryCIDRsFromNodeJSON(raw []byte) ([]string, error) {
	var nodes nodeList
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return nil, fmt.Errorf("parse node list: %w", err)
	}

	// Pod ranges, where the cluster populates them. Not every CNI does (Calico
	// and Cilium with their own IPAM leave podCIDR empty), so this is a check
	// when available rather than something to depend on.
	var podRanges []*net.IPNet
	for _, n := range nodes.Items {
		for _, c := range append([]string{n.Spec.PodCIDR}, n.Spec.PodCIDRs...) {
			if c == "" {
				continue
			}
			if _, network, err := net.ParseCIDR(c); err == nil {
				podRanges = append(podRanges, network)
			}
		}
	}

	seen := map[string]bool{}
	var cidrs []string
	for _, n := range nodes.Items {
		for _, a := range n.Status.Addresses {
			if a.Type != "InternalIP" {
				continue
			}
			ip := net.ParseIP(a.Address)
			if ip == nil {
				continue
			}
			// The same rules CDS applies to a token's host: anything it would
			// refuse to dial is not worth emitting.
			if !ip.IsGlobalUnicast() {
				continue
			}
			for _, r := range podRanges {
				if r.Contains(ip) {
					return nil, fmt.Errorf("node %s has InternalIP %s inside the pod range %s: node and pod addresses are not separable on this cluster, so the sandbox-digests callback cannot be bounded by address. Pass --node-cidr explicitly if you have a separate node network, or leave it unset to run without sandbox identity",
						n.Metadata.Name, a.Address, r)
				}
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			c := fmt.Sprintf("%s/%d", ip.String(), bits)
			if !seen[c] {
				seen[c] = true
				cidrs = append(cidrs, c)
			}
		}
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no node reported a routable InternalIP")
	}
	return cidrs, nil
}

// resolveInventoryCIDRs returns the operator's --node-cidr when given, and
// otherwise infers one host route per node. Detection failing is fatal: the
// alternative is installing with sandbox identity silently off, which reads as
// success and leaves workload certificates carrying no sandbox ID and no
// issuance-time image gate.
func resolveInventoryCIDRs(ctx context.Context, explicit []string) ([]string, error) {
	if len(explicit) > 0 {
		return explicit, nil
	}
	cidrs, err := inferInventoryCIDRs(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not determine this cluster's node addresses for the sandbox-digests callback: %w\n\nPass --node-cidr <cidr> to set them explicitly", err)
	}
	fmt.Printf("==> sandbox-digests callback bounded to %d node address(es): %s\n", len(cidrs), strings.Join(cidrs, ", "))
	fmt.Println("    (a node added later is not covered until this is refreshed — see docs/operator.md)")
	return cidrs, nil
}
