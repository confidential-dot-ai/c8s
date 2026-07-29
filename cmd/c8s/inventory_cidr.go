package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	corev1 "k8s.io/api/core/v1"
)

// resolveInventoryCIDRs returns the operator's --node-cidr when given. Unset,
// it preflights what CDS will derive at runtime and renders nothing: CDS
// bounds the callback from the live node list itself (docs/operator.md), so
// there is no install-time snapshot to go stale on scale-up. Detection
// failing is fatal: the alternative is installing with sandbox identity
// silently off, which reads as success and leaves workload certificates
// carrying no sandbox ID and no issuance-time image gate.
func resolveInventoryCIDRs(ctx context.Context, explicit []string) ([]string, error) {
	if len(explicit) > 0 {
		return explicit, nil
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
	out, err := fetchNodeJSON(ctx)
	if err != nil {
		return fmt.Errorf("kubectl get nodes: %w", err)
	}
	var nodes corev1.NodeList
	if err := json.Unmarshal(out, &nodes); err != nil {
		return fmt.Errorf("parse node list: %w", err)
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

// fetchNodeJSON reads the cluster's node list. It is a package variable only so
// tests can drive the parse and failure paths without a cluster.
var fetchNodeJSON = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "json").Output()
}
