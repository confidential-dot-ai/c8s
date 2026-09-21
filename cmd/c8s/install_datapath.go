//go:build !c8s_node

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

func preflightMeshDatapath(ctx context.Context, values map[string]any) error {
	mesh, ok := nestedMap(values, "ratlsMesh")
	if !ok || mesh["enabled"] != true {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "kubectl", "get", "daemonsets", "--all-namespaces", "-o", "json").Output()
	if err != nil {
		return fmt.Errorf("inspect mesh node datapath: %w", withStderr(err))
	}
	var agents appsv1.DaemonSetList
	if err := json.Unmarshal(out, &agents); err != nil {
		return fmt.Errorf("decode mesh datapath agents: %w", err)
	}
	for _, agent := range agents.Items {
		if isCiliumAgent(agent.Spec.Template) {
			return fmt.Errorf("ratls-mesh cannot enforce traffic on Cilium (agent %s/%s): pod-to-pod traffic bypasses host PREROUTING and FORWARD, disabling RA-TLS interception and the confidential-workload guard; use a verified host-netfilter datapath before installing the mesh", agent.Namespace, agent.Name)
		}
	}
	return nil
}

func isCiliumAgent(pod corev1.PodTemplateSpec) bool {
	if pod.Labels["k8s-app"] == "cilium" || pod.Labels["app.kubernetes.io/name"] == "cilium-agent" {
		return true
	}
	for _, container := range pod.Spec.Containers {
		image := strings.SplitN(container.Image, "@", 2)[0]
		name := image[strings.LastIndex(image, "/")+1:]
		name = strings.SplitN(name, ":", 2)[0]
		if name == "cilium" || name == "hardened-cilium" || name == "mirrored-cilium-cilium" {
			return true
		}
	}
	return false
}
