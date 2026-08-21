//go:build !c8s_node

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// clusterDNSServiceSelector selects the cluster DNS Service. Distributions
// name it differently (kube-dns on kubeadm/kind/GKE/AKS/k3s,
// rke2-coredns-rke2-coredns on RKE2) and all label it this.
const clusterDNSServiceSelector = "k8s-app=kube-dns"

// resolveClusterDNSIP returns the cluster DNS Service ClusterIP to render as
// ratlsMesh.clusterDNSIP, or "" to leave the chart default standing.
//
// The cw egress guard drops every non-TCP packet except UDP/53 to this
// address, so one that the cluster's pods do not resolve against costs every
// confidential workload its DNS. The chart default is the c8s node image's
// cluster-dns, which no other distribution shares.
func resolveClusterDNSIP(ctx context.Context, cvmMode string, valueFiles []string) (string, error) {
	// --cvm-mode=pod renders ratlsMesh.enabled=false (appendKataInstallArgs);
	// the guest guard reads C8S_CLUSTER_DNS_IP, not this value.
	if cvmModeIsPod(cvmMode) {
		return "", nil
	}
	set, err := valuesFilesSetClusterDNSIP(valueFiles)
	if err != nil {
		return "", err
	}
	if set {
		return "", nil
	}
	ip, err := clusterDNSServiceIP(ctx)
	if err != nil {
		return "", fmt.Errorf("could not determine the cluster DNS ClusterIP the confidential-workload egress guard carves out UDP/53 to: %w\n\nInstall with -f setting ratlsMesh.clusterDNSIP to the nameserver a pod's /etc/resolv.conf lists — with a node-local DNS cache that is its link-local address, not the Service ClusterIP", err)
	}
	fmt.Printf("==> confidential-workload DNS carve-out scoped to %s\n", ip)
	return ip, nil
}

// valuesFilesSetClusterDNSIP reports whether any -f values file sets
// ratlsMesh.clusterDNSIP. That file then owns the address the confidential-
// workload egress guard carves out UDP/53 to, and the cluster lookup stands
// aside.
func valuesFilesSetClusterDNSIP(files []string) (bool, error) {
	for _, f := range files {
		tree, err := decodeValuesFile(f)
		if err != nil {
			return false, err
		}
		if v, err := stringAtPath(tree, "ratlsMesh.clusterDNSIP"); err == nil && v != "" {
			return true, nil
		}
	}
	return false, nil
}

// clusterDNSServiceIP reads the ClusterIP off the kube-system DNS Service.
// Zero or several is a hard error rather than a guess: the guard is fail-
// closed, so the wrong address is indistinguishable from no carve-out.
func clusterDNSServiceIP(ctx context.Context) (string, error) {
	out, err := fetchClusterDNSServiceJSON(ctx)
	if err != nil {
		return "", fmt.Errorf("kubectl get svc -n kube-system -l %s: %w", clusterDNSServiceSelector, withStderr(err))
	}
	var svcs corev1.ServiceList
	if err := json.Unmarshal(out, &svcs); err != nil {
		return "", fmt.Errorf("parse service list: %w", err)
	}
	var chosen []corev1.Service
	for _, svc := range svcs.Items {
		// Rejects "" and "None" with everything else iptables-sync refuses:
		// a value it cannot parse exits it before it writes a rule.
		if ip := net.ParseIP(svc.Spec.ClusterIP); ip == nil || ip.IsUnspecified() {
			continue
		}
		chosen = append(chosen, svc)
	}
	if len(chosen) != 1 {
		if len(chosen) == 0 {
			return "", fmt.Errorf("no Service in kube-system matching %s has a ClusterIP", clusterDNSServiceSelector)
		}
		var named []string
		for _, svc := range chosen {
			named = append(named, fmt.Sprintf("%s (%s)", svc.Name, svc.Spec.ClusterIP))
		}
		return "", fmt.Errorf("kube-system has several Services matching %s, on different ClusterIPs: %s", clusterDNSServiceSelector, strings.Join(named, ", "))
	}
	if extra := chosen[0].Spec.ClusterIPs; len(extra) > 1 {
		fmt.Fprintf(os.Stderr, "warning: %s also answers on %s; the carve-out carries one address, so confidential workloads lose DNS on that family\n",
			chosen[0].Name, strings.Join(extra[1:], ", "))
	}
	return chosen[0].Spec.ClusterIP, nil
}

// fetchClusterDNSServiceJSON reads the cluster's DNS Service(s). It is a
// package variable only so tests can drive the parse and failure paths
// without a cluster.
var fetchClusterDNSServiceJSON = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "kubectl", "get", "svc", "-n", "kube-system",
		"-l", clusterDNSServiceSelector, "-o", "json").Output()
}
