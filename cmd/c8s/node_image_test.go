//go:build !c8s_node

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

func TestNodeImageRender(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	for _, platform := range []string{"tdx", "sev-snp"} {
		t.Run(platform, func(t *testing.T) {
			out := t.TempDir()
			cmd := newNodeImageCmd()
			args := []string{"render", "--hardware-platform", platform, "--kube-version", "v1.34.5", "--image-digest", testDigest, "--image-repository", "registry.example.com/c8s-operator", "--output-dir", out}
			if platform == "sev-snp" {
				args = append(args, "--chart-dir", filepath.Join("..", "..", "internal", "helmchart", "c8s"))
			}
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(out, "c8s-integration.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			docs := nodeImageDocuments(t, raw)
			for _, key := range []string{
				"Namespace/c8s-system", "CustomResourceDefinition/confidentialworkloads.confidential.ai",
				"Deployment/c8s-operator", "MutatingWebhookConfiguration/c8s-pod-injector",
				"ValidatingAdmissionPolicy/c8s-cw-label-integrity", "ValidatingAdmissionPolicyBinding/c8s-cw-label-integrity",
				"ValidatingAdmissionPolicy/c8s-deny-host-namespaces", "ValidatingAdmissionPolicyBinding/c8s-deny-host-namespaces",
				"ValidatingAdmissionPolicy/c8s-deny-host-namespaces-ephemeral", "ValidatingAdmissionPolicyBinding/c8s-deny-host-namespaces-ephemeral",
				"ValidatingAdmissionPolicy/deny-ratls-mesh-uid", "ValidatingAdmissionPolicyBinding/deny-ratls-mesh-uid",
				"ValidatingAdmissionPolicy/deny-ratls-mesh-uid-ephemeral", "ValidatingAdmissionPolicyBinding/deny-ratls-mesh-uid-ephemeral",
				"NetworkPolicy/ratls-mesh-tcp-only-egress", "NetworkPolicy/c8s-operator-ingress",
			} {
				if docs[key] == nil {
					t.Errorf("missing %s", key)
				}
			}
			for _, name := range []string{"c8s-deny-host-namespaces", "c8s-deny-host-namespaces-ephemeral"} {
				if !bytes.Contains(docs["ValidatingAdmissionPolicy/"+name], []byte("AppArmor must not")) {
					t.Errorf("baked node image lost AppArmor admission in %s", name)
				}
			}
			for key := range docs {
				if strings.HasPrefix(key, "DaemonSet/") || strings.HasPrefix(key, "Pod/") || strings.HasPrefix(key, "HelmChart") || (strings.HasPrefix(key, "Deployment/") && key != "Deployment/c8s-operator") || strings.HasPrefix(key, "ConfigMap/") {
					t.Errorf("unexpected runtime resource %s", key)
				}
			}
			var namespace corev1.Namespace
			if err := yaml.Unmarshal(docs["Namespace/c8s-system"], &namespace); err != nil {
				t.Fatal(err)
			}
			if namespace.Labels["confidential.ai/baked"] != "true" {
				t.Error("missing baked namespace marker")
			}
			for _, mode := range []string{"enforce", "warn", "audit"} {
				if namespace.Labels["pod-security.kubernetes.io/"+mode] != "privileged" {
					t.Errorf("namespace missing %s label", mode)
				}
			}
			var operator appsv1.Deployment
			if err := yaml.Unmarshal(docs["Deployment/c8s-operator"], &operator); err != nil {
				t.Fatal(err)
			}
			container := operator.Spec.Template.Spec.Containers[0]
			if container.Image != "registry.example.com/c8s-operator@"+testDigest {
				t.Errorf("operator image = %s", container.Image)
			}
			for _, arg := range []string{"--attestation-api-url=unix:///var/run/nri-image-policy/attestation-api.sock", "--cds-url=$(C8S_CDS_URL)", "--measurements-config=/etc/c8s-measurements/cds.json", "--workload-claims-host-dir=/var/run/nri-image-policy"} {
				if !slices.Contains(container.Args, arg) {
					t.Errorf("operator missing %s", arg)
				}
			}
			if len(container.Env) != 1 || container.Env[0].Name != "C8S_CDS_URL" || container.Env[0].ValueFrom.ConfigMapKeyRef.Name != "c8s-node-runtime" || container.Env[0].ValueFrom.ConfigMapKeyRef.Key != "cds-url" {
				t.Errorf("operator runtime endpoint env = %+v", container.Env)
			}
			var configVolume *corev1.ConfigMapVolumeSource
			for _, volume := range operator.Spec.Template.Spec.Volumes {
				if volume.Name == "measurements-config" {
					configVolume = volume.ConfigMap
				}
			}
			if configVolume == nil || configVolume.Name != "c8s-node-runtime" || !reflect.DeepEqual(configVolume.Items, []corev1.KeyToPath{{Key: "cds.json", Path: "cds.json"}}) {
				t.Errorf("operator pin mount = %+v", configVolume)
			}
			var meshRole rbacv1.ClusterRole
			if err := yaml.Unmarshal(docs["ClusterRole/c8s-ratls-mesh"], &meshRole); err != nil {
				t.Fatal(err)
			}
			wantRules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}}}
			if !reflect.DeepEqual(meshRole.Rules, wantRules) {
				t.Errorf("mesh role = %+v", meshRole.Rules)
			}
			var binding rbacv1.ClusterRoleBinding
			if err := yaml.Unmarshal(docs["ClusterRoleBinding/c8s-ratls-mesh"], &binding); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(binding.Subjects, []rbacv1.Subject{{Kind: "Group", Name: "system:nodes", APIGroup: "rbac.authorization.k8s.io"}}) {
				t.Errorf("mesh role subjects = %+v", binding.Subjects)
			}
			nginx, err := os.ReadFile(filepath.Join(out, "nginx.conf.in"))
			if err != nil {
				t.Fatal(err)
			}
			for _, directive := range []string{"listen 443 ssl;", "server_name c8s-node.invalid;", "pid /run/nginx.pid;", "error_log stderr warn;", "access_log syslog:server=unix:/dev/log,tag=c8s-nginx,nohostname main;", "/run/c8s-tls/cert.pem", "/run/c8s-tls/key.pem", "/run/c8s-tls/ca.pem", "/run/c8s-tls/discovery.json", "location = /allowlist", "limit_req zone=allowlist_write", "127.0.0.1:8801", "127.0.0.1:8800", "location /healthz"} {
				if !bytes.Contains(nginx, []byte(directive)) {
					t.Errorf("nginx missing %q", directive)
				}
			}
			if bytes.Contains(nginx, []byte("/var/log/nginx/")) {
				t.Error("baked nginx still opens distribution-owned log files")
			}
			if bytes.Contains(nginx, []byte("upstream catch_all")) {
				t.Error("unexpected catch-all upstream")
			}
			seed, err := os.ReadFile(filepath.Join(out, "allowlist-seed.json"))
			if err != nil {
				t.Fatal(err)
			}
			allowlist, err := pkgallowlist.ParseJSON(seed)
			if err != nil {
				t.Fatal(err)
			}
			if len(allowlist.Workloads) != 2 {
				t.Errorf("seed has %d workloads, want operator/get-cert and the local-path helper", len(allowlist.Workloads))
			}
			if !bytes.Contains(seed, []byte("registry.example.com/c8s-operator@"+testDigest)) {
				t.Error("operator missing from seed")
			}
			var helperDigest string
			for _, workload := range allowlist.Workloads {
				for _, c := range workload.Containers {
					if strings.HasPrefix(c.Image, "busybox@") {
						helperDigest = c.Digest.String()
					}
				}
			}
			if helperDigest == "" {
				t.Fatal("local-path helper missing from the baked CDS seed")
			}
			index := allowlist.BuildIndex()
			for _, script := range []string{"/script/setup", "/script/teardown"} {
				if !index.AdmitsContainer(pkgallowlist.RunningContainer{
					Digest: helperDigest,
					Argv:   []string{"/bin/sh", script, "-p", "/opt/local-path-provisioner/pvc-123"},
				}) {
					t.Errorf("seed denies local-path helper %s", script)
				}
			}
			if index.AdmitsContainer(pkgallowlist.RunningContainer{
				Digest: helperDigest,
				Argv:   []string{"/bin/sh", "-c", "echo arbitrary command"},
			}) {
				t.Error("seed admits arbitrary busybox commands")
			}
		})
	}
}

func nodeImageDocuments(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	docs := map[string][]byte{}
	r := k8syaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	for {
		doc, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var object struct {
			metav1.TypeMeta `json:",inline"`
			Metadata        metav1.ObjectMeta `json:"metadata"`
		}
		if err := yaml.Unmarshal(doc, &object); err != nil {
			t.Fatal(err)
		}
		key := object.Kind + "/" + object.Metadata.Name
		if docs[key] != nil {
			t.Fatalf("duplicate %s", key)
		}
		docs[key] = doc
	}
	return docs
}

func TestNodeImageRenderRejectsBadInputsBeforeHelm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*nodeImageRenderConfig)
	}{
		{"platform", func(c *nodeImageRenderConfig) { c.platform = "aks" }},
		{"missing Kubernetes version", func(c *nodeImageRenderConfig) { c.kubeVersion = "" }},
		{"invalid Kubernetes version", func(c *nodeImageRenderConfig) { c.kubeVersion = "latest" }},
		{"missing digest", func(c *nodeImageRenderConfig) { c.imageDigest = "" }},
		{"tag as digest", func(c *nodeImageRenderConfig) { c.imageDigest = "main" }},
		{"tagged repository", func(c *nodeImageRenderConfig) { c.imageRepository += ":main" }},
		{"missing output", func(c *nodeImageRenderConfig) { c.outputDir = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBin(t)
			f.tool(t, "helm", "exit 99")
			cfg := nodeImageRenderConfig{platform: "tdx", kubeVersion: "v1.34.5", imageDigest: testDigest, imageRepository: "ghcr.io/confidential-dot-ai/c8s-operator", outputDir: t.TempDir()}
			tc.change(&cfg)
			if err := renderNodeImage(context.Background(), cfg); err == nil {
				t.Fatal("accepted invalid build inputs")
			}
			if calls := f.calls(t); len(calls) != 0 {
				t.Fatalf("called Helm before input validation: %v", calls)
			}
		})
	}
}

func TestNodeImageSplitRejectsIncompleteOrUnexpectedChart(t *testing.T) {
	for _, input := range []string{"", "kind: Deployment\nmetadata:\n  name: c8s-cds\n", "kind: DaemonSet\nmetadata:\n  name: ratls-mesh\n", "kind: HelmChart\nmetadata:\n  name: c8s\n"} {
		if _, _, _, err := splitNodeImageArtifacts([]byte(input)); err == nil {
			t.Errorf("accepted incomplete or unexpected render %q", input)
		}
	}
}
