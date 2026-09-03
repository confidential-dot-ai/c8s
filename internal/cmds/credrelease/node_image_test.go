package credrelease

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	nodeImageCredReleaseService = "../../../node-guest-image/c8s/mkosi.extra/etc/systemd/system/cred-release.service"
	nodeImageCredReleaseRBAC    = "../../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/cred-release-rbac.yaml"
)

type nodeImageClusterRoleBinding struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	RoleRef struct {
		APIGroup string `yaml:"apiGroup"`
		Kind     string `yaml:"kind"`
		Name     string `yaml:"name"`
	} `yaml:"roleRef"`
	Subjects []struct {
		APIGroup string `yaml:"apiGroup"`
		Kind     string `yaml:"kind"`
		Name     string `yaml:"name"`
	} `yaml:"subjects"`
}

// TestNodeImageCredentialReleaseConfiguration is an independent oracle for
// the baked privilege boundary. Keep the expected values literal: sharing
// command defaults here would let both sides drift to a privileged value.
func TestNodeImageCredentialReleaseConfiguration(t *testing.T) {
	service, err := os.ReadFile(filepath.Clean(nodeImageCredReleaseService))
	if err != nil {
		t.Fatalf("read node-image credential-release service: %v", err)
	}

	args, err := credentialReleaseExecStart(service)
	if err != nil {
		t.Fatalf("parse node-image credential-release service: %v", err)
	}
	if strings.Contains(strings.Join(args, "\x00"), "system:masters") {
		t.Fatal("credential-release ExecStart must not grant system:masters")
	}
	assertSingleNodeImageFlag(t, args, "--cert-ttl", "1h")
	assertSingleNodeImageFlag(t, args, "--cert-org", "c8s:node-operators")
	assertSingleNodeImageFlag(t, args, "--cert-cn", "operator")

	body, err := os.ReadFile(filepath.Clean(nodeImageCredReleaseRBAC))
	if err != nil {
		t.Fatalf("read node-image credential-release RBAC manifest: %v", err)
	}
	if bytes.Contains(body, []byte("system:masters")) {
		t.Fatal("credential-release RBAC manifest must not grant system:masters")
	}
	binding, err := decodeSingleNodeImageRBAC(body)
	if err != nil {
		t.Fatalf("decode node-image credential-release RBAC manifest: %v", err)
	}
	if binding.APIVersion != "rbac.authorization.k8s.io/v1" || binding.Kind != "ClusterRoleBinding" {
		t.Errorf("typeMeta = %s %s, want rbac.authorization.k8s.io/v1 ClusterRoleBinding", binding.APIVersion, binding.Kind)
	}
	if binding.Metadata.Name != "c8s-node-operators" {
		t.Errorf("binding name = %q, want c8s-node-operators", binding.Metadata.Name)
	}
	if binding.RoleRef.APIGroup != "rbac.authorization.k8s.io" || binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != "cluster-admin" {
		t.Errorf("roleRef = %#v, want ClusterRole cluster-admin in rbac.authorization.k8s.io", binding.RoleRef)
	}
	if len(binding.Subjects) != 1 {
		t.Fatalf("subjects = %#v, want exactly one group subject", binding.Subjects)
	}
	subject := binding.Subjects[0]
	if subject.APIGroup != "rbac.authorization.k8s.io" || subject.Kind != "Group" || subject.Name != "c8s:node-operators" {
		t.Errorf("subject = %#v, want Group c8s:node-operators in rbac.authorization.k8s.io", subject)
	}
}

func credentialReleaseExecStart(service []byte) ([]string, error) {
	logicalLines, err := systemdLogicalLines(string(service))
	if err != nil {
		return nil, err
	}

	var execStarts []string
	for _, line := range logicalLines {
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(key) == "ExecStart" {
			execStarts = append(execStarts, strings.TrimSpace(value))
		}
	}
	if len(execStarts) != 1 {
		return nil, fmt.Errorf("ExecStart directive count = %d, want exactly 1", len(execStarts))
	}

	args := strings.Fields(execStarts[0])
	if len(args) < 2 || args[0] != "/usr/local/bin/c8s" || args[1] != "cred-release" {
		return nil, fmt.Errorf("ExecStart command = %q, want /usr/local/bin/c8s cred-release", execStarts[0])
	}
	return args, nil
}

func systemdLogicalLines(service string) ([]string, error) {
	var logicalLines []string
	var continued []string
	for _, physicalLine := range strings.Split(strings.ReplaceAll(service, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(physicalLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		continues := strings.HasSuffix(line, "\\")
		if continues {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		}
		continued = append(continued, line)
		if !continues {
			logicalLines = append(logicalLines, strings.Join(continued, " "))
			continued = nil
		}
	}
	if len(continued) != 0 {
		return nil, fmt.Errorf("unterminated systemd line continuation")
	}
	return logicalLines, nil
}

func assertSingleNodeImageFlag(t *testing.T, args []string, flag, want string) {
	t.Helper()
	got, err := singleLongFlagValue(args, flag)
	if err != nil {
		t.Error(err)
		return
	}
	if got != want {
		t.Errorf("%s = %q, want literal %q", flag, got, want)
	}
}

func singleLongFlagValue(args []string, flag string) (string, error) {
	var values []string
	equalsPrefix := flag + "="
	for i, arg := range args {
		switch {
		case arg == flag:
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "--") {
				values = append(values, "")
			} else {
				values = append(values, args[i+1])
			}
		case strings.HasPrefix(arg, equalsPrefix):
			values = append(values, strings.TrimPrefix(arg, equalsPrefix))
		}
	}
	if len(values) != 1 {
		return "", fmt.Errorf("%s occurrence count = %d, want exactly 1", flag, len(values))
	}
	if values[0] == "" {
		return "", fmt.Errorf("%s has no value", flag)
	}
	return values[0], nil
}

func decodeSingleNodeImageRBAC(body []byte) (nodeImageClusterRoleBinding, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)

	var binding nodeImageClusterRoleBinding
	if err := decoder.Decode(&binding); err != nil {
		return binding, err
	}
	for document := 2; ; document++ {
		var extra yaml.Node
		err := decoder.Decode(&extra)
		if err == io.EOF {
			return binding, nil
		}
		if err != nil {
			return binding, fmt.Errorf("decode YAML document %d: %w", document, err)
		}
		if !emptyYAMLDocument(&extra) {
			return binding, fmt.Errorf("unexpected non-empty YAML document %d", document)
		}
	}
}

func emptyYAMLDocument(document *yaml.Node) bool {
	if document == nil || len(document.Content) == 0 {
		return true
	}
	node := document
	if document.Kind == yaml.DocumentNode {
		node = document.Content[0]
	}
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null" && node.Value == ""
}

func TestCredentialReleaseExecStartParserRejectsOverrides(t *testing.T) {
	tests := []struct {
		name    string
		service string
		flag    string
	}{
		{
			name:    "missing ExecStart",
			service: "[Service]\nExecStartPre=/bin/true\n",
		},
		{
			name: "second ExecStart",
			service: "[Service]\n" +
				"ExecStart=/usr/local/bin/c8s cred-release --cert-org c8s:node-operators\n" +
				"ExecStart=/usr/local/bin/c8s cred-release --cert-org system:masters\n",
		},
		{
			name:    "separated duplicate flag",
			service: "[Service]\nExecStart=/usr/local/bin/c8s cred-release --cert-org c8s:node-operators --cert-org system:masters\n",
			flag:    "--cert-org",
		},
		{
			name:    "equals duplicate flag",
			service: "[Service]\nExecStart=/usr/local/bin/c8s cred-release --cert-org c8s:node-operators --cert-org=system:masters\n",
			flag:    "--cert-org",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, err := credentialReleaseExecStart([]byte(tt.service))
			if err == nil && tt.flag != "" {
				_, err = singleLongFlagValue(args, tt.flag)
			}
			if err == nil {
				t.Fatal("accepted ambiguous credential-release command")
			}
		})
	}
}

func TestDecodeSingleNodeImageRBACRejectsAmbiguousYAML(t *testing.T) {
	const valid = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: c8s-node-operators
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: c8s:node-operators
`
	tests := []struct {
		name string
		body string
	}{
		{name: "duplicate field", body: valid + "kind: ServiceAccount\n"},
		{name: "unknown top-level field", body: valid + "privileged: true\n"},
		{
			name: "unknown nested field",
			body: strings.Replace(valid, "  name: c8s-node-operators\n", "  name: c8s-node-operators\n  namespace: kube-system\n", 1),
		},
		{name: "second resource", body: valid + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: hidden\n"},
		{name: "empty object document", body: valid + "---\n{}\n"},
		{name: "resource after empty document", body: valid + "---\n# empty\n---\napiVersion: v1\nkind: ConfigMap\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeSingleNodeImageRBAC([]byte(tt.body)); err == nil {
				t.Fatal("accepted ambiguous RBAC YAML")
			}
		})
	}

	if _, err := decodeSingleNodeImageRBAC([]byte(valid + "---\n# an empty trailing document is harmless\n")); err != nil {
		t.Fatalf("rejects empty trailing YAML document: %v", err)
	}
}
