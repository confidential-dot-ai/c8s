package credrelease

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	rbacv1 "k8s.io/api/rbac/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

// The node image bakes the operator identity twice: the unit spells out the
// cert flags, and the RKE2 AddOn binds that group to cluster-admin. Nothing
// else ties the two files to this package, so load both here and check they
// agree with each other and with the binary's defaults (which cmd_test.go
// pins to literals).
const (
	nodeImageCredReleaseService = "../../../node-guest-image/c8s/mkosi.extra/etc/systemd/system/cred-release.service"
	nodeImageCredReleaseDropIns = nodeImageCredReleaseService + ".d/*.conf"
	nodeImageCredReleaseRBAC    = "../../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/cred-release-rbac.yaml"
	nodeImagePSAReadyScript     = "../../../node-guest-image/c8s/mkosi.extra/usr/local/bin/psa-ready.sh"
)

func TestNodeImageCredentialReleaseConfiguration(t *testing.T) {
	unit, err := os.ReadFile(filepath.Clean(nodeImageCredReleaseService))
	if err != nil {
		t.Fatalf("read node-image credential-release service: %v", err)
	}
	// systemd continues a line only on a bare trailing backslash; one followed
	// by whitespace makes the next line a bogus directive and the unit fails
	// to load. Reject it here rather than letting the truncated ExecStart
	// parse to the binary defaults below.
	if regexp.MustCompile(`\\[ \t]+\n`).Match(unit) {
		t.Fatal("cred-release.service has a backslash followed by whitespace: not a systemd continuation")
	}
	// Join continuation lines, then take the single ExecStart.
	joined := strings.ReplaceAll(string(unit), "\\\n", " ")
	if n := strings.Count(joined, "\nExecStartPre="); n != 1 {
		t.Fatalf("ExecStartPre directive count = %d, want exactly 1", n)
	}
	if !strings.Contains(joined, "\nExecStartPre=/usr/local/bin/psa-ready.sh\n") {
		t.Fatal("cred-release.service must gate startup on /usr/local/bin/psa-ready.sh")
	}
	if n := strings.Count(joined, "\nExecStart="); n != 1 {
		t.Fatalf("ExecStart directive count = %d, want exactly 1", n)
	}
	_, rest, _ := strings.Cut(joined, "\nExecStart=")
	execStart, _, _ := strings.Cut(rest, "\n")
	args := strings.Fields(execStart)
	if len(args) < 2 || args[0] != "/usr/local/bin/c8s" || args[1] != "cred-release" {
		t.Fatalf("ExecStart = %q, want /usr/local/bin/c8s cred-release ...", execStart)
	}
	// The unit spells the identity out (see its comment); a missing flag here
	// would otherwise pass silently on the binary defaults. And the only
	// environment expansion is the platform: anything else would let a
	// drop-in's Environment= rewrite the identity out of sight of this test.
	for _, flag := range []string{"--cert-ttl", "--cert-org", "--cert-cn"} {
		if !slices.Contains(args, flag) {
			t.Errorf("ExecStart does not spell out %s", flag)
		}
	}
	for _, arg := range args {
		if strings.Contains(arg, "$") && arg != "--platform=${CRED_PLATFORM}" {
			t.Errorf("ExecStart argument %q expands the environment", arg)
		}
	}
	// Drop-ins can reset ExecStart or inject environment; mkosi.sync renders
	// one with only Environment=CRED_PLATFORM, so any baked drop-in that
	// touches Exec*/Environment* is an override this test would not see.
	dropIns, err := filepath.Glob(nodeImageCredReleaseDropIns)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range dropIns {
		conf, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(conf), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Exec") || strings.HasPrefix(line, "Environment") {
				t.Errorf("%s overrides the unit: %q", path, line)
			}
		}
	}

	// Parse the baked flags with the real command so the test sees exactly
	// what the binary sees (last-wins duplicates, --flag=value forms, ...).
	flags := NewCmd().Flags()
	if err := flags.Parse(args[2:]); err != nil {
		t.Fatalf("parse baked ExecStart flags: %v", err)
	}
	org, _ := flags.GetString("cert-org")
	cn, _ := flags.GetString("cert-cn")
	ttl, _ := flags.GetDuration("cert-ttl")
	if org != defaultCertOrg || cn != defaultCertCN || ttl != defaultCertTTL {
		t.Errorf("baked identity = O=%s CN=%s ttl=%v, want the binary defaults O=%s CN=%s ttl=%v",
			org, cn, ttl, defaultCertOrg, defaultCertCN, defaultCertTTL)
	}
	// system:* groups are apiserver-reserved; system:masters in particular
	// bypasses RBAC and cannot be revoked.
	if strings.HasPrefix(org, "system:") {
		t.Errorf("baked --cert-org %q is an apiserver-reserved group", org)
	}

	body, err := os.ReadFile(filepath.Clean(nodeImageCredReleaseRBAC))
	if err != nil {
		t.Fatalf("read node-image credential-release RBAC manifest: %v", err)
	}
	// Exactly one document: a strict typed decode reads only the first, so
	// count them separately.
	docs := yaml.NewDecoder(bytes.NewReader(body))
	if err := docs.Decode(new(yaml.Node)); err != nil {
		t.Fatalf("decode RBAC manifest: %v", err)
	}
	if err := docs.Decode(new(yaml.Node)); err != io.EOF {
		t.Fatalf("RBAC manifest must hold exactly one document (second decode: %v)", err)
	}
	var binding rbacv1.ClusterRoleBinding
	if err := sigsyaml.UnmarshalStrict(body, &binding); err != nil {
		t.Fatalf("decode RBAC manifest as ClusterRoleBinding: %v", err)
	}
	if binding.APIVersion != "rbac.authorization.k8s.io/v1" || binding.Kind != "ClusterRoleBinding" {
		t.Errorf("typeMeta = %s %s, want rbac.authorization.k8s.io/v1 ClusterRoleBinding", binding.APIVersion, binding.Kind)
	}
	gate, err := os.ReadFile(filepath.Clean(nodeImagePSAReadyScript))
	if err != nil {
		t.Fatalf("read node-image PodSecurity readiness gate: %v", err)
	}
	gateInfo, err := os.Stat(filepath.Clean(nodeImagePSAReadyScript))
	if err != nil {
		t.Fatalf("stat node-image PodSecurity readiness gate: %v", err)
	}
	if gateInfo.Mode().Perm()&0o111 == 0 {
		t.Error("psa-ready.sh is not executable")
	}
	// The production gate must wait for both AddOns that authorize and
	// constrain the released credential, then exercise the real admission
	// chain as a non-granter. node-guest-image/tests/psa-ready-test.sh executes
	// this exact script and proves these are behavior, not inert strings.
	gateText := string(gate)
	for _, want := range []string{
		"get clusterrolebinding \"$operator_binding\"",
		"get validatingadmissionpolicy \"$policy\"",
		"get validatingadmissionpolicybinding \"$policy\"",
		"--as=\"$probe_user\" create --dry-run=server",
		"probe_namespace restricted",
		"probe_namespace privileged",
		"pod-security.kubernetes.io/enforce may not be set below restricted",
	} {
		if !strings.Contains(gateText, want) {
			t.Errorf("psa-ready.sh does not contain required gate %q", want)
		}
	}
	// The gate waits for this binding by name so a released credential is
	// never ahead of its authorization.
	if binding.Name == "" || !strings.Contains(gateText, "operator_binding="+binding.Name) {
		t.Errorf("psa-ready.sh does not wait for ClusterRoleBinding %q before serving", binding.Name)
	}
	wantRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"}
	if binding.RoleRef != wantRef {
		t.Errorf("roleRef = %+v, want %+v", binding.RoleRef, wantRef)
	}
	wantSubjects := []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: org}}
	if len(binding.Subjects) != 1 || binding.Subjects[0] != wantSubjects[0] {
		t.Errorf("subjects = %+v, want %+v (the baked --cert-org group)", binding.Subjects, wantSubjects)
	}
}
