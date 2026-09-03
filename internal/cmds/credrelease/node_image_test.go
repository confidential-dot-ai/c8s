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

	"github.com/confidential-dot-ai/c8s/internal/cmds/policymeasure"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
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
	// The policy dir is the measurer's output; the unit must read the one the
	// measurer writes and be ordered after it, and start on either disk.
	if dir, _ := flags.GetString("policy-dir"); dir != policybundle.DefaultPolicyDir {
		t.Errorf("baked --policy-dir = %q, want %q", dir, policybundle.DefaultPolicyDir)
	}
	for _, line := range []string{
		"\nAfter=", "\nRequires=",
	} {
		_, rest, ok := strings.Cut(joined, line)
		directive, _, _ := strings.Cut(rest, "\n")
		if !ok || !slices.Contains(strings.Fields(directive), "c8s-policy-measure.service") {
			t.Errorf("cred-release.service %s does not name c8s-policy-measure.service: %q", strings.TrimSpace(line), directive)
		}
	}
	for _, cond := range []string{
		"ConditionPathExists=|" + policymeasure.DefaultOpkeyDisk,
		"ConditionPathExists=|" + policymeasure.DefaultPolicyDisk,
	} {
		if !strings.Contains(joined, "\n"+cond+"\n") {
			t.Errorf("cred-release.service lacks the OR condition %q", cond)
		}
	}
	if strings.Contains(joined, "\nConditionPathExists="+policymeasure.DefaultOpkeyDisk+"\n") {
		t.Error("cred-release.service still requires opkeydata unconditionally; static boots have no operator key")
	}
	// The unit now starts on static boots, where the initrd never creates
	// /etc/confai; a ReadOnlyPaths entry without the `-` prefix makes systemd
	// fail the mount namespace setup before ExecStart runs.
	var readOnly []string
	for _, line := range strings.Split(joined, "\n") {
		if v, ok := strings.CutPrefix(line, "ReadOnlyPaths="); ok {
			readOnly = append(readOnly, strings.Fields(v)...)
		}
	}
	confai := filepath.Dir(policymeasure.DefaultOperatorPubkey)
	if slices.Contains(readOnly, confai) || !slices.Contains(readOnly, "-"+confai) {
		t.Errorf("cred-release.service ReadOnlyPaths = %q, want -%s: the directory exists only on an opkeydata boot", readOnly, confai)
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
	// The unit's ExecStartPre waits for this binding by name so a released
	// credential is never ahead of its authorization.
	if binding.Name == "" || !strings.Contains(joined, "get clusterrolebinding "+binding.Name+" ") {
		t.Errorf("cred-release.service does not wait for ClusterRoleBinding %q before serving", binding.Name)
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
