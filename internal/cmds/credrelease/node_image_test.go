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

// The node image bakes each issued identity twice: the unit spells out the
// cert flags, and an RKE2 AddOn binds that group to its ClusterRole. Nothing
// else ties the files to this package, so load them here and check they agree
// with each other and with the binary's defaults (which cmd_test.go pins to
// literals). The operator role is bounded on purpose: the baked guards exist
// to hold against the credential holder, so the role must not reach RBAC,
// admission, the PodSecurity-exempt namespaces, or the kubelet.
const (
	nodeImageCredReleaseService = "../../../node-guest-image/c8s/mkosi.extra/etc/systemd/system/cred-release.service"
	nodeImageCredReleaseDropIns = nodeImageCredReleaseService + ".d/*.conf"
	nodeImageCredReleaseRBAC    = "../../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/cred-release-rbac.yaml"
	nodeImagePSAReadyScript     = "../../../node-guest-image/c8s/mkosi.extra/usr/local/bin/psa-ready.sh"
	nodeImageLogReaderRBAC      = "../../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/log-reader-rbac.yaml"
	nodeImagePodExecPolicy      = "../../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/pod-exec-policy.yaml"
	nodeImageOperatorScope      = "../../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/operator-scope-policy.yaml"
	nodeImageRKE2Config         = "../../../node-guest-image/c8s/mkosi.extra/etc/rancher/rke2/config.yaml"
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
	for _, flag := range []string{"--cert-ttl", "--cert-org", "--cert-cn", "--log-cert-ttl", "--log-cert-org", "--log-cert-cn"} {
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
	logOrg, _ := flags.GetString("log-cert-org")
	logCN, _ := flags.GetString("log-cert-cn")
	logTTL, _ := flags.GetDuration("log-cert-ttl")
	if logOrg != defaultLogCertOrg || logCN != defaultLogCertCN || logTTL != defaultLogCertTTL {
		t.Errorf("baked log-reader identity = O=%s CN=%s ttl=%v, want the binary defaults O=%s CN=%s ttl=%v",
			logOrg, logCN, logTTL, defaultLogCertOrg, defaultLogCertCN, defaultLogCertTTL)
	}
	if logOrg == org || logCN == cn {
		t.Errorf("log-reader identity O=%s CN=%s collides with the operator's O=%s CN=%s", logOrg, logCN, org, cn)
	}
	// system:* groups are apiserver-reserved; system:masters in particular
	// bypasses RBAC and cannot be revoked.
	for _, g := range []string{org, logOrg} {
		if strings.HasPrefix(g, "system:") {
			t.Errorf("baked group %q is an apiserver-reserved group", g)
		}
	}

	operatorRole, binding := readRoleAndBinding(t, nodeImageCredReleaseRBAC)
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
	// The operator is bound to the baked bounded role, never to cluster-admin
	// (which could delete every guard) and never to a role that reaches them.
	wantRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: operatorRole.Name}
	if binding.RoleRef != wantRef || operatorRole.Name == "cluster-admin" || operatorRole.Name == "" {
		t.Errorf("roleRef = %+v, want the bounded ClusterRole %q from the same AddOn", binding.RoleRef, operatorRole.Name)
	}
	wantSubjects := []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: org}}
	if len(binding.Subjects) != 1 || binding.Subjects[0] != wantSubjects[0] {
		t.Errorf("subjects = %+v, want %+v (the baked --cert-org group)", binding.Subjects, wantSubjects)
	}
	if operatorRole.AggregationRule != nil {
		t.Error("operator ClusterRole must not aggregate: its rules must be exactly what this file says")
	}
	checkGuardedRules(t, "operator", operatorRole.Rules, operatorGuard)

	// The log-reader AddOn: exactly a ClusterRole and a ClusterRoleBinding
	// that grants the baked --log-cert-org group that role, and the role
	// reads pods and their logs but nothing that carries secrets or lets the
	// holder run code.
	logRole, logBinding := readRoleAndBinding(t, nodeImageLogReaderRBAC)
	if logBinding.RoleRef != (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: logRole.Name}) {
		t.Errorf("log-reader roleRef = %+v, want the ClusterRole %q from the same AddOn", logBinding.RoleRef, logRole.Name)
	}
	wantLogSubjects := []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: logOrg}}
	if len(logBinding.Subjects) != 1 || logBinding.Subjects[0] != wantLogSubjects[0] {
		t.Errorf("log-reader subjects = %+v, want %+v (the baked --log-cert-org group)", logBinding.Subjects, wantLogSubjects)
	}
	if !strings.Contains(gateText, "log_reader_binding="+logBinding.Name) {
		t.Errorf("psa-ready.sh does not wait for ClusterRoleBinding %q before serving", logBinding.Name)
	}
	if !strings.Contains(gateText, "get clusterrolebinding \"$log_reader_binding\"") {
		t.Error("psa-ready.sh does not get the log-reader binding")
	}
	checkGuardedRules(t, "log-reader", logRole.Rules, logReaderGuard)
	var grantsLogs bool
	for _, rule := range logRole.Rules {
		if slices.Contains(rule.Resources, "pods/log") && slices.Contains(rule.Verbs, "get") && slices.Contains(rule.APIGroups, "") {
			grantsLogs = true
		}
	}
	if !grantsLogs {
		t.Error("log-reader ClusterRole does not grant get on pods/log")
	}

	// The operator-scope AddOn re-checks the same exclusions in admission for
	// every c8s:* group; the gate waits for it and proves its deny path. Its
	// shape and expressions are tested in internal/helmchart.
	scopeText, err := os.ReadFile(filepath.Clean(nodeImageOperatorScope))
	if err != nil {
		t.Fatalf("read node-image operator-scope policy: %v", err)
	}
	for _, want := range []string{
		"kind: ValidatingAdmissionPolicy\n", "kind: ValidatingAdmissionPolicyBinding\n",
		"name: confos-operator-scope\n", "policyName: confos-operator-scope\n", "failurePolicy: Fail\n", "- Deny\n",
		"g.startsWith('c8s:')",
	} {
		if !strings.Contains(string(scopeText), want) {
			t.Errorf("operator-scope-policy.yaml does not contain %q", want)
		}
	}
	for _, want := range []string{
		"scope_policy=confos-operator-scope",
		"operator_group=" + org,
		"get validatingadmissionpolicy \"$scope_policy\"",
		"get validatingadmissionpolicybinding \"$scope_policy\"",
		"--as-group=\"$operator_group\"",
		"probe_scope default",
		"probe_scope kube-system",
		"may not write in the PodSecurity-exempt namespaces",
		// Live guards must equal their reference copies on the read-only root.
		"GUARDS_DIR=${GUARDS_DIR:-/usr/lib/confai/guards}",
		"elif ! guards_match; then",
		"replace --dry-run=server -f \"$file\"",
		"get -f \"$file\"",
		"live objects differ from the read-only reference copy",
	} {
		if !strings.Contains(gateText, want) {
			t.Errorf("psa-ready.sh does not contain required gate %q", want)
		}
	}

	// The pod-exec AddOn keeps exec/attach/port-forward/ephemeral containers
	// closed at the apiserver now that the kubelet serves logs; the gate waits
	// for both of its objects unless the dev build's .skip marker is present.
	execText, err := os.ReadFile(filepath.Clean(nodeImagePodExecPolicy))
	if err != nil {
		t.Fatalf("read node-image pod-exec policy: %v", err)
	}
	for _, want := range []string{
		"kind: ValidatingAdmissionPolicy\n", "kind: ValidatingAdmissionPolicyBinding\n",
		"name: confos-pod-exec\n", "policyName: confos-pod-exec\n", "failurePolicy: Fail\n", "- Deny\n",
		`"pods/exec"`, `"pods/attach"`, `"pods/portforward"`, `"pods/ephemeralcontainers"`, `"CONNECT"`,
	} {
		if !strings.Contains(string(execText), want) {
			t.Errorf("pod-exec-policy.yaml does not contain %q", want)
		}
	}
	for _, want := range []string{
		"exec_policy=confos-pod-exec",
		"get validatingadmissionpolicy \"$exec_policy\"",
		"get validatingadmissionpolicybinding \"$exec_policy\"",
		"pod-exec-policy.yaml.skip",
	} {
		if !strings.Contains(gateText, want) {
			t.Errorf("psa-ready.sh does not contain required gate %q", want)
		}
	}
	rke2Config, err := os.ReadFile(filepath.Clean(nodeImageRKE2Config))
	if err != nil {
		t.Fatalf("read node-image rke2 config: %v", err)
	}
	if !strings.Contains(string(rke2Config), "\n  - enable-debugging-handlers=true\n") {
		t.Error("rke2 config.yaml does not keep the kubelet debugging handlers on (kubectl logs needs them)")
	}
}

// guard is what a cred-release ClusterRole must never grant. Wildcards are
// refused outright: "*" in resources matches every subresource (nodes/proxy
// reaches the kubelet's exec endpoint with no pods/exec admission check), and
// "*" in verbs includes bind, escalate, impersonate and grant.
type guard struct {
	writeVerbs bool                // may any rule carry a write verb
	resources  map[string][]string // apiGroup -> resources refused with any verb
	writeOnly  map[string][]string // apiGroup -> resources refused with a write verb
}

var (
	writeVerbs    = []string{"create", "update", "patch", "delete", "deletecollection"}
	dangerVerbs   = []string{"*", "bind", "escalate", "impersonate", "grant", "approve", "sign"}
	proxyOrExec   = []string{"nodes/proxy", "nodes/log", "nodes/stats", "nodes/metrics", "nodes/spec", "pods/proxy", "services/proxy", "pods/exec", "pods/attach", "pods/portforward", "pods/ephemeralcontainers", "serviceaccounts/token"}
	operatorGuard = guard{
		writeVerbs: true,
		resources: map[string][]string{
			"":                proxyOrExec,
			"confidential.ai": {"podsecurityexemptions"},
		},
		writeOnly: map[string][]string{
			"":                             {"nodes", "nodes/status", "persistentvolumes"},
			"rbac.authorization.k8s.io":    {"clusterroles", "clusterrolebindings"},
			"admissionregistration.k8s.io": {"validatingadmissionpolicies", "validatingadmissionpolicybindings", "validatingwebhookconfigurations", "mutatingwebhookconfigurations", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings"},
			"storage.k8s.io":               {"storageclasses", "csidrivers", "csinodes", "volumeattachments"},
			"helm.cattle.io":               {"helmcharts", "helmchartconfigs"},
			"k3s.cattle.io":                {"addons"},
			"apiregistration.k8s.io":       {"apiservices"},
			"certificates.k8s.io":          {"certificatesigningrequests", "certificatesigningrequests/approval", "certificatesigningrequests/status", "signers"},
		},
	}
	logReaderGuard = guard{
		writeVerbs: false,
		resources: map[string][]string{
			"": append([]string{"secrets", "configmaps"}, proxyOrExec...),
		},
	}
)

func checkGuardedRules(t *testing.T, role string, rules []rbacv1.PolicyRule, g guard) {
	t.Helper()
	for _, rule := range rules {
		if slices.Contains(rule.APIGroups, "*") {
			t.Errorf("%s rule %+v spans every API group", role, rule)
		}
		if slices.Contains(rule.Resources, "*") {
			t.Errorf("%s rule %+v spans every resource (and subresource)", role, rule)
		}
		for _, res := range rule.Resources {
			if strings.HasSuffix(res, "/*") {
				t.Errorf("%s rule grants every subresource of %q", role, res)
			}
		}
		if len(rule.NonResourceURLs) != 0 {
			t.Errorf("%s rule %+v grants non-resource URLs", role, rule)
		}
		writes := false
		for _, verb := range rule.Verbs {
			if slices.Contains(dangerVerbs, verb) {
				t.Errorf("%s rule %+v grants verb %q", role, rule, verb)
			}
			if slices.Contains(writeVerbs, verb) {
				writes = true
			}
		}
		if writes && !g.writeVerbs {
			t.Errorf("%s rule %+v grants a write verb", role, rule)
		}
		for _, group := range rule.APIGroups {
			for _, res := range rule.Resources {
				if slices.Contains(g.resources[group], res) {
					t.Errorf("%s rule grants %s/%s", role, group, res)
				}
				if writes && slices.Contains(g.writeOnly[group], res) {
					t.Errorf("%s rule grants a write verb on %s/%s", role, group, res)
				}
			}
		}
	}
}

// readRoleAndBinding decodes a two-document ClusterRole + ClusterRoleBinding
// AddOn strictly.
func readRoleAndBinding(t *testing.T, path string) (rbacv1.ClusterRole, rbacv1.ClusterRoleBinding) {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read node-image RBAC manifest %s: %v", path, err)
	}
	var role rbacv1.ClusterRole
	var binding rbacv1.ClusterRoleBinding
	docs := yaml.NewDecoder(bytes.NewReader(body))
	for i := 0; ; i++ {
		var node yaml.Node
		if err := docs.Decode(&node); err == io.EOF {
			if i != 2 {
				t.Fatalf("%s holds %d documents, want a ClusterRole then a ClusterRoleBinding", path, i)
			}
			break
		} else if err != nil {
			t.Fatalf("decode %s document %d: %v", path, i, err)
		}
		raw, err := yaml.Marshal(&node)
		if err != nil {
			t.Fatal(err)
		}
		switch i {
		case 0:
			if err := sigsyaml.UnmarshalStrict(raw, &role); err != nil {
				t.Fatalf("decode %s document 0 as ClusterRole: %v", path, err)
			}
			if role.APIVersion != "rbac.authorization.k8s.io/v1" || role.Kind != "ClusterRole" {
				t.Errorf("document 0 typeMeta = %s %s, want rbac.authorization.k8s.io/v1 ClusterRole", role.APIVersion, role.Kind)
			}
		case 1:
			if err := sigsyaml.UnmarshalStrict(raw, &binding); err != nil {
				t.Fatalf("decode %s document 1 as ClusterRoleBinding: %v", path, err)
			}
			if binding.APIVersion != "rbac.authorization.k8s.io/v1" || binding.Kind != "ClusterRoleBinding" {
				t.Errorf("document 1 typeMeta = %s %s, want rbac.authorization.k8s.io/v1 ClusterRoleBinding", binding.APIVersion, binding.Kind)
			}
		}
	}
	return role, binding
}
