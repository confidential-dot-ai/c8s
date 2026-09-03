package allowlist

import (
	"strings"
	"testing"
)

func str(s string) *string { return &s }

// sealedContainer is a complete rule for an unprivileged web server.
func sealedContainer(t *testing.T) Container {
	t.Helper()
	cs := []Container{{
		Digest:  mustDigest(t, digestA),
		Command: ArgvPolicy{Policy: PolicyExact, Argv: []string{"/app"}},
		Args:    ArgvPolicy{Policy: PolicyExact, Argv: []string{"serve"}},
		Mounts: MountPolicy{Policy: PolicyExact,
			Destinations: []string{"/etc/hosts", "/data", "/run/confai", "/var/run/secrets/kubernetes.io/serviceaccount"},
			Rules: map[string]MountRule{
				"/etc/hosts":  {Source: SourcePlatform},
				"/data":       {Source: SourcePVC, Review: "opaque blob store; the app never executes its contents"},
				"/run/confai": {Source: SourceNodeState, Review: "c8s sidecar; attests over the node socket"},
				"/var/run/secrets/kubernetes.io/serviceaccount": {Source: SourceServiceAccountToken, Review: "the app reads nothing there"},
			}},
		Env: EnvPolicy{Policy: PolicyExact, Names: []string{"PATH", "HOSTNAME"},
			Values: map[string]EnvValue{"PATH": {Value: str("/bin")}, "HOSTNAME": {From: FromPodName}}},
	}}
	if err := normalizeContainers("web", "containers", cs); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return cs[0]
}

func sealedObservation() Observation {
	return Observation{
		Digest: digestA,
		Argv:   []string{"/app", "serve"},
		Env:    map[string]string{"PATH": "/bin", "HOSTNAME": "web-0"},
		Mounts: map[string]MountSource{
			"/etc/hosts":  {Path: "/var/lib/kubelet/pods/u/etc-hosts", Class: SourcePlatform},
			"/data":       {Path: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~csi/pvc-1/mount", Class: SourcePVC},
			"/run/confai": {Path: "/run/confai", Class: SourceNodeState},
			"/var/run/secrets/kubernetes.io/serviceaccount": {Path: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~projected/kube-api-access-x", Class: SourceServiceAccountToken},
		},
		Sources: map[string]string{FromPodName: "web-0"},
	}
}

func TestIndexAdmit(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{"web": {Containers: []Container{sealedContainer(t)}}}}
	idx := al.BuildIndex()
	for _, tc := range []struct {
		name     string
		mutate   func(o *Observation)
		wantRule string
		wantOK   bool
	}{
		{"complete match", func(*Observation) {}, "web/containers[0]", true},
		{"no env at all is a subset", func(o *Observation) { o.Env = nil }, "web/containers[0]", true},
		{"unknown digest", func(o *Observation) { o.Digest = digestB }, "", false},
		{"argv drift", func(o *Observation) { o.Argv = []string{"/app", "serve", "--debug"} }, "", false},
		{"env value drift", func(o *Observation) { o.Env["PATH"] = "/bin:/evil" }, "", false},
		{"env from-source drift", func(o *Observation) { o.Env["HOSTNAME"] = "other" }, "", false},
		{"env from-source missing", func(o *Observation) { o.Sources = nil }, "", false},
		{"undeclared env name", func(o *Observation) { o.Env["LD_PRELOAD"] = "/x.so" }, "", false},
		{"undeclared mount", func(o *Observation) { o.Mounts["/x"] = MountSource{Path: "/tmp/x", Class: SourceEmptyDir} }, "", false},
		{"mount class drift", func(o *Observation) { o.Mounts["/data"] = MountSource{Path: "/etc", Class: SourceHostPath} }, "", false},
		{"node state bind where a platform rule stands", func(o *Observation) {
			o.Mounts["/etc/hosts"] = MountSource{Path: "/run/confai/attestation-api.sock", Class: SourceNodeState}
		}, "", false},
		{"platform bind where a nodeState rule stands", func(o *Observation) {
			o.Mounts["/run/confai"] = MountSource{Path: "/var/lib/kubelet/pods/u/etc-hosts", Class: SourcePlatform}
		}, "", false},
		{"hostPath bind where a nodeState rule stands", func(o *Observation) {
			o.Mounts["/run/confai"] = MountSource{Path: "/run/confai-evil", Class: SourceHostPath}
		}, "", false},
		{"configMap at a declared destination", func(o *Observation) {
			o.Mounts["/etc/hosts"] = MountSource{Path: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~configmap/c", Class: "configMap"}
		}, "", false},
		{"hooks present", func(o *Observation) { o.Hooks = true }, "", false},
		{"privileged", func(o *Observation) { o.Privileged = true }, "", false},
		{"host namespace", func(o *Observation) { o.HostNamespaces = []string{HostNamespaceNet} }, "", false},
		{"device", func(o *Observation) { o.Devices = []string{"/dev/tdx_guest"} }, "", false},
		{"capability", func(o *Observation) { o.Capabilities = []string{"CAP_NET_ADMIN"} }, "", false},
		{"unmasked proc", func(o *Observation) { o.UnmaskedProc = true }, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := sealedObservation()
			tc.mutate(&obs)
			rule, ok := idx.Admit(obs)
			if rule != tc.wantRule || ok != tc.wantOK {
				t.Errorf("Admit(%s) = (%q, %v), want (%q, %v)", tc.name, rule, ok, tc.wantRule, tc.wantOK)
			}
		})
	}
}

func TestIndexAdmit_Privileged(t *testing.T) {
	cs := []Container{{
		Digest:  mustDigest(t, digestB),
		Command: ArgvPolicy{Policy: PolicyExact, Argv: []string{"/cilium-agent"}},
		Args:    ArgvPolicy{Policy: PolicyExact, Argv: []string{"--config-dir=/tmp/cm"}},
		Mounts: MountPolicy{Policy: PolicyExact, Destinations: []string{"/host/etc/cni", "/run/cilium", "/tmp/cm"},
			Rules: map[string]MountRule{
				"/host/etc/cni": {Source: SourceHostPath, Path: "/etc/cni/net.d"},
				"/run/cilium":   {Source: SourceEmptyDir},
				"/tmp/cm":       {Source: SourceHostPath, Path: KubeletVolumesRoot},
			}},
		Env: EnvPolicy{Policy: PolicyExact, Names: []string{"NODE"}, Values: map[string]EnvValue{"NODE": {From: FromNodeName}}},
		Privileges: &Privileges{HostNamespaces: []string{HostNamespaceNet},
			Capabilities: []string{"CAP_NET_ADMIN"}, HostPaths: []string{"/etc/cni/net.d", KubeletVolumesRoot},
			Review: "CNI agent; node TCB"},
	}, {
		Digest:     mustDigest(t, digestC),
		Command:    ArgvPolicy{Policy: PolicyExact, Argv: []string{"/device-plugin"}},
		Args:       ArgvPolicy{Policy: PolicyDeny},
		Mounts:     MountPolicy{Policy: PolicyExact, Destinations: []string{"/etc/hosts"}, Rules: map[string]MountRule{"/etc/hosts": {Source: SourcePlatform}}},
		Env:        EnvPolicy{Policy: PolicyExact, Names: []string{"PATH"}, Values: map[string]EnvValue{"PATH": {Value: str("/bin")}}},
		Privileges: &Privileges{Privileged: true, Review: "device plugin; node TCB"},
	}}
	if err := normalizeContainers("cni", "containers", cs); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{"cni": {Containers: cs}}}
	idx := al.BuildIndex()
	base := func() Observation {
		return Observation{
			Digest: digestB, Argv: []string{"/cilium-agent", "--config-dir=/tmp/cm"},
			Env:            map[string]string{"NODE": "node-a"},
			Sources:        map[string]string{FromNodeName: "node-a"},
			HostNamespaces: []string{HostNamespaceNet},
			Capabilities:   []string{"CAP_NET_ADMIN"},
			Mounts: map[string]MountSource{
				"/host/etc/cni": {Path: "/etc/cni/net.d", Class: SourceHostPath},
				"/run/cilium":   {Path: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~empty-dir/run", Class: SourceEmptyDir},
				"/tmp/cm":       {Path: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~configmap/cm", Class: "configMap"},
			},
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(o *Observation)
		wantOK bool
	}{
		{"declared privileges and host paths", func(*Observation) {}, true},
		{"hostPath outside hostPaths", func(o *Observation) { o.Mounts["/host/etc/cni"] = MountSource{Path: "/", Class: SourceHostPath} }, false},
		{"listed source at another rule's destination", func(o *Observation) {
			o.Mounts["/host/etc/cni"] = MountSource{Path: KubeletVolumesRoot + "u/volumes/kubernetes.io~secret/s", Class: "secret"}
		}, false},
		{"subtree entry admits a path under it", func(o *Observation) {
			o.Mounts["/tmp/cm"] = MountSource{Path: KubeletVolumesRoot + "u/volumes/kubernetes.io~secret/s", Class: "secret"}
		}, true},
		{"subtree entry refuses a traversal out of it", func(o *Observation) {
			o.Mounts["/tmp/cm"] = MountSource{Path: KubeletVolumesRoot + "../../../../etc/shadow", Class: "secret"}
		}, false},
		{"exact entry matches the cleaned source", func(o *Observation) {
			o.Mounts["/host/etc/cni"] = MountSource{Path: "/etc/../etc/cni/net.d", Class: SourceHostPath}
		}, true},
		{"emptyDir where a hostPath rule stands", func(o *Observation) { o.Mounts["/tmp/cm"] = MountSource{Path: "/x", Class: SourceEmptyDir} }, false},
		{"other argv on a privileged image", func(o *Observation) { o.Argv = []string{"/bin/sh", "-c", "id"} }, false},
		{"undeclared env on a privileged image", func(o *Observation) { o.Env["LD_PRELOAD"] = "/tmp/cm/x.so" }, false},
		{"undeclared host namespace", func(o *Observation) { o.HostNamespaces = append(o.HostNamespaces, HostNamespacePID) }, false},
		{"undeclared capability", func(o *Observation) { o.Capabilities = append(o.Capabilities, "CAP_SYS_ADMIN") }, false},
		{"privileged without a privileged rule", func(o *Observation) { o.Privileged = true }, false},
		{"privileged rule admits every capability and device", func(o *Observation) {
			*o = Observation{Digest: digestC, Argv: []string{"/device-plugin"}, Env: map[string]string{"PATH": "/bin"},
				Mounts:     map[string]MountSource{"/etc/hosts": {Path: "/var/lib/kubelet/pods/u/etc-hosts", Class: SourcePlatform}},
				Privileged: true, Capabilities: []string{"CAP_SYS_ADMIN"}, Devices: []string{"/dev/vfio/1"}}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := base()
			tc.mutate(&obs)
			if _, ok := idx.Admit(obs); ok != tc.wantOK {
				t.Errorf("Admit(%s) = %v, want %v", tc.name, ok, tc.wantOK)
			}
		})
	}
}

// A rule with an open policy admits nothing, privileged or not: the lint
// refuses such a document, and Admit does not rely on the lint having run.
func TestIndexAdmit_RefusesOpenPolicies(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(c *Container)
	}{
		{"command any", func(c *Container) { c.Command = ArgvPolicy{Policy: PolicyAny} }},
		{"args any", func(c *Container) { c.Args = ArgvPolicy{Policy: PolicyAny} }},
		{"env any", func(c *Container) { c.Env = EnvPolicy{Policy: PolicyAny} }},
		{"mounts any", func(c *Container) { c.Mounts = MountPolicy{Policy: PolicyAny} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := sealedContainer(t)
			c.Privileges = &Privileges{Privileged: true, Review: "node TCB"}
			tc.edit(&c)
			cs := []Container{c}
			if err := normalizeContainers("web", "containers", cs); err != nil {
				t.Fatal(err)
			}
			al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{"web": {Containers: cs}}}
			obs := sealedObservation()
			obs.Privileged = true
			if rule, ok := al.BuildIndex().Admit(obs); ok {
				t.Errorf("Admit(%s) = (%q, true), want refusal", tc.name, rule)
			}
		})
	}
}

// A floor digest admits nothing through Admit: sealed mode has no digest-only
// path, whatever the dynamic index says about the same document.
func TestIndexAdmit_IgnoresFloor(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"base"}}`)
	idx := al.BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA}) {
		t.Fatal("AdmitsContainer(floor digest) = false, want true")
	}
	if rule, ok := idx.Admit(Observation{Digest: digestA}); ok {
		t.Errorf("Admit(floor digest) = (%q, true), want refusal", rule)
	}
}

func TestSealedFieldValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Container
		want string
	}{
		{"env value and from together", Container{Env: EnvPolicy{Policy: PolicyExact, Names: []string{"A"},
			Values: map[string]EnvValue{"A": {Value: str("x"), From: FromPodIP}}}}, "mutually exclusive"},
		{"env value neither", Container{Env: EnvPolicy{Policy: PolicyExact, Names: []string{"A"},
			Values: map[string]EnvValue{"A": {}}}}, "one of value or from"},
		{"env unknown from", Container{Env: EnvPolicy{Policy: PolicyExact, Names: []string{"A"},
			Values: map[string]EnvValue{"A": {From: "moon"}}}}, "unknown from source"},
		{"env value for unlisted name", Container{Env: EnvPolicy{Policy: PolicyExact, Names: []string{"A"},
			Values: map[string]EnvValue{"B": {Value: str("x")}}}}, "names no listed name"},
		{"env name without value", Container{Env: EnvPolicy{Policy: PolicyExact, Names: []string{"A", "B"},
			Values: map[string]EnvValue{"A": {Value: str("x")}}}}, `"B" has no value`},
		{"env any with values", Container{Env: EnvPolicy{Policy: PolicyAny, Values: map[string]EnvValue{"A": {From: FromPodIP}}}}, "takes no values"},
		{"mount unknown source", Container{Mounts: MountPolicy{Policy: PolicyExact, Destinations: []string{"/a"},
			Rules: map[string]MountRule{"/a": {Source: "nfs"}}}}, "unknown source"},
		{"mount rule for unlisted destination", Container{Mounts: MountPolicy{Policy: PolicyExact, Destinations: []string{"/a"},
			Rules: map[string]MountRule{"/b": {Source: SourceEmptyDir}}}}, "names no listed destination"},
		{"mount destination without rule", Container{Mounts: MountPolicy{Policy: PolicyExact, Destinations: []string{"/a", "/b"},
			Rules: map[string]MountRule{"/a": {Source: SourceEmptyDir}}}}, `"/b" has no rule`},
		{"mount any with rules", Container{Mounts: MountPolicy{Policy: PolicyAny, Rules: map[string]MountRule{"/a": {Source: SourceEmptyDir}}}}, "takes no rules"},
		{"mount path on a reviewed source", Container{Mounts: MountPolicy{Policy: PolicyExact, Destinations: []string{"/a"},
			Rules: map[string]MountRule{"/a": {Source: SourceEmptyDir, Path: "/x"}}}}, "path is only for a hostPath source"},
		{"mount relative path", Container{Mounts: MountPolicy{Policy: PolicyExact, Destinations: []string{"/a"},
			Rules: map[string]MountRule{"/a": {Source: SourceHostPath, Path: "etc"}}}}, "not an absolute path"},
		{"privileges unknown namespace", Container{Privileges: &Privileges{HostNamespaces: []string{"uts"}}}, "unknown host namespace"},
		{"privileges capability not OCI form", Container{Privileges: &Privileges{Capabilities: []string{"NET_ADMIN"}}}, "not in OCI form"},
		{"privileges relative device", Container{Privileges: &Privileges{Devices: []string{"dev/null"}}}, "not an absolute path"},
		{"privileges relative host path", Container{Privileges: &Privileges{HostPaths: []string{"etc"}}}, "not an absolute path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.c
			c.Digest = mustDigest(t, digestA)
			err := normalizeContainers("w", "containers", []Container{c})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("normalizeContainers(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestPrivilegesNormalizeSortsAndKeepsEmptyBlock(t *testing.T) {
	cs := []Container{{Digest: mustDigest(t, digestA), Privileges: &Privileges{
		HostNamespaces: []string{HostNamespacePID, HostNamespaceNet, HostNamespaceNet},
		Capabilities:   []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN"},
	}}, {Digest: mustDigest(t, digestA), Privileges: &Privileges{}}}
	if err := normalizeContainers("w", "containers", cs); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cs[0].Privileges.HostNamespaces, ","); got != "net,pid" {
		t.Errorf("HostNamespaces = %q, want %q", got, "net,pid")
	}
	if got := strings.Join(cs[0].Privileges.Capabilities, ","); got != "CAP_NET_ADMIN,CAP_SYS_ADMIN" {
		t.Errorf("Capabilities = %q, want %q", got, "CAP_NET_ADMIN,CAP_SYS_ADMIN")
	}
	if cs[1].Privileges == nil {
		t.Error("an empty privileges block was dropped; it marks the entry as node TCB")
	}
}

// Two same-digest containers that tie on argv but differ in env must
// canonicalize identically whichever order they were written in.
func TestPolicyKeyCoversEveryField(t *testing.T) {
	a := `{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"},"env":{"policy":"exact","names":["A"]}}`
	b := `{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"},"env":{"policy":"exact","names":["B"]}}`
	ab := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[`+a+`,`+b+`]}}}`)
	ba := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[`+b+`,`+a+`]}}}`)
	x, _ := ab.Canonical()
	y, _ := ba.Canonical()
	if string(x) != string(y) {
		t.Errorf("Canonical(ab) = %s\nCanonical(ba) = %s, want equal", x, y)
	}
}

// existingDocument is a pre-sealed-schema document already in canonical form.
// Its bytes are stamped into issued leaves and hashed by verify --allowlist,
// so the schema additions must not move them.
const existingDocument = `{"schema":"c8s.allowlist/v1","digests":{"` + digestC + `":"registry.example/base@` + digestC + `"},"workloads":{"web":{"label":"registry.example/web:1","initContainers":[{"digest":"` + digestB + `","command":{"policy":"exact","argv":["/init"]},"args":{"policy":"deny"},"mounts":{"policy":"any"},"env":{"policy":"any"}}],"containers":[{"digest":"` + digestA + `","image":"registry.example/web@` + digestA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"exact","argv":["serve"]},"mounts":{"policy":"exact","destinations":["/data","/etc/hosts"]},"env":{"policy":"exact","names":["HOME","PATH"]}}],"secrets":{"policy":"allow","read":["/web/**"]}},"worker":{"initContainers":null,"containers":[{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"},"env":{"policy":"any"}}]}}}`

func TestCanonical_ExistingDocumentBytesUnchanged(t *testing.T) {
	al := mustParse(t, existingDocument)
	got, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != existingDocument {
		t.Errorf("Canonical(existing) =\n%s\nwant\n%s", got, existingDocument)
	}
}

func TestCanonical_NewFieldsRoundTrip(t *testing.T) {
	doc := `{"schema":"c8s.allowlist/v1","digests":null,"workloads":{"w":{"initContainers":null,"containers":[{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/a","/b","/c"],"rules":{"/a":{"source":"emptyDir"},"/b":{"source":"pvc","review":"why"},"/c":{"source":"hostPath","path":"/etc/"}}},"env":{"policy":"exact","names":["A","B"],"values":{"A":{"value":""},"B":{"from":"podIP"}}},"privileges":{"privileged":true,"hostNamespaces":["net"],"capabilities":["CAP_NET_ADMIN"],"devices":["/dev/x"],"hostPaths":["/etc/"],"unmaskedProc":true,"review":"r"}}]}}}`
	al := mustParse(t, doc)
	got, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != doc {
		t.Errorf("Canonical(new fields) =\n%s\nwant\n%s", got, doc)
	}
	if _, err := ParseServedJSON([]byte(doc)); err != nil {
		t.Errorf("ParseServedJSON(new fields) = %v, want nil", err)
	}
}

// The dynamic path (AdmitsContainer) keeps ignoring values, rules and
// privileges: its enforcers never observe them.
func TestAdmitsContainerIgnoresSealedFields(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{"web": {Containers: []Container{sealedContainer(t)}}}}
	idx := al.BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Argv: []string{"/app", "serve"}, EnvNames: []string{"PATH"}, BindMounts: []string{"/data"}}) {
		t.Error("AdmitsContainer(names only) = false, want true")
	}
}

func sealedDoc(t *testing.T, workloads string) []byte {
	t.Helper()
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{},"workloads":{`+workloads+`}}`)
	b, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLintSealed(t *testing.T) {
	complete := `{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},` +
		`"mounts":{"policy":"exact","destinations":["/etc/hosts"],"rules":{"/etc/hosts":{"source":"platform"}}},` +
		`"env":{"policy":"exact","names":["PATH"],"values":{"PATH":{"value":"/bin"}}}}`
	// privileged pins everything complete does and binds one host path.
	privileged := func(rule, hostPaths string) string {
		return `{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/agent"]},"args":{"policy":"deny"},` +
			`"mounts":{"policy":"exact","destinations":["/host/cni"],"rules":{"/host/cni":` + rule + `}},` +
			`"env":{"policy":"exact","names":["PATH"],"values":{"PATH":{"value":"/bin"}}},` +
			`"privileges":{"privileged":true,"hostPaths":` + hostPaths + `,"review":"node TCB"}}`
	}
	for _, tc := range []struct {
		name string
		doc  []byte
		want string // "" for clean
	}{
		{"complete unprivileged entry", sealedDoc(t, `"w":{"containers":[`+complete+`]}`), ""},
		{"privileged entry with a bound host path", sealedDoc(t, `"w":{"containers":[`+privileged(`{"source":"hostPath","path":"/etc/cni/net.d"}`, `["/etc/cni/net.d"]`)+`]}`), ""},
		{"privileged entry with a subtree host path", sealedDoc(t, `"w":{"containers":[`+privileged(`{"source":"hostPath","path":"/etc/cni/"}`, `["/etc/"]`)+`]}`), ""},
		{"hostPath rule without a path", sealedDoc(t, `"w":{"containers":[`+privileged(`{"source":"hostPath"}`, `["/etc/cni/net.d"]`)+`]}`), "hostPath rule without a path"},
		{"hostPath path outside hostPaths", sealedDoc(t, `"w":{"containers":[`+privileged(`{"source":"hostPath","path":"/etc/cni/net.d"}`, `["/opt/cni/"]`)+`]}`), "privileges.hostPaths does not cover"},
		{"hostPath subtree under an exact grant", sealedDoc(t, `"w":{"containers":[`+privileged(`{"source":"hostPath","path":"/etc/cni/"}`, `["/etc/cni"]`)+`]}`), "privileges.hostPaths does not cover"},
		{"privileged entry with an open argv", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"exact","destinations":["/a"],"rules":{"/a":{"source":"emptyDir"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}},"privileges":{"privileged":true,"review":"node TCB"}}]}`), "command must be exact"},
		{"privileged entry with open env and mounts", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"privileges":{"privileged":true,"review":"node TCB"}}]}`), "env must be exact"},
		{"serviceAccountToken with review", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/var/run/secrets/kubernetes.io/serviceaccount"],"rules":{"/var/run/secrets/kubernetes.io/serviceaccount":{"source":"serviceAccountToken","review":"reads nothing there"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), ""},
		{"serviceAccountToken without review", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/var/run/secrets/kubernetes.io/serviceaccount"],"rules":{"/var/run/secrets/kubernetes.io/serviceaccount":{"source":"serviceAccountToken"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), "serviceAccountToken bind without a review"},
		{"non-canonical bytes", append(sealedDoc(t, `"w":{"containers":[`+complete+`]}`), '\n'), "not its canonical form"},
		{"floor digest", []byte(`{"schema":"c8s.allowlist/v1","digests":{"` + digestC + `":"x"},"workloads":{}}`), "digests must be empty"},
		{"digests null", []byte(`{"schema":"c8s.allowlist/v1","digests":null,"workloads":{}}`), `"digests" must be {}`},
		{"workloads null", []byte(`{"schema":"c8s.allowlist/v1","digests":{},"workloads":null}`), `"workloads" must be an object`},
		{"store form with no entries", []byte(`{"schema":"c8s.allowlist/v1","digests":{},"workloads":{}}`), ""},
		{"command any", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/a"],"rules":{"/a":{"source":"emptyDir"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), "command must be exact"},
		{"args any", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"any"},"mounts":{"policy":"exact","destinations":["/a"],"rules":{"/a":{"source":"emptyDir"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), "args must be exact or deny"},
		{"mounts any", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), "mounts must be exact"},
		{"env any", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/a"],"rules":{"/a":{"source":"emptyDir"}}}}]}`), "env must be exact"},
		{"env without values", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/a"],"rules":{"/a":{"source":"emptyDir"}}},"env":{"policy":"exact","names":["A"]}}]}`), "carry no values"},
		{"mounts without rules", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/a"]},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), "carry no rules"},
		{"nodeState with review", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/run/confai"],"rules":{"/run/confai":{"source":"nodeState","review":"c8s sidecar"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), ""},
		{"nodeState without review", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/run/confai"],"rules":{"/run/confai":{"source":"nodeState"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), "nodeState bind without a review"},
		{"pvc without review", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/a"],"rules":{"/a":{"source":"pvc"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), "pvc without a review"},
		{"hostPath rule on unprivileged entry", sealedDoc(t, `"w":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/a"],"rules":{"/a":{"source":"hostPath"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}}}]}`), "hostPath on an unprivileged entry"},
		{"privileged without review", sealedDoc(t, `"w":{"initContainers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/a"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/a"],"rules":{"/a":{"source":"emptyDir"}}},"env":{"policy":"exact","names":["A"],"values":{"A":{"value":"x"}}},"privileges":{"privileged":true}}]}`), "privileges.review is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := LintSealed(tc.doc)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("LintSealed(%s) = %v, want nil", tc.name, err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("LintSealed(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestLintSealed_ParseError(t *testing.T) {
	if err := LintSealed([]byte(`{"schema":"other"}`)); err == nil || !strings.Contains(err.Error(), "unknown schema") {
		t.Errorf("LintSealed(bad schema) = %v, want unknown schema error", err)
	}
}
