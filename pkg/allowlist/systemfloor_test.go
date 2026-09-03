package allowlist

import (
	"strings"
	"testing"
)

const floorDoc = `{"schema":"c8s.system-floor/v1","images":[
 {"ref":"docker.io/rancher/hardened-kubernetes:v1.33.3-rke2r1-build20250723","digest":"` + digestA + `","entrypoint":["/usr/local/bin/kube-apiserver"],"cmd":null,"env":{},"mounts":{},"privileges":{"review":""}},
 {"ref":"docker.io/rancher/mirrored-pause:3.6","digest":"` + digestB + `","entrypoint":null,"cmd":["/pause"],"env":{"PATH":{"value":"/bin"}},"mounts":{"/etc/hosts":{"source":"platform"}},"privileges":{"hostNamespaces":["net"],"review":"sandbox"}},
 {"ref":"docker.io/rancher/mirrored-coredns-coredns:1.12.1","digest":"` + digestC + `","entrypoint":["/coredns"],"cmd":null,"env":{},"mounts":{},"privileges":null}
]}`

func TestSystemFloorWorkloads(t *testing.T) {
	f, err := ParseSystemFloor([]byte(floorDoc))
	if err != nil {
		t.Fatal(err)
	}
	ws, err := f.Workloads()
	if err != nil {
		t.Fatal(err)
	}
	api, ok := ws["system-hardened-kubernetes-v1.33.3-rke2r1-build20250723"]
	if !ok {
		t.Fatalf("Workloads() names = %v, want the kube-apiserver entry", keys(ws))
	}
	c := api.Containers[0]
	if c.Image != "docker.io/rancher/hardened-kubernetes@"+digestA {
		t.Errorf("Image = %q, want repo@digest", c.Image)
	}
	if c.Command.Policy != PolicyExact || c.Command.Argv[0] != "/usr/local/bin/kube-apiserver" || c.Args.Policy != PolicyDeny {
		t.Errorf("argv rule = %+v/%+v, want exact entrypoint and deny args", c.Command, c.Args)
	}
	if c.Privileges == nil || c.Privileges.Review != "" || c.Env.Policy != PolicyAny || c.Mounts.Policy != PolicyAny {
		t.Errorf("skeleton = %+v, want empty privileges and unconstrained env/mounts", c)
	}

	pause := ws["system-mirrored-pause-3.6"].Containers[0]
	if pause.Command.Policy != PolicyExact || pause.Command.Argv[0] != "/pause" || pause.Args.Policy != PolicyDeny {
		t.Errorf("cmd-only image argv rule = %+v/%+v, want the cmd as the command", pause.Command, pause.Args)
	}
	if pause.Env.Policy != PolicyExact || pause.Env.Values["PATH"].Value == nil || pause.Mounts.Rules["/etc/hosts"].Source != SourcePlatform {
		t.Errorf("completed rule = env %+v mounts %+v, want exact policies from the keys", pause.Env, pause.Mounts)
	}

	dns := ws["system-mirrored-coredns-coredns-1.12.1"].Containers[0]
	if dns.Privileges != nil {
		t.Errorf("privileges null -> %+v, want nil (an unprivileged system image)", dns.Privileges)
	}

	al := &Allowlist{Schema: Schema, Workloads: ws}
	b, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJSON(b); err != nil {
		t.Errorf("ParseJSON(Canonical(floor workloads)) = %v, want nil", err)
	}
}

// A reviewer who nulls privileges owes exact env and mounts: the sealed lint
// holds an unprivileged floor entry to the same rule as any workload.
func TestSystemFloorWorkloads_UnprivilegedNeedsCompleteRule(t *testing.T) {
	for _, tc := range []struct {
		name   string
		images string
		want   []string
	}{
		{"privileged with review passes with empty env and mounts",
			`[{"ref":"a/b:1","digest":"` + digestA + `","entrypoint":["/b"],"env":{},"mounts":{},"privileges":{"review":"node TCB"}}]`, nil},
		{"unprivileged with empty env and mounts",
			`[{"ref":"a/b:1","digest":"` + digestA + `","entrypoint":["/b"],"env":{},"mounts":{},"privileges":null}]`, []string{"mounts must be exact", "env must be exact"}},
		{"unprivileged with complete rules",
			`[{"ref":"a/b:1","digest":"` + digestA + `","entrypoint":["/b"],"env":{"PATH":{"value":"/bin"}},"mounts":{"/etc/hosts":{"source":"platform"}},"privileges":null}]`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseSystemFloor([]byte(`{"schema":"c8s.system-floor/v1","images":` + tc.images + `}`))
			if err != nil {
				t.Fatal(err)
			}
			ws, err := f.Workloads()
			if err != nil {
				t.Fatal(err)
			}
			doc, err := (&Allowlist{Schema: Schema, Digests: map[string]string{}, Workloads: ws}).Canonical()
			if err != nil {
				t.Fatal(err)
			}
			err = LintSealed(doc)
			if len(tc.want) == 0 && err != nil {
				t.Fatalf("LintSealed(%s) = %v, want nil", tc.name, err)
			}
			for _, w := range tc.want {
				if err == nil || !strings.Contains(err.Error(), w) {
					t.Errorf("LintSealed(%s) = %v, want error containing %q", tc.name, err, w)
				}
			}
		})
	}
}

func TestParseSystemFloorRejects(t *testing.T) {
	for _, tc := range []struct{ name, doc, want string }{
		{"schema", `{"schema":"x","images":[]}`, "unknown schema"},
		{"unknown field", `{"schema":"c8s.system-floor/v1","images":[],"extra":1}`, "unknown field"},
	} {
		_, err := ParseSystemFloor([]byte(tc.doc))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseSystemFloor(%s) = %v, want error containing %q", tc.name, err, tc.want)
		}
	}
}

func TestSystemFloorWorkloads_Rejects(t *testing.T) {
	for _, tc := range []struct{ name, images, want string }{
		{"bad digest", `[{"ref":"a/b:1","digest":"sha256:zz","privileges":{"review":""}}]`, "digest"},
		{"bad ref", `[{"ref":"A B","digest":"` + digestA + `","privileges":{"review":""}}]`, "ref"},
		{"duplicate name", `[{"ref":"a/b:1","digest":"` + digestA + `","privileges":{"review":""}},{"ref":"c/b:1","digest":"` + digestB + `","privileges":{"review":""}}]`, "share the entry name"},
	} {
		f, err := ParseSystemFloor([]byte(`{"schema":"c8s.system-floor/v1","images":` + tc.images + `}`))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		if _, err := f.Workloads(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Workloads(%s) = %v, want error containing %q", tc.name, err, tc.want)
		}
	}
}

func keys(m map[string]Workload) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
