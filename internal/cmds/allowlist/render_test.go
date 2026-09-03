//go:build !c8s_node

package allowlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/crane/cranetest"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// chartFixture is what `helm template` produces for the pods render cares
// about: the operator (whose args configure injection), a plain deployment,
// a privileged DaemonSet with host paths, and a hook to skip.
const chartFixture = `---
# Source: c8s/templates/operator.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: c8s-operator
  namespace: c8s-system
spec:
  template:
    spec:
      enableServiceLinks: false
      containers:
        - name: operator
          image: ghcr.io/confidential-dot-ai/c8s-operator@` + digA + `
          args:
            - operator
            - --leader-election-namespace=c8s-system
            - --get-cert-image=ghcr.io/confidential-dot-ai/c8s-operator@` + digA + `
            - --cds-url=https://c8s-cds.c8s-system.svc:8443
            - --attestation-api-url=unix:///run/c8s/attestation-api.sock
            - --cds-measurements=aa
            - --cert-fs-group=65532
            - --cert-key-mode=0640
            - --get-cert-renew-interval=2h
            - --workload-claims-host-dir=/var/run/nri-image-policy
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: c8s-cds
  namespace: c8s-system
spec:
  template:
    spec:
      enableServiceLinks: false
      automountServiceAccountToken: false
      containers:
        - name: cds
          image: ghcr.io/confidential-dot-ai/cds:dev
          args: ["cds", "--listen=:8443", "--kubernetes=$(KUBERNETES_SERVICE_HOST)"]
          env:
            - name: LOG_LEVEL
              value: debug
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          volumeMounts:
            - name: data
              mountPath: /var/lib/cds
      volumes:
        - name: data
          emptyDir: {}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: c8s-attestation-api
  namespace: c8s-system
spec:
  template:
    spec:
      enableServiceLinks: false
      hostNetwork: true
      containers:
        - name: attestation-api
          image: ghcr.io/confidential-dot-ai/attestation-api:dev
          command: ["/attestation-api"]
          args: ["--node-ip=$(HOST_IP)"]
          env:
            - name: HOST_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.hostIP
          securityContext:
            privileged: true
            capabilities:
              add: [NET_ADMIN]
          volumeMounts:
            - name: dev
              mountPath: /dev/tdx_guest
            - name: config
              mountPath: /etc/attestation
            - name: runtime
              mountPath: /run/c8s
      volumes:
        - name: dev
          hostPath:
            path: /dev/tdx_guest/
        - name: config
          configMap:
            name: attestation-config
        - name: runtime
          hostPath:
            path: /var/run/nri-image-policy/
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: c8s-uninstall
  namespace: c8s-system
  annotations:
    helm.sh/hook: pre-delete
spec:
  template:
    spec:
      containers:
        - name: cleanup
          image: ghcr.io/confidential-dot-ai/c8s-operator:dev
`

const workloadsFixture = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: apps
spec:
  template:
    metadata:
      annotations:
        confidential.ai/cw: web
    spec:
      containers:
        - name: app
          image: registry.example.com/web:1.2
          env:
            - name: PORT
              value: "8080"
`

const floorFixture = `{"schema":"c8s.system-floor/v1","images":[{"ref":"docker.io/rancher/mirrored-pause:3.6","digest":"` + digC + `","entrypoint":["/pause"],"cmd":null,"env":{},"mounts":{},"privileges":{"review":"sandbox"}}]}`

// installHelm puts a helm stub on PATH that prints fixture for `template`
// and records its argv.
func installHelm(t *testing.T, fixture string) (argvFile string) {
	t.Helper()
	dir := t.TempDir()
	fixturePath := filepath.Join(dir, "rendered.yaml")
	argvFile = filepath.Join(dir, "argv")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argvFile + "\ncat " + fixturePath + "\n"
	if err := os.WriteFile(filepath.Join(dir, "helm"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argvFile
}

func renderArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	dir := t.TempDir()
	values := writeFile(t, "values.yaml", "image:\n  digest: "+digA+"\n")
	chart := filepath.Join(dir, "chart")
	if err := os.MkdirAll(chart, 0o755); err != nil {
		t.Fatal(err)
	}
	return append([]string{"render", "--sealed", "--chart-values", values, "--chart", chart}, extra...)
}

func TestRenderSealed(t *testing.T) {
	cranetest.Install(t)
	argvFile := installHelm(t, chartFixture)
	workloads := writeFile(t, "w.yaml", workloadsFixture)
	floor := writeFile(t, "floor.json", floorFixture)
	report := filepath.Join(t.TempDir(), "report.txt")

	out, stderr, err := runCmd(renderArgs(t, "--workloads", workloads, "--system-floor", floor, "--report", report)...)
	if err != nil {
		t.Fatalf("render: %v\n%s", err, stderr)
	}
	argv, _ := os.ReadFile(argvFile)
	for _, want := range []string{"template", "c8s", "--namespace", "c8s-system", "--kube-version", chartKubeVersion} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("helm argv = %q, want it to contain %q", argv, want)
		}
	}

	al, err := pkgallowlist.ParseJSON([]byte(out))
	if err != nil {
		t.Fatalf("ParseJSON(render output) = %v\n%s", err, out)
	}
	canonical, _ := al.Canonical()
	if string(canonical) != out {
		t.Errorf("render output is not canonical:\n%s", out)
	}
	if len(al.Digests) != 0 {
		t.Errorf("Digests = %v, want empty", al.Digests)
	}
	for _, name := range []string{"c8s-operator", "c8s-cds", "c8s-attestation-api", "web", "system-mirrored-pause-3.6"} {
		if _, ok := al.Workloads[name]; !ok {
			t.Errorf("Workloads lacks %q; have %v", name, sortedWorkloadNames(al.Workloads))
		}
	}
	if _, ok := al.Workloads["c8s-uninstall"]; ok {
		t.Error("a helm hook got an entry")
	}

	cds := al.Workloads["c8s-cds"].Containers[0]
	if got := strings.Join(cds.Command.Argv, " "); got != "/bin/app" || cds.Command.Policy != pkgallowlist.PolicyExact {
		t.Errorf("cds command = %s %v, want exact [/bin/app] (image entrypoint kept under template args)", cds.Command.Policy, cds.Command.Argv)
	}
	if got := strings.Join(cds.Args.Argv, " "); got != "cds --listen=:8443 --kubernetes="+defaultKubernetesServiceHost {
		t.Errorf("cds args = %q, want the template args with $(KUBERNETES_SERVICE_HOST) expanded", got)
	}
	for name, want := range map[string]pkgallowlist.EnvValue{
		"PATH":                    {Value: str("/usr/bin:/bin")},
		"APP_MODE":                {Value: str("prod")},
		"LOG_LEVEL":               {Value: str("debug")},
		"HOSTNAME":                {From: pkgallowlist.FromPodName},
		"POD_NAMESPACE":           {From: pkgallowlist.FromPodNamespace},
		"KUBERNETES_SERVICE_HOST": {Value: str(defaultKubernetesServiceHost)},
		"KUBERNETES_PORT":         {Value: str("tcp://" + defaultKubernetesServiceHost + ":443")},
	} {
		got := cds.Env.Values[name]
		if got.From != want.From || (got.Value == nil) != (want.Value == nil) || (got.Value != nil && *got.Value != *want.Value) {
			t.Errorf("cds env %s = %s, want %s", name, envRuleSummary(name, got), envRuleSummary(name, want))
		}
	}
	for dest, want := range map[string]string{
		"/var/lib/cds":         pkgallowlist.SourceEmptyDir,
		"/etc/hosts":           pkgallowlist.SourcePlatform,
		"/dev/termination-log": pkgallowlist.SourcePlatform,
	} {
		if got := cds.Mounts.Rules[dest].Source; got != want {
			t.Errorf("cds mount %s source = %q, want %q", dest, got, want)
		}
	}
	if _, ok := cds.Mounts.Rules[serviceAccountMountPath]; ok {
		t.Error("cds mounts the service account token although automountServiceAccountToken is false")
	}
	if cds.Privileges != nil {
		t.Errorf("cds privileges = %+v, want none", cds.Privileges)
	}

	api := al.Workloads["c8s-attestation-api"].Containers[0]
	if api.Privileges == nil {
		t.Fatal("attestation-api has no privileges block")
	}
	if !api.Privileges.Privileged || strings.Join(api.Privileges.HostNamespaces, ",") != "net" || strings.Join(api.Privileges.Capabilities, ",") != "CAP_NET_ADMIN" {
		t.Errorf("attestation-api privileges = %+v, want privileged, net namespace, CAP_NET_ADMIN", api.Privileges)
	}
	if got := strings.Join(api.Privileges.HostPaths, " "); got != "/dev/tdx_guest "+pkgallowlist.KubeletVolumesRoot {
		t.Errorf("attestation-api hostPaths = %q, want the cleaned device path and the kubelet volumes root", got)
	}
	if api.Mounts.Rules["/run/c8s"].Source != pkgallowlist.SourcePlatform {
		t.Errorf("/run/c8s source = %q, want platform (bound from the operator's --workload-claims-host-dir)", api.Mounts.Rules["/run/c8s"].Source)
	}
	if api.Args.Policy != pkgallowlist.PolicyAny || api.Command.Policy != pkgallowlist.PolicyExact {
		t.Errorf("attestation-api argv = %s/%s, want exact command and any args ($(HOST_IP) varies per node)", api.Command.Policy, api.Args.Policy)
	}
	if _, ok := api.Mounts.Rules[serviceAccountMountPath]; !ok {
		t.Error("attestation-api lacks the service account token mount")
	}

	web := al.Workloads["web"]
	if len(web.InitContainers) != 2 || len(web.Containers) != 1 {
		t.Fatalf("web has %d init and %d main containers, want the injected c8s-cert and c8s-cert-wait plus app", len(web.InitContainers), len(web.Containers))
	}
	var cert pkgallowlist.Container
	for _, c := range web.InitContainers {
		if len(c.Args.Argv) > 0 && c.Args.Argv[0] == "get-cert" {
			cert = c
		}
	}
	if cert.Digest.String() == "" {
		t.Fatalf("no c8s-cert rule among %+v", web.InitContainers)
	}
	if cert.Env.Values["C8S_WORKLOAD_ID"].Value == nil || *cert.Env.Values["C8S_WORKLOAD_ID"].Value != "web" {
		t.Errorf("c8s-cert C8S_WORKLOAD_ID = %+v, want literal web", cert.Env.Values["C8S_WORKLOAD_ID"])
	}
	if cert.Env.Values["HOST_IP"].From != pkgallowlist.FromHostIP || cert.Env.Values["C8S_POD_UID"].From != pkgallowlist.FromPodUID {
		t.Errorf("c8s-cert fieldRef env = %+v, want hostIP and podUID sources", cert.Env.Values)
	}
	if cert.Mounts.Rules["/etc/c8s/certs"].Source != pkgallowlist.SourceEmptyDir || cert.Mounts.Rules["/run/c8s/workload-claims"].Source != pkgallowlist.SourcePlatform {
		t.Errorf("c8s-cert mounts = %+v, want the cert emptyDir and the platform claims socket", cert.Mounts.Rules)
	}
	if !strings.Contains(strings.Join(cert.Args.Argv, " "), "--cds-measurements=aa") {
		t.Errorf("c8s-cert argv = %v, want the operator's CDS pins", cert.Args.Argv)
	}
	if cert.Privileges != nil {
		t.Errorf("c8s-cert privileges = %+v, want none", cert.Privileges)
	}

	rep, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"entry c8s-cds",
		"argv: command=exact[/bin/app] args=exact[cds --listen=:8443 --kubernetes=" + defaultKubernetesServiceHost + "]",
		"env: HOSTNAME from podName",
		"mount: /var/lib/cds source=emptyDir",
		"privileges: privileged=true hostNamespaces=[net]",
		"note: platform socket directory: /run/nri-image-policy",
		`note: pod c8s-system/c8s-attestation-api container attestation-api: hostPath "/dev/tdx_guest/" is bound as "/dev/tdx_guest"`,
		"skipped: DaemonSet c8s-system/c8s-uninstall is a helm hook",
		"warning: pod apps/web: enableServiceLinks is not false",
		"privileges.review is empty",
	} {
		if !strings.Contains(string(rep), want) {
			t.Errorf("report lacks %q:\n%s", want, rep)
		}
	}
	if strings.Contains(string(rep), "warning: pod c8s-system/c8s-cds: enableServiceLinks") {
		t.Errorf("report warns about enableServiceLinks on a pod that sets it false:\n%s", rep)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want the report in --report only", stderr)
	}
}

func str(s string) *string { return &s }

func TestRenderSealed_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fixture   string
		workloads string
		args      []string
		want      string
	}{
		{"without --sealed", chartFixture, "", []string{"render"}, "--sealed is required"},
		{"workloads without chart", chartFixture, "", []string{"render", "--sealed", "--workloads", "x"}, "--workloads needs --chart-values"},
		{"no operator in the chart", "kind: ConfigMap\nmetadata:\n  name: x\n", "", nil, "deploys no operator"},
		{"local-path claim", chartFixture + "---\nkind: PersistentVolumeClaim\nmetadata:\n  name: cds-data\nspec:\n  storageClassName: local-path\n", "", nil, "PersistentVolumeClaim cds-data uses local-path storage"},
		{"claim on the default class", chartFixture + "---\nkind: PersistentVolumeClaim\nmetadata:\n  name: cds-data\nspec:\n  accessModes: [ReadWriteOnce]\n", "", nil, "PersistentVolumeClaim cds-data uses local-path storage"},
		{"statefulset volumeClaimTemplates on the default class", chartFixture, "kind: StatefulSet\nmetadata:\n  name: db\nspec:\n  volumeClaimTemplates:\n    - metadata:\n        name: data\n      spec:\n        accessModes: [ReadWriteOnce]\n  template:\n    spec:\n      containers:\n        - name: db\n          image: registry.example.com/db:1\n", nil, "StatefulSet db volumeClaimTemplates data uses local-path storage"},
		{"ephemeral volume on the default class", chartFixture, strings.Replace(workloadsFixture, "      containers:", "      volumes:\n        - name: scratch\n          ephemeral:\n            volumeClaimTemplate:\n              spec:\n                accessModes: [ReadWriteOnce]\n      containers:", 1), nil, "Deployment web ephemeral volume scratch uses local-path storage"},
		{"unprivileged argv with a per-pod variable", chartFixture, strings.Replace(workloadsFixture, `value: "8080"`, "valueFrom:\n                fieldRef:\n                  fieldPath: status.podIP\n          args: [\"--port=$(PORT)\"]", 1), nil, "expands $(PORT)"},
		{"envFrom", chartFixture, strings.Replace(workloadsFixture, "env:", "envFrom:\n            - configMapRef:\n                name: cm\n          env:", 1), nil, "envFrom"},
		{"secretKeyRef", chartFixture, strings.Replace(workloadsFixture, `value: "8080"`, "valueFrom:\n                secretKeyRef:\n                  name: s\n                  key: k", 1), nil, "Secret"},
		{"unknown volume", chartFixture, strings.Replace(workloadsFixture, "env:", "volumeMounts:\n            - name: nope\n              mountPath: /x\n          env:", 1), nil, "names no volume"},
		{"admission refusal", chartFixture, strings.Replace(workloadsFixture, "    spec:\n", "    spec:\n      hostNetwork: true\n", 1), nil, "admission would refuse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cranetest.Install(t)
			installHelm(t, tc.fixture)
			args := tc.args
			if args == nil {
				args = renderArgs(t)
				if tc.workloads != "" {
					args = append(args, "--workloads", writeFile(t, "w.yaml", tc.workloads))
				}
			}
			_, _, err := runCmd(args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("render(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestRenderSealedRequiresHelmAndCrane(t *testing.T) {
	cranetest.Install(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "crane"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	_, _, err := runCmd(renderArgs(t)...)
	if err == nil || !strings.Contains(err.Error(), "helm") {
		t.Errorf("render without helm = %v, want a helm-not-found error", err)
	}
	t.Setenv("PATH", "")
	_, _, err = runCmd(renderArgs(t)...)
	if err == nil || !strings.Contains(err.Error(), "crane") {
		t.Errorf("render without crane = %v, want a crane-not-found error", err)
	}
}

func TestExpandEnv(t *testing.T) {
	env := kubeletEnv{literals: map[string]string{"A": "1"}, dynamic: map[string]bool{"IP": true}}
	for _, tc := range []struct{ in, want, dynamic string }{
		{"x$(A)y", "x1y", ""},
		{"$$(A)", "$(A)", ""},
		{"$(UNSET)", "$(UNSET)", ""},
		{"http://$(IP):80", "http://$(IP):80", "IP"},
	} {
		got, dynamic := expandEnv(tc.in, env)
		if got != tc.want || dynamic != tc.dynamic {
			t.Errorf("expandEnv(%q) = (%q, %q), want (%q, %q)", tc.in, got, dynamic, tc.want, tc.dynamic)
		}
	}
}

// argvRules follows the kubelet: command/args override Entrypoint/Cmd, and
// $(VAR) expands only against the Service variables and the template env,
// never the image config. A per-pod reference is admissible only for a
// privileged entry, and then the segment it lands in is unconstrained.
func TestArgvRules(t *testing.T) {
	img := &imageFacts{entrypoint: []string{"/bin/app"}, cmd: []string{"serve"}}
	cmdOnly := &imageFacts{cmd: []string{"/pause"}}
	env := kubeletEnv{
		literals: map[string]string{"KUBERNETES_SERVICE_HOST": "10.53.0.1", "PORT": "8080"},
		dynamic:  map[string]bool{"HOST_IP": true},
	}
	unconstrained := pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}
	deny := pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny}
	exact := func(argv ...string) pkgallowlist.ArgvPolicy {
		return pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: argv}
	}
	for _, tc := range []struct {
		name        string
		c           corev1.Container
		img         *imageFacts
		privileged  bool
		wantCommand pkgallowlist.ArgvPolicy
		wantArgs    pkgallowlist.ArgvPolicy
		wantErr     string
	}{
		{name: "entrypoint and cmd", img: img, wantCommand: exact("/bin/app"), wantArgs: exact("serve")},
		{name: "command drops the image cmd", c: corev1.Container{Command: []string{"/sh"}}, img: img, wantCommand: exact("/sh"), wantArgs: deny},
		{name: "command and args", c: corev1.Container{Command: []string{"/sh"}, Args: []string{"-c", "x"}}, img: img, wantCommand: exact("/sh"), wantArgs: exact("-c", "x")},
		{name: "args keep the entrypoint", c: corev1.Container{Args: []string{"--port=$(PORT)"}}, img: img, wantCommand: exact("/bin/app"), wantArgs: exact("--port=8080")},
		{name: "cmd-only image runs its cmd", img: cmdOnly, wantCommand: exact("/pause"), wantArgs: deny},
		{name: "image env is not expanded", c: corev1.Container{Args: []string{"$(PATH)"}}, img: img, wantCommand: exact("/bin/app"), wantArgs: exact("$(PATH)")},
		{name: "HOSTNAME is not expanded", c: corev1.Container{Args: []string{"$(HOSTNAME)"}}, img: img, wantCommand: exact("/bin/app"), wantArgs: exact("$(HOSTNAME)")},
		{name: "per-pod reference unprivileged", c: corev1.Container{Args: []string{"--ip=$(HOST_IP)"}}, img: img, wantErr: "args expands $(HOST_IP)"},
		{name: "per-pod reference in args privileged", c: corev1.Container{Args: []string{"--ip=$(HOST_IP)"}}, img: img, privileged: true, wantCommand: exact("/bin/app"), wantArgs: unconstrained},
		{name: "per-pod reference in command privileged", c: corev1.Container{Command: []string{"/sync", "--node-ip", "$(HOST_IP)"}}, img: img, privileged: true, wantCommand: unconstrained, wantArgs: unconstrained},
		{name: "per-pod reference in command with exact args privileged", c: corev1.Container{Command: []string{"/sync", "$(HOST_IP)"}, Args: []string{"-v"}}, img: img, privileged: true, wantCommand: unconstrained, wantArgs: unconstrained},
		{name: "per-pod reference on a cmd-only image privileged", c: corev1.Container{Args: []string{"--ip=$(HOST_IP)"}}, img: &imageFacts{}, privileged: true, wantCommand: unconstrained, wantArgs: unconstrained},
		{name: "per-pod reference on a cmd-only image unprivileged", c: corev1.Container{Args: []string{"--ip=$(HOST_IP)"}}, img: &imageFacts{}, wantErr: "args expands $(HOST_IP)"},
		{name: "no argv", img: &imageFacts{}, wantErr: "no argv"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.c
			command, args, err := argvRules(&c, tc.img, env, tc.privileged)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("argvRules(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("argvRules(%s) = %v, want nil", tc.name, err)
			}
			if got, want := containerSummary(pkgallowlist.Container{Command: command, Args: args}), containerSummary(pkgallowlist.Container{Command: tc.wantCommand, Args: tc.wantArgs}); got != want {
				t.Errorf("argvRules(%s) = %s, want %s", tc.name, got, want)
			}
		})
	}
}

func TestHostPathAsBound(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/etc/cni/net.d/", "/etc/cni/net.d"},
		{"/var/run/nri-image-policy", "/run/nri-image-policy"},
		{"/var/run/nri-image-policy/", "/run/nri-image-policy"},
		{"/var/run", "/run"},
		{"/var/runtime", "/var/runtime"},
		{"/dev/../etc", "/etc"},
	} {
		if got := hostPathAsBound(tc.in); got != tc.want {
			t.Errorf("hostPathAsBound(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLocalPathClass(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class *string
		want  bool
	}{
		{"unset means the cluster default", nil, true},
		{"empty disables dynamic provisioning", str(""), false},
		{"named", str("local-path"), true},
		{"other class", str("nfs"), false},
	} {
		if got := localPathClass(tc.class); got != tc.want {
			t.Errorf("localPathClass(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseManifests(t *testing.T) {
	ms, err := parseManifests([]byte("---\n# comment\n---\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: i\n---\nkind: CronJob\nmetadata:\n  name: j\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n            - name: c\n              image: i\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Fatalf("parseManifests = %d documents, want 2", len(ms))
	}
	for i, wantName := range []string{"p", "j"} {
		pod, ok := ms[i].pod("ns")
		if !ok || pod.Name != wantName || pod.Namespace != "ns" || len(pod.Spec.Containers) != 1 {
			t.Errorf("manifest[%d].pod() = %v %+v, want pod %s in ns with one container", i, ok, pod, wantName)
		}
	}
	if _, err := parseManifests([]byte("kind: [")); err == nil {
		t.Error("parseManifests(bad yaml) = nil, want error")
	}
}
