package systempolicy

import (
	"context"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func fakeImageConfigs(t *testing.T, configs map[string]ImageConfig) ImageConfigSource {
	t.Helper()
	return func(_ context.Context, image string) (ImageConfig, error) {
		config, ok := configs[image]
		if !ok {
			t.Fatalf("unexpected image config request for %q", image)
		}
		return config, nil
	}
}

func TestDeriveUsesEffectiveOCIProcessAndRuntimeInputs(t *testing.T) {
	image := "registry.example/c8s/app@" + digestA
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: c8s-app
spec:
  template:
    spec:
      enableServiceLinks: false
      automountServiceAccountToken: false
      initContainers:
      - name: prepare
        image: ` + image + `
        command: ["/prepare"]
        args: ["--once"]
        env:
        - name: FROM_MANIFEST
          value: x
        volumeMounts:
        - name: config
          mountPath: /etc/app/config
          subPath: app.conf
      containers:
      - name: app
        image: ` + image + `
        args: ["serve", "--port=8443"]
        volumeMounts:
        - name: state
          mountPath: /run/state
      volumes:
      - name: config
        configMap:
          name: app
      - name: state
        persistentVolumeClaim:
          claimName: app
`
	got, err := Derive(context.Background(), []byte(manifest), fakeImageConfigs(t, map[string]ImageConfig{
		image: {Entrypoint: []string{"/image-entry"}, Cmd: []string{"image-default"}, Env: []string{"PATH=/bin", "IMAGE_ONLY=1"}},
	}))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	workload := got["c8s-app"]
	if len(workload.InitContainers) != 1 || len(workload.Containers) != 1 {
		t.Fatalf("container counts = %d/%d", len(workload.InitContainers), len(workload.Containers))
	}
	init := workload.InitContainers[0]
	if init.Name != "prepare" {
		t.Fatalf("init name = %q, want prepare", init.Name)
	}
	if joined := strings.Join(init.Command.Argv, " "); joined != "/prepare --once" || init.Args.Policy != allowlist.PolicyDeny {
		t.Fatalf("init argv policy = %#v / %#v", init.Command, init.Args)
	}
	if got := init.Mounts.Kinds["/etc/app/config"]; got != "node" {
		t.Fatalf("ConfigMap subPath provenance = %q, want node because CRI loses the source class", got)
	}
	if strings.Join(init.Env.Names, ",") != "FROM_MANIFEST,IMAGE_ONLY,PATH" {
		t.Fatalf("init env names = %v", init.Env.Names)
	}
	main := workload.Containers[0]
	if main.Name != "app" {
		t.Fatalf("main name = %q, want app", main.Name)
	}
	if joined := strings.Join(main.Command.Argv, " "); joined != "/image-entry serve --port=8443" {
		t.Fatalf("main effective argv = %q", joined)
	}
	if got := main.Mounts.Kinds["/run/state"]; got != "node" {
		t.Fatalf("PVC observation class = %q, want node", got)
	}
	for _, c := range []allowlist.Container{init, main} {
		if contains(c.Mounts.Destinations, "/var/run/secrets/kubernetes.io/serviceaccount") {
			t.Fatal("disabled ServiceAccount token was added to exact mounts")
		}
	}
}

func TestDeriveBindsFinalKubeletArgvToRuntimeEnvironment(t *testing.T) {
	image := "registry.example/c8s/app@" + digestA
	manifest := `apiVersion: apps/v1
kind: DaemonSet
metadata: {name: c8s-agent}
spec:
  template:
    spec:
      enableServiceLinks: false
      automountServiceAccountToken: false
      containers:
      - name: agent
        image: ` + image + `
        args: ["--listen=http://$(HOST_IP):8080"]
        env:
        - name: HOST_IP
          valueFrom: {fieldRef: {fieldPath: status.hostIP}}
`
	got, err := Derive(context.Background(), []byte(manifest), fakeImageConfigs(t, map[string]ImageConfig{
		image: {Entrypoint: []string{"/app/c8s", "serve"}, Env: []string{"PATH=/bin"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	c := got["c8s-agent"].Containers[0]
	wantArg := "--listen=http://$(HOST_IP):8080"
	if c.Command.Argv[len(c.Command.Argv)-1] != wantArg {
		t.Fatalf("declared argv template = %v, want %q", c.Command.Argv, wantArg)
	}
	runtimeArgv := append([]string{}, c.Command.Argv...)
	runtimeArgv[len(runtimeArgv)-1] = "--listen=http://10.0.0.7:8080"
	running := allowlist.RunningContainer{
		Name: "agent", Digest: digestA, Argv: runtimeArgv,
		BindMounts: c.Mounts.Destinations, BindMountKinds: c.Mounts.Kinds,
		EnvNames:       append(append([]string{}, c.Env.Names...), "KUBERNETES_SERVICE_HOST"),
		EnvValues:      map[string]string{"HOST_IP": "10.0.0.7"},
		MountsObserved: true, EnvObserved: true,
	}
	if !gotIndex(got).AdmitsContainer(running) {
		t.Fatal("effective CRI argv and kubelet API environment were refused")
	}
	running.EnvNames = append(running.EnvNames, "LD_PRELOAD")
	if gotIndex(got).AdmitsContainer(running) {
		t.Fatal("unrelated runtime environment injection was admitted")
	}
	running.EnvNames = running.EnvNames[:len(running.EnvNames)-1]
	running.EnvValues["HOST_IP"] = "10.0.0.8"
	if gotIndex(got).AdmitsContainer(running) {
		t.Fatal("argv was admitted with a changed downward-API environment value")
	}
	delete(running.EnvValues, "HOST_IP")
	if gotIndex(got).AdmitsContainer(running) {
		t.Fatal("argv was admitted with an ambiguous or absent downward-API value")
	}

	bad := strings.Replace(manifest, "valueFrom: {fieldRef: {fieldPath: status.hostIP}}", "value: attacker.example", 1)
	if _, err := Derive(context.Background(), []byte(bad), fakeImageConfigs(t, map[string]ImageConfig{
		image: {Entrypoint: []string{"/app/c8s", "serve"}},
	})); err == nil || !strings.Contains(err.Error(), "status.hostIP downward-API env") {
		t.Fatalf("untrusted dynamic argv source error = %v", err)
	}
}

func TestDerivePodCVMUsesProvableMountProvenance(t *testing.T) {
	image := "registry.example/c8s/app@" + digestA
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata: {name: c8s-guest}
spec:
  template:
    spec:
      runtimeClassName: kata-qemu-snp
      enableServiceLinks: false
      containers:
      - name: app
        image: ` + image + `
        volumeMounts:
        - {name: public-tls, mountPath: /public-tls}
        - {name: config, mountPath: /config}
      volumes:
      - name: public-tls
        emptyDir: {medium: Memory}
      - name: config
        configMap: {name: app}
`
	got, err := Derive(context.Background(), []byte(manifest), fakeImageConfigs(t, map[string]ImageConfig{
		image: {Entrypoint: []string{"/app"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	kinds := got["c8s-guest"].Containers[0].Mounts.Kinds
	if kinds["/public-tls"] != "private" {
		t.Fatalf("secret-bearing memory volume = %q, want private", kinds["/public-tls"])
	}
	if kinds["/config"] != "node" || kinds["/var/run/secrets/kubernetes.io/serviceaccount"] != "node" {
		t.Fatalf("guest non-tmpfs provenance made an unprovable claim: %v", kinds)
	}
}

func gotIndex(workloads map[string]allowlist.Workload) *allowlist.Index {
	return (&allowlist.Allowlist{Schema: allowlist.Schema, Workloads: workloads}).BuildIndex()
}

func TestDeriveAddsImplicitServiceAccountMount(t *testing.T) {
	image := "registry.example/c8s/app@" + digestA
	manifest := `apiVersion: apps/v1
kind: DaemonSet
metadata: {name: c8s-agent}
spec:
  template:
    spec:
      enableServiceLinks: false
      containers:
      - name: agent
        image: ` + image + `
`
	got, err := Derive(context.Background(), []byte(manifest), fakeImageConfigs(t, map[string]ImageConfig{
		image: {Entrypoint: []string{"/agent"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	container := got["c8s-agent"].Containers[0]
	path := "/var/run/secrets/kubernetes.io/serviceaccount"
	if !contains(container.Mounts.Destinations, path) || container.Mounts.Kinds[path] != "node" {
		t.Fatalf("implicit ServiceAccount mount missing: %#v", container.Mounts)
	}
}

func TestDeriveRejectsInputsThatCannotProduceExactPolicy(t *testing.T) {
	digestImage := "registry.example/c8s/app@" + digestA
	cases := []struct {
		name     string
		manifest string
		want     string
	}{
		{
			name: "service links not disabled",
			manifest: `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec: {template: {spec: {containers: [{name: app, image: "` + digestImage + `"}]}}}
`,
			want: "enableServiceLinks: false",
		},
		{
			name: "tag image",
			manifest: `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec: {template: {spec: {enableServiceLinks: false, containers: [{name: app, image: "registry.example/app:latest"}]}}}
`,
			want: "not digest-pinned",
		},
		{
			name: "envFrom",
			manifest: `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  template:
    spec:
      enableServiceLinks: false
      containers:
      - name: app
        image: "` + digestImage + `"
        envFrom:
        - configMapRef: {name: app}
`,
			want: "envFrom",
		},
		{
			name: "unsupported volume",
			manifest: `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  template:
    spec:
      enableServiceLinks: false
      containers: [{name: app, image: "` + digestImage + `"}]
      volumes:
      - name: data
        nfs: {server: example, path: /data}
`,
			want: "unsupported source",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Derive(context.Background(), []byte(tc.manifest), fakeImageConfigs(t, map[string]ImageConfig{
				digestImage: {Entrypoint: []string{"/app"}},
			}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want text %q", err, tc.want)
			}
		})
	}
}

func TestDeriveRejectsDuplicateSteadyWorkloadNames(t *testing.T) {
	image := "registry.example/app@" + digestB
	one := `apiVersion: apps/v1
kind: Deployment
metadata: {name: duplicate}
spec: {template: {spec: {enableServiceLinks: false, containers: [{name: app, image: "` + image + `"}]}}}
`
	_, err := Derive(context.Background(), []byte(one+"---\n"+strings.Replace(one, "Deployment", "DaemonSet", 1)), fakeImageConfigs(t, map[string]ImageConfig{
		image: {Entrypoint: []string{"/app"}},
	}))
	if err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("duplicate name error = %v", err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
