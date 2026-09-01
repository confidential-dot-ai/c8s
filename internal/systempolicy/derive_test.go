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
	if joined := strings.Join(init.Command.Argv, " "); joined != "/prepare --once" || init.Args.Policy != allowlist.PolicyDeny {
		t.Fatalf("init argv policy = %#v / %#v", init.Command, init.Args)
	}
	if got := init.Mounts.Kinds["/etc/app/config"]; got != "configmap" {
		t.Fatalf("ConfigMap subPath kind = %q, want configmap", got)
	}
	if strings.Join(init.Env.Names, ",") != "FROM_MANIFEST,IMAGE_ONLY,PATH" {
		t.Fatalf("init env names = %v", init.Env.Names)
	}
	main := workload.Containers[0]
	if joined := strings.Join(main.Command.Argv, " "); joined != "/image-entry serve --port=8443" {
		t.Fatalf("main effective argv = %q", joined)
	}
	if got := main.Mounts.Kinds["/run/state"]; got != "host-path" {
		t.Fatalf("PVC observation class = %q, want host-path", got)
	}
	for _, c := range []allowlist.Container{init, main} {
		if contains(c.Mounts.Destinations, "/var/run/secrets/kubernetes.io/serviceaccount") {
			t.Fatal("disabled ServiceAccount token was added to exact mounts")
		}
	}
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
	if !contains(container.Mounts.Destinations, path) || container.Mounts.Kinds[path] != "projected" {
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
