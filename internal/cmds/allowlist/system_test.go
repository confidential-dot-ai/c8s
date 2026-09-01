package allowlist

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/crane/cranetest"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestDeriveSystemProducesCanonicalExactWorkload(t *testing.T) {
	cranetest.Install(t)
	image := "registry.example/c8s/agent@" + digA
	manifest := writeFile(t, "rendered.yaml", `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: c8s-agent
spec:
  template:
    spec:
      enableServiceLinks: false
      automountServiceAccountToken: false
      containers:
      - name: agent
        image: `+image+`
        args: ["run"]
        env:
        - name: MODE
          value: steady
`)

	out, _, err := runCmd("derive-system", manifest)
	if err != nil {
		t.Fatalf("derive-system: %v", err)
	}
	al, err := pkgallowlist.ParseJSON([]byte(out))
	if err != nil {
		t.Fatalf("generated output is not a strict allowlist: %v\n%s", err, out)
	}
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if out != string(canonical) {
		t.Fatal("derive-system output is not canonical")
	}
	workload, ok := al.Workloads["c8s-agent"]
	if !ok || len(workload.Containers) != 1 {
		t.Fatalf("derived workloads = %#v", al.Workloads)
	}
	container := workload.Containers[0]
	if got := strings.Join(container.Command.Argv, " "); got != "/bin/app run" {
		t.Fatalf("effective argv = %q", got)
	}
	if container.Command.Policy != pkgallowlist.PolicyExact || container.Args.Policy != pkgallowlist.PolicyDeny {
		t.Fatalf("argv policy = %#v / %#v", container.Command, container.Args)
	}
	if strings.Join(container.Env.Names, ",") != "MODE" {
		t.Fatalf("exact env names = %v", container.Env.Names)
	}
}

func TestDeriveSystemMergesBaseAndRejectsConflict(t *testing.T) {
	cranetest.Install(t)
	image := "registry.example/c8s/agent@" + digA
	manifest := writeFile(t, "rendered.yaml", `apiVersion: apps/v1
kind: Deployment
metadata: {name: c8s-agent}
spec: {template: {spec: {enableServiceLinks: false, automountServiceAccountToken: false, containers: [{name: agent, image: "`+image+`", command: ["/agent"]}]}}}
`)
	base := writeFile(t, "base.json", `{"schema":"c8s.allowlist/v1","workloads":{"application":{"containers":[`+ctrJSON(digB, "/application")+`]}}}`)
	out, _, err := runCmd("derive-system", manifest, "--base", base)
	if err != nil {
		t.Fatalf("merge base: %v", err)
	}
	al, err := pkgallowlist.ParseJSON([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := al.Workloads["application"]; !ok {
		t.Fatalf("base application entry was lost: %#v", al.Workloads)
	}
	if _, ok := al.Workloads["c8s-agent"]; !ok {
		t.Fatalf("derived system entry is missing: %#v", al.Workloads)
	}

	conflict := writeFile(t, "conflict.json", `{"schema":"c8s.allowlist/v1","workloads":{"c8s-agent":{"containers":[`+ctrJSON(digB, "/other")+`]}}}`)
	if _, _, err := runCmd("derive-system", manifest, "--base", conflict); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestDeriveSystemDoesNotContactCDS(t *testing.T) {
	cranetest.Install(t)
	manifest := writeFile(t, "empty.yaml", `apiVersion: v1
kind: Service
metadata: {name: ignored}
`)
	out, _, err := runCmd("derive-system", manifest, "--url", "https://unreachable.invalid")
	if err != nil {
		t.Fatalf("offline command used CDS options: %v", err)
	}
	if !strings.Contains(out, `"workloads":{}`) {
		t.Fatalf("unexpected output: %s", out)
	}
}
