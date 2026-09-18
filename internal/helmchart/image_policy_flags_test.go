package helmchart

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestChartImagePolicyUsesCanonicalFlags(t *testing.T) {
	policy, err := filepath.Abs("../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t,
		"--set-file", "cds.measurementsConfig="+policy,
		"--set-file", "ratlsMesh.measurementsConfig="+policy,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	want := map[string]bool{"c8s-cds": false, "c8s-operator": false, "c8s-router": false, "c8s-ratls-mesh": false}
	for _, workload := range renderedPodSpecs(t, out) {
		containers := append(workload.spec.Containers, workload.spec.InitContainers...)
		for _, container := range containers {
			for _, arg := range container.Args {
				if strings.HasPrefix(arg, "--measurements-config") {
					t.Fatalf("%s/%s uses removed policy alias: %s", workload.name, container.Name, arg)
				}
				if arg == "--image-policy-file" || strings.HasPrefix(arg, "--image-policy-file=") {
					if _, expected := want[workload.name]; expected {
						want[workload.name] = true
					}
				}
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("%s did not receive its complete policy through --image-policy-file", name)
		}
	}
}
