package webhook

import (
	"os"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestEveryInjectedFetcherRetainsCompleteCDSPolicy(t *testing.T) {
	doc, err := os.ReadFile("../../pkg/measurements/testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := secretsConfig()
	cfg.CDSMeasurementsConfigJSON = string(doc)
	cfg.WorkloadClaimsHostDir = "/var/run/nri-image-policy"
	cfg.AttestationApiURL = "unix:///var/run/nri-image-policy/attestation-api.sock"
	// The operator still has flat fields for legacy initdata. They must not
	// become conflicting flags or a policy without the operator identity.
	cfg.CDSMeasurements = []string{strings.Repeat("ab", 48)}
	cfg.CDSRTMRs = []string{"1=" + strings.Repeat("cd", 48)}
	inj := &injection{}
	for name, container := range map[string]corev1.Container{
		"certificate": certContainer(inj, cfg),
		"secret":      secretContainer(inj, cfg),
		"volume":      volumeContainer(inj, cfg),
	} {
		t.Run(name, func(t *testing.T) {
			if !slices.Contains(container.Args, "--attestation-api-url=unix://"+workloadclaims.SidecarSocketDir+"/attestation-api.sock") {
				t.Fatalf("sidecar did not use the local attestation socket: %v", container.Args)
			}
			if !slices.ContainsFunc(container.VolumeMounts, func(m corev1.VolumeMount) bool {
				return m.Name == workloadClaimsVolumeName && m.ReadOnly
			}) {
				t.Fatal("sidecar did not mount the inventory socket read-only")
			}
			if !slices.Contains(container.Args, "--measurements-config-json="+string(doc)) {
				t.Fatal("injected fetcher lost the complete policy")
			}
			for _, arg := range container.Args {
				for _, prefix := range []string{"--measurements=", "--rtmrs=", "--cds-measurements=", "--cds-rtmrs="} {
					if strings.HasPrefix(arg, prefix) {
						t.Fatalf("flat fallback flag: %s", arg)
					}
				}
			}
		})
	}
}
