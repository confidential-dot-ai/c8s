package webhook

import (
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	corev1 "k8s.io/api/core/v1"
)

// Under a static allowlist every injected sidecar pins CDS from its own
// quote and reaches the verifier over the node's socket, mounted read-only
// at its own path so the sealed argv names the host path. The flat pins the
// operator may still hold are not forwarded: they would put a per-cluster
// digest into an argv the bundle measures.
func TestStaticAllowlist_SidecarsPinFromOwnQuote(t *testing.T) {
	for _, tc := range []struct {
		name      string
		socketDir string
		wantDir   string
	}{
		{"default socket dir", "", DefaultAttestationSocketDir},
		{"custom socket dir", "/run/node-attest", "/run/node-attest"},
		{"trailing slash", "/run/confai/", "/run/confai"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := newInjectablePod()
			mutatePod(pod, &injection{
				WorkloadID: "api",
				Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}, Dir: "/run/c8s/secrets"},
				Volumes:    volumesSpec{Specs: []string{"data=/api/data"}, Dir: "/mnt"},
			}, Config{
				GetCertImage:          "img",
				CDSURL:                "https://cds:8443",
				AttestationApiURL:     "unix:///var/run/nri-image-policy/attestation-api.sock",
				CDSMeasurements:       []string{strings.Repeat("ab", 48)},
				CDSRTMRs:              []string{"1=" + strings.Repeat("cd", 48)},
				WorkloadClaimsHostDir: "/var/run/nri-image-policy",
				StaticAllowlist:       true,
				AttestationSocketDir:  tc.socketDir,
			})

			vol := findVolume(pod, attestationSocketVolumeName)
			if vol == nil || vol.HostPath == nil || vol.HostPath.Path != tc.wantDir || vol.HostPath.Type == nil || *vol.HostPath.Type != corev1.HostPathDirectory {
				t.Fatalf("attestation socket volume = %#v, want hostPath %s of type Directory", vol, tc.wantDir)
			}
			if pod.Spec.SecurityContext == nil || !slices.Contains(pod.Spec.SecurityContext.SupplementalGroups, workloadclaims.InventorySocketGID) {
				t.Fatalf("pod lacks supplemental group %d for the root-owned socket: %+v", workloadclaims.InventorySocketGID, pod.Spec.SecurityContext)
			}
			wantURL := "--attestation-api-url=unix://" + tc.wantDir + "/attestation-api.sock"
			for _, name := range []string{reservedCertContainerName, reservedSecretContainerName, reservedVolumeContainerName} {
				c := containerNamed(pod, name)
				if c == nil {
					t.Fatalf("no %s container injected", name)
				}
				if !hasArg(c.Args, "--cds-pins-from-own-quote") || !hasArg(c.Args, wantURL) {
					t.Errorf("%s args = %v, want --cds-pins-from-own-quote and %s", name, c.Args, wantURL)
				}
				for _, arg := range c.Args {
					for _, flat := range []string{"--cds-measurements=", "--cds-rtmrs=", "--measurements=", "--rtmrs="} {
						if strings.HasPrefix(arg, flat) {
							t.Errorf("%s forwards the flat pin %q under a static allowlist", name, arg)
						}
					}
				}
				i := slices.IndexFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool { return m.Name == attestationSocketVolumeName })
				if i < 0 || c.VolumeMounts[i].MountPath != tc.wantDir || !c.VolumeMounts[i].ReadOnly {
					t.Errorf("%s attestation socket mount = %+v, want %s read-only", name, c.VolumeMounts, tc.wantDir)
				}
			}
		})
	}
}

// Off by default: no socket volume, and the flat pins keep flowing.
func TestStaticAllowlist_OffKeepsFlatPins(t *testing.T) {
	pod := newInjectablePod()
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "img",
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://as:8400",
		CDSMeasurements:   []string{strings.Repeat("ab", 48)},
	})
	if findVolume(pod, attestationSocketVolumeName) != nil {
		t.Fatal("the attestation socket volume is injected without a static allowlist")
	}
	cert := containerNamed(pod, reservedCertContainerName)
	if hasArg(cert.Args, "--cds-pins-from-own-quote") || !hasArg(cert.Args, "--cds-measurements="+strings.Repeat("ab", 48)) {
		t.Fatalf("c8s-cert args = %v, want the flat pin and no own-quote flag", cert.Args)
	}
}
