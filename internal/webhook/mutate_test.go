package webhook

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Mutate is the whole admission decision without HTTP, so a tool that
// renders rules for injected containers sees what a cluster runs.
func TestMutate(t *testing.T) {
	cfg := Config{
		GetCertImage:          "ghcr.io/confidential-dot-ai/c8s-operator:test",
		CDSURL:                "https://cds.c8s-system.svc:8443",
		WorkloadClaimsHostDir: "/run/c8s",
	}
	for _, tc := range []struct {
		name        string
		pod         corev1.Pod
		wantID      string
		wantInit    int
		wantErr     string
		wantMutated bool
	}{
		{
			name:    "passthrough without annotation",
			pod:     corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}},
			wantErr: "",
		},
		{
			name: "injects the cert containers and a namespace-derived SAN",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationWorkload: "api"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
			},
			wantID: "api", wantInit: 2, wantMutated: true,
		},
		{
			name: "refuses hostNetwork",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationWorkload: "api"}},
				Spec:       corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "app"}}},
			},
			wantErr: "must not set hostNetwork",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := tc.pod
			res, err := Mutate(&pod, "tenant", cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Mutate(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Mutate(%s) = %v, want nil", tc.name, err)
			}
			if res.WorkloadID != tc.wantID || res.Mutated() != tc.wantMutated {
				t.Errorf("Mutate(%s) = %+v, want workload %q mutated=%v", tc.name, res, tc.wantID, tc.wantMutated)
			}
			if len(pod.Spec.InitContainers) != tc.wantInit {
				t.Errorf("Mutate(%s) left %d init containers, want %d", tc.name, len(pod.Spec.InitContainers), tc.wantInit)
			}
			if tc.wantMutated {
				args := strings.Join(pod.Spec.InitContainers[0].Args, " ")
				if want := "--san=" + workloadSAN("api", "tenant") + " "; !strings.Contains(args+" ", want) {
					t.Errorf("c8s-cert args = %q, want %q (the SAN comes from the request namespace)", args, strings.TrimSpace(want))
				}
			}
		})
	}
}
