package webhook

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMutatePodUsesSecretRefForAttestationAPIKey(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api", TrustDomain: "default"}, Config{
		OperatorImage:                      "ghcr.io/lunal-dev/c8s-operator:test",
		AssamURL:                           "http://assam.c8s-system.svc:8080",
		AttestationServiceURL:              "http://attestation-service.c8s-system.svc:8400",
		AttestationServiceAPIKeySecretName: "c8s-attestation-service-api-key",
		AttestationServiceAPIKeySecretKey:  "apiKey",
		CertDir:                            "/etc/c8s/certs",
	})

	if len(pod.Spec.InitContainers) != 1 {
		t.Fatalf("init containers = %d, want 1", len(pod.Spec.InitContainers))
	}

	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.FSGroup == nil {
		t.Fatalf("expected injected fsGroup")
	}
	if got := *pod.Spec.SecurityContext.FSGroup; got != defaultCertFSGroup {
		t.Fatalf("fsGroup = %d, want %d", got, defaultCertFSGroup)
	}
	init := pod.Spec.InitContainers[0]
	if !hasArg(init.Args, "--key-mode=0640") {
		t.Fatalf("init args %v missing --key-mode=0640", init.Args)
	}
	if init.SecurityContext == nil {
		t.Fatalf("missing init security context")
	}
	if init.SecurityContext.AllowPrivilegeEscalation == nil || *init.SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("init container allows privilege escalation")
	}
	if init.SecurityContext.RunAsNonRoot == nil || !*init.SecurityContext.RunAsNonRoot {
		t.Fatalf("init container does not require non-root")
	}
	if init.SecurityContext.RunAsUser == nil || *init.SecurityContext.RunAsUser != defaultInitRunAsUser {
		t.Fatalf("init runAsUser = %v", init.SecurityContext.RunAsUser)
	}
	if init.SecurityContext.RunAsGroup == nil || *init.SecurityContext.RunAsGroup != defaultInitRunAsGroup {
		t.Fatalf("init runAsGroup = %v", init.SecurityContext.RunAsGroup)
	}
	if init.SecurityContext.SeccompProfile == nil || init.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("init seccomp profile = %#v", init.SecurityContext.SeccompProfile)
	}

	env, ok := findEnv(init.Env, "C8S_ATTESTATION_SERVICE_API_KEY")
	if !ok {
		t.Fatalf("missing C8S_ATTESTATION_SERVICE_API_KEY env")
	}
	if env.Value != "" {
		t.Fatalf("API key env uses literal value")
	}
	if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
		t.Fatalf("API key env does not use SecretKeyRef: %#v", env)
	}
	if got := env.ValueFrom.SecretKeyRef.Name; got != "c8s-attestation-service-api-key" {
		t.Fatalf("secret name = %q", got)
	}
	if got := env.ValueFrom.SecretKeyRef.Key; got != "apiKey" {
		t.Fatalf("secret key = %q", got)
	}
}

func TestMutatePodPreservesExistingFSGroupAndOmitsAPIKeyEnvWithoutSecretName(t *testing.T) {
	existing := int64(1234)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{FSGroup: &existing},
			Containers:      []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api", TrustDomain: "default"}, Config{
		OperatorImage:         "image",
		AssamURL:              "http://assam",
		AttestationServiceURL: "http://attestation-service",
		CertDir:               "/etc/c8s/certs",
	})

	if got := *pod.Spec.SecurityContext.FSGroup; got != existing {
		t.Fatalf("fsGroup = %d, want existing %d", got, existing)
	}
	if _, ok := findEnv(pod.Spec.InitContainers[0].Env, "C8S_ATTESTATION_SERVICE_API_KEY"); ok {
		t.Fatalf("unexpected API key env when secret name is empty")
	}
}

func TestMutatePodUsesConfiguredCertAndInitSecurity(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api", TrustDomain: "default"}, Config{
		OperatorImage:         "image",
		AssamURL:              "http://assam",
		AttestationServiceURL: "http://attestation-service",
		CertDir:               "/etc/c8s/certs",
		CertFSGroup:           int64Ptr(4242),
		CertKeyMode:           "0440",
		InitRunAsUser:         int64Ptr(0),
		InitRunAsGroup:        int64Ptr(0),
		InitRunAsNonRoot:      boolPtr(false),
	})

	if got := *pod.Spec.SecurityContext.FSGroup; got != 4242 {
		t.Fatalf("fsGroup = %d, want 4242", got)
	}
	init := pod.Spec.InitContainers[0]
	if !hasArg(init.Args, "--key-mode=0440") {
		t.Fatalf("init args %v missing --key-mode=0440", init.Args)
	}
	if got := *init.SecurityContext.RunAsUser; got != 0 {
		t.Fatalf("runAsUser = %d, want 0", got)
	}
	if got := *init.SecurityContext.RunAsGroup; got != 0 {
		t.Fatalf("runAsGroup = %d, want 0", got)
	}
	if got := *init.SecurityContext.RunAsNonRoot; got {
		t.Fatalf("runAsNonRoot = %t, want false", got)
	}
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func findEnv(envs []corev1.EnvVar, name string) (corev1.EnvVar, bool) {
	for _, env := range envs {
		if env.Name == name {
			return env, true
		}
	}
	return corev1.EnvVar{}, false
}
