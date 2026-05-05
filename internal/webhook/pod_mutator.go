// Package webhook contains the mutating admission webhook that injects
// the c8s init-cert container into pods opted in by annotation.
//
// The webhook reads one annotation on the pod (not its owning workload,
// not any CR — pod metadata only):
//
//	confidential.ai/cw=<workload-id>     required to opt in
//
// Pod-to-pod mTLS is handled by the node-level ratls-mesh DaemonSet
// (cmd/ratls-mesh/), so the webhook does not inject any mesh sidecar.
// Its only job is to add the init container that fetches the workload's
// own identity cert when the pod opts in.
//
// Pods without confidential.ai/cw pass through unchanged. The webhook does
// not GET any CR — sidecar injection runs whether or not a ConfidentialWorkload
// CR exists.
package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Pod annotations that drive sidecar injection.
const (
	// AnnotationWorkload opts a pod in to c8s injection. Required.
	AnnotationWorkload = "confidential.ai/cw"

	// AnnotationInjected is stamped on pods after a successful mutation
	// so re-invocations of the webhook are no-ops.
	AnnotationInjected = "confidential.ai/c8s-injected"
)

// defaultCertFSGroup is the shared group used for the injected EmptyDir
// when the pod does not already specify an fsGroup. The c8s image runs as
// the distroless nonroot UID/GID 65532, and get-cert writes tls.key 0640.
const defaultCertFSGroup int64 = 65532
const defaultCertKeyMode = "0640"
const defaultInitRunAsUser int64 = 65532
const defaultInitRunAsGroup int64 = 65532
const defaultInitRunAsNonRoot = true

// Config tunes the injector.
type Config struct {
	// OperatorImage is the c8s multi-mode binary image used for the
	// init-cert container.
	OperatorImage string

	// AssamURL points at the assam Service in-cluster.
	AssamURL string

	// AttestationServiceURL points at the node-local attestation-service.
	AttestationServiceURL string

	// AttestationServiceAPIKeySecretName/Key identifies the workload-namespace
	// Secret the init container reads for attestation-service auth.
	AttestationServiceAPIKeySecretName string
	AttestationServiceAPIKeySecretKey  string

	// CertDir is the mount path for the shared cert volume.
	CertDir string

	// CertFSGroup is applied to the pod when it does not already specify
	// fsGroup. A negative value disables fsGroup mutation.
	CertFSGroup *int64

	// CertKeyMode is passed to get-cert for the generated tls.key.
	CertKeyMode string

	// InitRunAsUser/Group/NonRoot configure the injected init container identity.
	InitRunAsUser    *int64
	InitRunAsGroup   *int64
	InitRunAsNonRoot *bool
}

// Register wires the pod mutator onto the manager's webhook server.
func Register(mgr ctrl.Manager, cfg Config) error {
	cfg = cfg.withDefaults()
	mgr.GetWebhookServer().Register("/mutate-pods", &admission.Webhook{
		Handler: &podMutator{
			decoder: admission.NewDecoder(mgr.GetScheme()),
			cfg:     cfg,
		},
	})
	return nil
}

type podMutator struct {
	decoder admission.Decoder
	cfg     Config
}

// injection captures everything the mutator decides from pod annotations.
type injection struct {
	WorkloadID string
}

// parseAnnotations returns nil if the pod isn't opted in.
func parseAnnotations(pod *corev1.Pod) *injection {
	id := pod.Annotations[AnnotationWorkload]
	if id == "" {
		return nil
	}
	return &injection{WorkloadID: id}
}

func (m *podMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	l := log.FromContext(ctx).WithValues("pod", req.Name, "ns", req.Namespace)

	pod := &corev1.Pod{}
	if err := m.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	inj := parseAnnotations(pod)
	if inj == nil {
		return admission.Allowed("no c8s annotation — passthrough")
	}
	if _, already := pod.Annotations[AnnotationInjected]; already {
		return admission.Allowed("already injected")
	}

	l.Info("injecting c8s-init-cert", "workload", inj.WorkloadID)
	mutatePod(pod, inj, m.cfg)

	raw, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, raw)
}

// mutatePod is pure — easy to unit test.
func mutatePod(pod *corev1.Pod, inj *injection, cfg Config) {
	cfg = cfg.withDefaults()
	if *cfg.CertFSGroup >= 0 {
		ensureFSGroup(pod, *cfg.CertFSGroup)
	}
	ensureVolume(pod, certsVolume())

	mountAll(pod, corev1.VolumeMount{
		Name:      "c8s-certs",
		MountPath: cfg.CertDir,
		ReadOnly:  true,
	})

	pod.Spec.InitContainers = ensureInitContainer(pod.Spec.InitContainers,
		initCertContainer(inj, cfg))

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[AnnotationInjected] = "true"
}

// initCertContainer fetches the workload's leaf cert from assam over HTTP
// using the existing get-cert subcommand.
func initCertContainer(inj *injection, cfg Config) corev1.Container {
	c := corev1.Container{
		Name:            "c8s-init-cert",
		Image:           cfg.OperatorImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args: []string{
			"get-cert",
			"--assam-url=" + cfg.AssamURL,
			"--attestation-service-url=" + cfg.AttestationServiceURL,
			"--san=" + inj.WorkloadID,
			"--out=" + filepath.Join(cfg.CertDir, "tls.crt"),
			"--key-out=" + filepath.Join(cfg.CertDir, "tls.key"),
			"--key-mode=" + cfg.CertKeyMode,
		},
		Env: []corev1.EnvVar{
			{Name: "C8S_WORKLOAD_ID", Value: inj.WorkloadID},
			{Name: "C8S_POD_NAME", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
			}},
			{Name: "C8S_POD_UID", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"},
			}},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "c8s-certs", MountPath: cfg.CertDir},
		},
		SecurityContext: initSecurityContext(cfg),
	}
	if cfg.AttestationServiceAPIKeySecretName != "" {
		key := cfg.AttestationServiceAPIKeySecretKey
		if key == "" {
			key = "apiKey"
		}
		c.Env = append(c.Env, corev1.EnvVar{
			Name: "C8S_ATTESTATION_SERVICE_API_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: cfg.AttestationServiceAPIKeySecretName},
					Key:                  key,
				},
			},
		})
	}
	return c
}

func (cfg Config) withDefaults() Config {
	if cfg.CertDir == "" {
		cfg.CertDir = "/etc/c8s/certs"
	}
	if cfg.CertFSGroup == nil {
		cfg.CertFSGroup = int64Ptr(defaultCertFSGroup)
	}
	if cfg.CertKeyMode == "" {
		cfg.CertKeyMode = defaultCertKeyMode
	}
	if cfg.InitRunAsUser == nil {
		cfg.InitRunAsUser = int64Ptr(defaultInitRunAsUser)
	}
	if cfg.InitRunAsGroup == nil {
		cfg.InitRunAsGroup = int64Ptr(defaultInitRunAsGroup)
	}
	if cfg.InitRunAsNonRoot == nil {
		cfg.InitRunAsNonRoot = boolPtr(defaultInitRunAsNonRoot)
	}
	if cfg.AttestationServiceAPIKeySecretName != "" && cfg.AttestationServiceAPIKeySecretKey == "" {
		cfg.AttestationServiceAPIKeySecretKey = "apiKey"
	}
	return cfg
}

func initSecurityContext(cfg Config) *corev1.SecurityContext {
	falseValue := false
	trueValue := true
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &falseValue,
		ReadOnlyRootFilesystem:   &trueValue,
		RunAsNonRoot:             cfg.InitRunAsNonRoot,
		RunAsUser:                cfg.InitRunAsUser,
		RunAsGroup:               cfg.InitRunAsGroup,
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}

func certsVolume() corev1.Volume {
	return corev1.Volume{
		Name: "c8s-certs",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
		},
	}
}

func ensureVolume(pod *corev1.Pod, v corev1.Volume) {
	for _, existing := range pod.Spec.Volumes {
		if existing.Name == v.Name {
			return
		}
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, v)
}

func ensureFSGroup(pod *corev1.Pod, fsGroup int64) {
	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if pod.Spec.SecurityContext.FSGroup == nil {
		pod.Spec.SecurityContext.FSGroup = &fsGroup
	}
}

func ensureInitContainer(existing []corev1.Container, c corev1.Container) []corev1.Container {
	for _, ec := range existing {
		if ec.Name == c.Name {
			return existing
		}
	}
	return append([]corev1.Container{c}, existing...)
}

func mountAll(pod *corev1.Pod, mount corev1.VolumeMount) {
	add := func(cs []corev1.Container) []corev1.Container {
		for i := range cs {
			if containerHasMount(cs[i], mount.Name) {
				continue
			}
			cs[i].VolumeMounts = append(cs[i].VolumeMounts, mount)
		}
		return cs
	}
	pod.Spec.Containers = add(pod.Spec.Containers)
	pod.Spec.InitContainers = add(pod.Spec.InitContainers)
}

func containerHasMount(c corev1.Container, name string) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return true
		}
	}
	return false
}
