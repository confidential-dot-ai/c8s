package webhook

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/initdata"
)

// Classes whose guest runs the c8s in-guest stack. Plain kata-qemu has no
// policy-monitor to read the document.
var confidentialKataClasses = map[string]struct{}{
	kataSnpRuntimeClass:    {},
	kataSnpGpuRuntimeClass: {},
	kataTdxRuntimeClass:    {},
	kataTdxGpuRuntimeClass: {},
}

// stampInitData carries the CDS measurements and TCB floor to the guest's
// policy-monitor. Writing the annotation is not what makes it trustworthy —
// the shim hashes the document into HOST_DATA and the guest re-derives the
// digest before trusting it. On the TDX classes the digest lands padded in
// MRCONFIGID instead, which the guest refuses, so those pods enforce the
// baked seed (docs/kata-image-policy.md).
//
// An author-supplied value would name the CDS their own guest pins, and the
// HOST_DATA check cannot tell it from ours, so it is rejected. Comparing
// against the desired value rather than banning the key is what keeps this
// reinvocation-safe: initdata rendering is canonical.
func stampInitData(pod *corev1.Pod, kataClass string, measurements []string, minTCB string) error {
	want, err := initDataAnnotation(kataClass, measurements, minTCB)
	if err != nil {
		return err
	}
	if got, ok := pod.Annotations[initdata.AnnotationKey]; ok && got != want {
		return fmt.Errorf("%w: %s is set by c8s and must not be supplied by the pod author",
			errInvalidInjectionAnnotation, initdata.AnnotationKey)
	}
	if want == "" {
		return nil
	}
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[initdata.AnnotationKey] = want
	return nil
}

// kataHypervisorAnnotationPrefix is the pod-annotation family the kata shim
// turns into hypervisor settings (kernel_params, default_vcpus, enable_iommu,
// kernel_verity_params, ...).
const kataHypervisorAnnotationPrefix = "io.katacontainers.config.hypervisor."

// rejectKataHypervisorAnnotations denies a pod carrying any annotation under
// kataHypervisorAnnotationPrefix other than the cc_init_data document
// stampInitData manages: the shim applies them to the guest on every kata
// class, so a pod author must not set them.
func rejectKataHypervisorAnnotations(pod *corev1.Pod) error {
	for key := range pod.Annotations {
		if key != initdata.AnnotationKey && strings.HasPrefix(key, kataHypervisorAnnotationPrefix) {
			return fmt.Errorf("%w: %s configures the kata hypervisor and must not be supplied by the pod author",
				errInvalidInjectionAnnotation, key)
		}
	}
	return nil
}

// initDataAnnotation renders the value, or "" when the shape carries none.
func initDataAnnotation(kataClass string, measurements []string, minTCB string) (string, error) {
	if _, ok := confidentialKataClasses[kataClass]; !ok {
		return "", nil
	}
	data := map[string]string{initdata.KeyRole: initdata.RoleWorkload}
	if joined := strings.Join(measurements, ","); joined != "" {
		data[initdata.KeyCDSMeasurements] = joined
	}
	if minTCB != "" {
		data[initdata.KeyCDSMinTCB] = minTCB
	}
	if len(data) == 1 {
		return "", nil
	}
	built, err := initdata.New(data).Build()
	if err != nil {
		return "", fmt.Errorf("build init-data document: %w", err)
	}
	return built.Annotation, nil
}
