package webhook

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/initdata"
)

var testMeasurements = []string{
	"781b4eb3313fe694dcf72ec78853f132590856c7e267797afe9bf45dd2c9fbe8352c71a20cf3f0e1e9ec03da36d5f25a",
	"da0854af8bff0e67f87b37f84af11a1aac570739efe55032e511c7d13dee180d1f4e3b4b209197d351646ddbd0e91509",
}

// decodeStamped reads the document back the way policy-monitor does.
func decodeStamped(t *testing.T, pod *corev1.Pod) initdata.Document {
	t.Helper()
	raw, err := initdata.Decode(pod.Annotations[initdata.AnnotationKey])
	if err != nil {
		t.Fatalf("decode annotation: %v", err)
	}
	doc, err := initdata.Parse(raw)
	if err != nil {
		t.Fatalf("parse document: %v", err)
	}
	return doc
}

func TestStampInitDataCarriesMeasurementsAndRole(t *testing.T) {
	pod := &corev1.Pod{}
	if err := stampInitData(pod, kataSnpRuntimeClass, testMeasurements); err != nil {
		t.Fatalf("stampInitData: %v", err)
	}

	doc := decodeStamped(t, pod)
	want := testMeasurements[0] + "," + testMeasurements[1]
	if got := doc.Data[initdata.KeyCDSMeasurements]; got != want {
		t.Fatalf("measurements = %q, want %q", got, want)
	}
	if got := doc.Data[initdata.KeyRole]; got != initdata.RoleWorkload {
		t.Fatalf("role = %q, want %q", got, initdata.RoleWorkload)
	}
}

// What the webhook encodes must decode to the bytes whose digest the shim
// commits — that equality is the whole trust anchor.
func TestStampInitDataDigestMatchesEncodedBytes(t *testing.T) {
	pod := &corev1.Pod{}
	if err := stampInitData(pod, kataSnpRuntimeClass, testMeasurements); err != nil {
		t.Fatalf("stampInitData: %v", err)
	}
	raw, err := initdata.Decode(pod.Annotations[initdata.AnnotationKey])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	built, err := initdata.New(map[string]string{
		initdata.KeyRole:            initdata.RoleWorkload,
		initdata.KeyCDSMeasurements: testMeasurements[0] + "," + testMeasurements[1],
	}).Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if initdata.Digest(raw) != built.Digest {
		t.Fatal("digest of the decoded annotation differs from the document digest the shim commits")
	}
}

// Nothing in a plain kata-qemu guest reads the document.
func TestStampInitDataSkipsNonConfidentialClass(t *testing.T) {
	pod := &corev1.Pod{}
	if err := stampInitData(pod, kataRuntimeClass, testMeasurements); err != nil {
		t.Fatalf("stampInitData: %v", err)
	}
	if _, ok := pod.Annotations[initdata.AnnotationKey]; ok {
		t.Fatal("kata-qemu pod was given an init-data document")
	}
}

func TestStampInitDataSkipsWithoutMeasurements(t *testing.T) {
	pod := &corev1.Pod{}
	if err := stampInitData(pod, kataSnpRuntimeClass, nil); err != nil {
		t.Fatalf("stampInitData: %v", err)
	}
	if _, ok := pod.Annotations[initdata.AnnotationKey]; ok {
		t.Fatal("stamped an empty document with no measurements to carry")
	}
}

// An author-chosen document names the CDS their guest trusts.
func TestStampInitDataRejectsAuthorSuppliedValue(t *testing.T) {
	pod := &corev1.Pod{}
	pod.Annotations = map[string]string{initdata.AnnotationKey: "rogue"}

	err := stampInitData(pod, kataSnpRuntimeClass, testMeasurements)
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("err = %v, want errInvalidInjectionAnnotation", err)
	}
}

// Including shapes c8s stamps nothing for, where it would otherwise survive
// untouched and reach the shim.
func TestStampInitDataRejectsAuthorValueOnUnstampedShapes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		class        string
		measurements []string
	}{
		{"non-confidential class", kataRuntimeClass, testMeasurements},
		{"no measurements configured", kataSnpRuntimeClass, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{}
			pod.Annotations = map[string]string{initdata.AnnotationKey: "rogue"}
			if err := stampInitData(pod, tc.class, tc.measurements); !errors.Is(err, errInvalidInjectionAnnotation) {
				t.Fatalf("err = %v, want errInvalidInjectionAnnotation", err)
			}
		})
	}
}

// The second pass must accept its own stamp, not read it as author-supplied.
func TestStampInitDataIsReinvocationSafe(t *testing.T) {
	pod := &corev1.Pod{}
	if err := stampInitData(pod, kataSnpRuntimeClass, testMeasurements); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	first := pod.Annotations[initdata.AnnotationKey]
	if err := stampInitData(pod, kataSnpRuntimeClass, testMeasurements); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if pod.Annotations[initdata.AnnotationKey] != first {
		t.Fatal("reinvocation changed the stamped document")
	}
}

func TestStampInitDataCoversEveryConfidentialClass(t *testing.T) {
	for class := range confidentialKataClasses {
		pod := &corev1.Pod{}
		if err := stampInitData(pod, class, testMeasurements); err != nil {
			t.Fatalf("stampInitData(%s): %v", class, err)
		}
		if _, ok := pod.Annotations[initdata.AnnotationKey]; !ok {
			t.Fatalf("confidential class %s got no init-data document", class)
		}
	}
}
