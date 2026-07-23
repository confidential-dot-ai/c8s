package nriimagepolicy

import (
	"context"
	"reflect"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// TestLUKSMapperNamesFor pins the annotation-suffix → mapper-name mapping the
// reap uses. If the webhook's luksAnnotationPrefix or luksopen's "c8s-<name>"
// convention change, this test's failure locates the seams to update.
func TestLUKSMapperNamesFor(t *testing.T) {
	cases := []struct {
		name        string
		annotations map[string]string
		want        []string
	}{
		{
			name:        "no luks annotations",
			annotations: map[string]string{"confidential.ai/cw": "api"},
			want:        nil,
		},
		{
			name: "sorted by mapper name",
			annotations: map[string]string{
				"confidential.ai/luks-secondary": "dev=/dev/vdc,mount=/data-2,secret=…",
				"confidential.ai/luks-data":      "dev=/dev/vdb,mount=/data,secret=…",
			},
			want: []string{"c8s-data", "c8s-secondary"},
		},
		{
			name: "empty suffix skipped (defensive)",
			annotations: map[string]string{
				"confidential.ai/luks-":     "value",
				"confidential.ai/luks-data": "value",
			},
			want: []string{"c8s-data"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := luksMapperNamesFor(tc.annotations)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mappers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRemovePodSandboxNoLUKSAnnotations short-circuits before it touches the
// device-mapper control device, so this runs on any host.
func TestRemovePodSandboxNoLUKSAnnotations(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	pod := &api.PodSandbox{
		Name:        "unrelated",
		Namespace:   "default",
		Annotations: map[string]string{"foo": "bar"},
	}
	if err := p.RemovePodSandbox(context.Background(), pod); err != nil {
		t.Fatalf("RemovePodSandbox(no luks) = %v, want nil", err)
	}
}
