package kataspec

import (
	"strings"
	"testing"
)

const (
	hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestPullDigest(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        string
		wantOK      bool
	}{
		{
			name:        "digest-pinned reference",
			annotations: map[string]string{PullReferenceKey: "ghcr.io/confidential-dot-ai/assam@sha256:" + hexA},
			want:        "sha256:" + hexA,
			wantOK:      true,
		},
		{
			// The whole point of the change: kata pulls the reference in
			// image-name, so a digest sitting on any other annotation is not
			// the image that runs.
			name: "image-id is not consulted",
			annotations: map[string]string{
				PullReferenceKey:             "ghcr.io/confidential-dot-ai/assam:v1.0.0",
				"io.kubernetes.cri.image-id": "sha256:" + hexB,
			},
			wantOK: false,
		},
		{
			name: "ref.name is not consulted",
			annotations: map[string]string{
				PullReferenceKey:                    "ghcr.io/confidential-dot-ai/assam:v1.0.0",
				"org.opencontainers.image.ref.name": "sha256:" + hexB,
			},
			wantOK: false,
		},
		{
			// A tag is resolved by the registry when the guest pulls, so it
			// names no particular bytes.
			name:        "tag only",
			annotations: map[string]string{PullReferenceKey: "nginx:1.27-alpine"},
			wantOK:      false,
		},
		{
			// The baked policy anchors the same pattern, and Rego regex is
			// case-sensitive; accepting more here would let the two disagree.
			name:        "uppercase digest",
			annotations: map[string]string{PullReferenceKey: "x@sha256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			wantOK:      false,
		},
		{
			name:        "bare digest without a reference",
			annotations: map[string]string{PullReferenceKey: "sha256:" + hexA},
			wantOK:      false,
		},
		{
			name:        "trailing content after the digest",
			annotations: map[string]string{PullReferenceKey: "x@sha256:" + hexA + "extra"},
			wantOK:      false,
		},
		{
			name:        "short digest",
			annotations: map[string]string{PullReferenceKey: "x@sha256:abc"},
			wantOK:      false,
		},
		{
			name:        "no annotations",
			annotations: nil,
			wantOK:      false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := PullDigest(tc.annotations)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tc.wantOK, got)
			}
			if ok && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsSandbox(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{"containerd cri sandbox", map[string]string{"io.kubernetes.cri.container-type": "sandbox"}, true},
		{"cri-o sandbox", map[string]string{"io.kubernetes.cri-o.ContainerType": "sandbox"}, true},
		{"workload container", map[string]string{"io.kubernetes.cri.container-type": "container"}, false},
		{"no container-type annotation", map[string]string{PullReferenceKey: "ghcr.io/x:latest"}, false},
		{"nil annotations", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsSandbox(tc.annotations); got != tc.want {
				t.Errorf("IsSandbox = %v, want %v", got, tc.want)
			}
		})
	}
}

// The set here must match the regex the baked kata-agent policy applies to
// input.container_id: an id the policy admits but this rejects is a container
// policy-monitor never decides on, and rtmr3-measurer never measures.
func TestValidContainerID(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want bool
	}{
		{"6d7f5f7bd6e6b1f3a2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6", true},
		{hexA, true},
		{"init", false}, // a systemd unit cgroup name
		{"ab", false},
		{"aa-1", false},
		{"aa_1", false},
		{"aa.1", false},
		{"shared", false}, // kata's own subdirectory of /run/kata-containers
		{"sandbox", false},
		{"image", false},
		{"aa/1", false},
		{"аа1", false}, // Cyrillic
		{"", false},
		{hexA[:63], false},
		{hexA + "a", false},
		{strings.ToUpper(hexA), false},
		{strings.Repeat("g", 64), false}, // not hex
	} {
		if got := ValidContainerID(tc.id); got != tc.want {
			t.Errorf("ValidContainerID(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}
