package volume

import "testing"

func TestVolumeNamesMatchDeviceAndKubernetesConventions(t *testing.T) {
	if got := SerialPrefix + "weights"; got != "c8s-vol-weights" {
		t.Fatalf("device serial = %q", got)
	}
	if got := KubeVolumeName("weights"); got != "c8s-volume-weights" {
		t.Fatalf("Kubernetes volume name = %q", got)
	}
}

func TestValidVolumeNameEnforcesTheSerialBound(t *testing.T) {
	for _, name := range []string{"", "Weights", "-weights", "weights-", "we/ights", "thirteenchars"} {
		if err := ValidVolumeName(name); err == nil {
			t.Errorf("name %q: accepted", name)
		}
	}
	if err := ValidVolumeName("twelve-chars"); err != nil {
		t.Fatalf("12-character name rejected: %v", err)
	}
}
