package nriimagepolicy

import (
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The sources below are what a live RKE2 node reports through CRI, with the pod
// UID and sandbox ID shortened.
const (
	podDir      = kubeletRoot + "/pods/0b30e735-a0c6-476d-b689-47ebfa6435fc"
	sandboxDir  = "/var/lib/rancher/rke2/agent/containerd" + sandboxSegment + "098d4947871d"
	stateSbxDir = "/run/k3s/containerd" + sandboxSegment + "098d4947871d"
)

func TestClassifyMount(t *testing.T) {
	for _, tc := range []struct {
		name        string
		destination string
		source      string
		want        allowlist.MountClass
	}{
		{"etc-hosts", "/etc/hosts", podDir + "/etc-hosts", allowlist.MountPlatform},
		{"termination log", "/dev/termination-log", podDir + "/containers/app/f8c22d8d", allowlist.MountPlatform},
		{"hostname", "/etc/hostname", sandboxDir + "/hostname", allowlist.MountPlatform},
		{"resolv.conf", "/etc/resolv.conf", sandboxDir + "/resolv.conf", allowlist.MountPlatform},
		{"shm", "/dev/shm", stateSbxDir + "/shm", allowlist.MountPlatform},
		{"serviceaccount projection", serviceAccountDestination, podDir + "/volumes/kubernetes.io~projected/kube-api-access-4hfr8", allowlist.MountPlatform},

		{"emptyDir", "/var/cache/nginx", podDir + "/volumes/kubernetes.io~empty-dir/cache", allowlist.MountEmptyDir},
		{"configMap", "/mnt/c8s-data/config", podDir + "/volumes/kubernetes.io~configmap/config-volume", allowlist.MountData},
		{"secret", "/mnt/c8s-data/tls", podDir + "/volumes/kubernetes.io~secret/tls", allowlist.MountData},
		{"csi volume", "/mnt/c8s-data/pvc", podDir + "/volumes/kubernetes.io~csi/pvc-1/mount", allowlist.MountData},
		{"subPath of an operator volume", "/mnt/c8s-data/app.conf", podDir + "/volume-subpaths/config-volume/app/0", allowlist.MountData},

		// The redirect this check exists for: content the node staged, bound
		// somewhere the node never puts it.
		{"projection redirected off its destination", "/etc/ld.so.conf.d", podDir + "/volumes/kubernetes.io~projected/kube-api-access-4hfr8", allowlist.MountData},
		{"etc-hosts redirected over the loader preload file", "/etc/ld.so.preload", podDir + "/etc-hosts", allowlist.MountData},

		{"hostPath", "/host", "/", allowlist.MountHost},
		{"hostPath at a platform destination", "/etc/resolv.conf", "/etc/c8s/resolv.conf", allowlist.MountHost},
		{"source under no staging directory", "/opt/lib", "/srv/payload", allowlist.MountHost},
		{"kubelet root itself", "/kubelet", kubeletRoot, allowlist.MountHost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyMount(tc.destination, tc.source); got != tc.want {
				t.Errorf("classifyMount(%q, %q) = %q, want %q", tc.destination, tc.source, got, tc.want)
			}
		})
	}
}

func TestObserveMountsDropsNonBinds(t *testing.T) {
	ctr := &api.Container{Mounts: []*api.Mount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/sys/fs/cgroup", Type: "cgroup", Source: "cgroup"},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs"},
		{Destination: "/etc/hosts", Type: "bind", Source: podDir + "/etc-hosts", Options: []string{"rbind", "rw"}},
	}}

	got := observeMounts(ctr)
	want := []allowlist.ObservedMount{{Destination: "/etc/hosts", Source: podDir + "/etc-hosts", Class: allowlist.MountPlatform}}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("observeMounts() = %+v, want %+v", got, want)
	}
}

// The deny log has to name the source, not just the destination: the source is
// the only thing that says a ConfigMap rather than an emptyDir landed there.
func TestMountObservationNamesSourceAndClass(t *testing.T) {
	line := mountObservation([]allowlist.ObservedMount{{
		Destination: "/etc/ld.so.preload",
		Source:      podDir + "/volumes/kubernetes.io~configmap/cfg",
		Class:       allowlist.MountData,
	}})
	if len(line) != 1 {
		t.Fatalf("mountObservation returned %d lines, want 1", len(line))
	}
	for _, want := range []string{"/etc/ld.so.preload", "kubernetes.io~configmap/cfg", "data"} {
		if !strings.Contains(line[0], want) {
			t.Errorf("mountObservation() = %q, missing %q", line[0], want)
		}
	}
}
