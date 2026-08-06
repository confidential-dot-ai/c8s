package volumed

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// PeerIdentity resolves a caller to the pod the kernel says it is in.
//
// The pod decides where the volume mounts, so it is taken from the caller's
// cgroup via kernel peer credentials and never from the request.
type PeerIdentity struct {
	ProcRoot string
}

// Resolve returns the pod the calling process belongs to.
func (p PeerIdentity) Resolve(peer workloadclaims.Peer) (PodCgroup, error) {
	pods, err := PodCandidatesForPID(p.procRoot(), peer.PID())
	if err != nil {
		return PodCgroup{}, err
	}
	// Rechecked after the /proc read so a caller that exited mid-resolution
	// cannot have its PID reused by another pod's container.
	if !peer.IsAlive() {
		return PodCgroup{}, fmt.Errorf("volumed: caller exited during resolution")
	}
	return pods[0], nil
}

func (p PeerIdentity) procRoot() string {
	if p.ProcRoot != "" {
		return p.ProcRoot
	}
	return "/proc"
}

// GuestPodUID stands in for the pod UID inside a kata guest. It is a map key
// and a device-mapper name component, never an identity claim, and it never
// reaches a filesystem path: GuestTargets ignores it.
const GuestPodUID = "guest"

// GuestIdentity resolves every caller to the guest's single pod.
//
// A kata guest holds exactly one pod, so there is no caller to tell apart and
// nothing for peer credentials to decide — the guest boundary is the binding,
// for the same reason the guest's token route needs no peer credentials. The
// pod UID kubelet would supply does not exist in here and is not needed.
type GuestIdentity struct{}

// Resolve returns the guest's single pod.
func (GuestIdentity) Resolve(workloadclaims.Peer) (PodCgroup, error) {
	return PodCgroup{UID: GuestPodUID}, nil
}
