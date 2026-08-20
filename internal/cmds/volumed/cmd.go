package volumed

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// SocketName is the daemon's socket, created inside the same directory the
// admission inventory uses. That directory is the one the webhook mounts into
// cw pods and the one the deny-host-namespaces VAP carves out by exact path, so
// a second directory would be denied to every pod that needs to reach this.
const SocketName = "volumed.sock"

type config struct {
	socketDir   string
	kubeletRoot string
	cgroupRoot  string
	// socketGID group-owns the socket so the non-root fetcher sidecar can
	// connect. Not a flag: it must match what the webhook injects as a
	// supplemental group, which is the same compiled constant.
	socketGID    int
	reapInterval time.Duration
	maxMounts    int
	// guest runs the in-guest shape: serve on guest loopback, mount into
	// kata's ephemeral directory, and let the VM's lifetime do the reaping.
	guest          bool
	guestEphemeral string
}

// Run is the cobra-driven entry point invoked from cmd/volumed/main.go, the
// standalone binary baked into the kata guest rootfs. runDaemon installs its
// own signal handling, so this only dispatches. Mirrors the shape of
// internal/cmds/policymonitor.Run.
func Run(args []string) error {
	cmd := NewCmd()
	cmd.SetArgs(args)
	cmd.SilenceErrors = true
	return cmd.Execute()
}

// NewCmd returns the `c8s volumed` command.
func NewCmd() *cobra.Command {
	cfg := config{socketGID: workloadclaims.InventorySocketGID}
	cmd := &cobra.Command{
		Use:   "volumed",
		Short: "Agent that opens encrypted volumes for entitled pods",
		Long: `volumed opens an encrypted volume for a pod.

An injected sidecar fetches the volume's key from CDS over the attested secrets
flow and hands it to this daemon, which opens dm-crypt and dm-verity and mounts
the result read-only into that pod and no other.

It runs in one of two shapes. On node-CVM it is a privileged node daemon: it
resolves the calling pod from kernel peer credentials and mounts into that pod's
kubelet directory. With --guest it runs inside a kata guest, which holds exactly
one pod, so it serves on guest loopback and mounts into kata's ephemeral
directory instead.

Either way it runs privileged — opening a device and mounting into a pod's
directory needs it — and where a volume is mounted is never driven by what a
caller says about itself.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         func(cmd *cobra.Command, _ []string) error { return runDaemon(cmd.Context(), cfg) },
	}
	f := cmd.Flags()
	// No default: the inventory's socket directory is a chart value, and the
	// in-pod path a sidecar sees it at is not where this daemon serves.
	f.StringVar(&cfg.socketDir, "socket-dir", "",
		"host directory holding the admission inventory's socket, where this daemon creates its own (required)")
	f.StringVar(&cfg.kubeletRoot, "kubelet-root", "/var/lib/kubelet", "kubelet's root directory, holding per-pod volume directories")
	f.StringVar(&cfg.cgroupRoot, "cgroup-root", DefaultCgroupRoot, "cgroup mount, where a pod's slice going away is what triggers teardown")
	f.DurationVar(&cfg.reapInterval, "reap-interval", DefaultReapInterval, "how often to tear down volumes whose pod has gone")
	f.IntVar(&cfg.maxMounts, "max-mounts", DefaultMaxMounts, "maximum volumes open on this node at once")
	f.BoolVar(&cfg.guest, "guest", false,
		"run inside a kata guest: serve on guest loopback, mount into kata's ephemeral directory, and resolve every caller to the guest's single pod")
	f.StringVar(&cfg.guestEphemeral, "guest-ephemeral-dir", DefaultGuestEphemeralRoot,
		"where kata-agent materializes memory-backed emptyDir volumes inside the guest (--guest only)")
	return cmd
}

func runDaemon(ctx context.Context, cfg config) error {
	if err := validate(cfg); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.guest {
		return runGuest(ctx, cfg)
	}
	return runNode(ctx, cfg)
}

func runNode(ctx context.Context, cfg config) error {
	opener := &Opener{Ops: SystemOps{}, Targets: KubeletTargets{Root: cfg.kubeletRoot}, MaxMounts: cfg.maxMounts}
	srv := &Server{
		Identity: PeerIdentity{},
		Opener:   opener,
		Devices:  SerialDevices{},
		Logger:   slog.Default(),
	}

	l, err := listen(cfg.socketDir, cfg.socketGID)
	if err != nil {
		return err
	}
	defer l.Close()

	// Mappings an earlier volumed left behind hold the backing disk open, so a
	// volume they cover cannot be reopened until they go. Sweep before serving.
	if closed, stuck := opener.SweepStale(ctx); closed > 0 || len(stuck) > 0 {
		slog.Info("swept mappings left by an earlier volumed", "closed", closed, "still_in_use", stuck)
	}

	reaper := &Reaper{
		Opener:   opener,
		Liveness: CgroupLiveness{Root: cfg.cgroupRoot},
		Interval: cfg.reapInterval,
		Logger:   slog.Default(),
	}
	go reaper.Run(ctx)

	slog.Info("serving volume opens", "socket", filepath.Join(cfg.socketDir, SocketName), "kubelet_root", cfg.kubeletRoot)
	return srv.Serve(ctx, l)
}

// runGuest serves the in-guest shape. No reaper: the volume dies with the VM
// that holds it, so there is no surviving daemon to reap for.
func runGuest(ctx context.Context, cfg config) error {
	srv := &Server{
		Identity: GuestIdentity{},
		Opener:   &Opener{Ops: SystemOps{}, Targets: GuestTargets{Root: cfg.guestEphemeral}, MaxMounts: cfg.maxMounts},
		Devices:  SerialDevices{},
		Logger:   slog.Default(),
	}

	l, err := net.Listen("tcp", GuestAddr())
	if err != nil {
		return fmt.Errorf("volumed: listen on %s: %w", GuestAddr(), err)
	}
	defer l.Close()

	slog.Info("serving volume opens", "addr", GuestAddr(), "ephemeral_dir", cfg.guestEphemeral)
	return srv.Serve(ctx, l)
}

// listen creates the socket, replacing a stale one left by a previous run and
// group-owning it to gid so the non-root fetcher sidecar can connect.
//
// The directory is the inventory's, and this daemon must not disturb what is
// already there: only its own socket name is touched.
func listen(dir string, gid int) (net.Listener, error) {
	return workloadclaims.ListenUnix(filepath.Join(dir, SocketName), gid)
}

func validate(cfg config) error {
	if cfg.maxMounts <= 0 {
		return fmt.Errorf("--max-mounts must be positive")
	}
	// The guest shape has no socket, no kubelet and no reaper, so requiring
	// their flags would mean carrying values nothing reads.
	if cfg.guest {
		if cfg.guestEphemeral == "" {
			return fmt.Errorf("--guest-ephemeral-dir is required with --guest")
		}
		return nil
	}
	switch {
	case cfg.socketDir == "":
		return fmt.Errorf("--socket-dir is required")
	case cfg.kubeletRoot == "":
		return fmt.Errorf("--kubelet-root is required")
	case cfg.cgroupRoot == "":
		return fmt.Errorf("--cgroup-root is required")
	case cfg.reapInterval <= 0:
		return fmt.Errorf("--reap-interval must be positive")
	}
	return nil
}
