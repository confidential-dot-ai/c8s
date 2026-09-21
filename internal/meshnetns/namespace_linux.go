//go:build linux

// Package meshnetns creates mesh sockets inside pod network namespaces.
package meshnetns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const MeshMark = 0xc850

type Namespace struct {
	mu sync.Mutex
	fd netns.NsHandle
}

func Open(path string) (*Namespace, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open pod namespace: %w", err)
	}
	if err := validatePodNamespace(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &Namespace{fd: netns.NsHandle(fd)}, nil
}

func validatePodNamespace(fd int) error {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fs.Type != unix.NSFS_MAGIC {
		return errors.New("pod namespace is not an nsfs mount")
	}
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil {
		return err
	}
	if kind != unix.CLONE_NEWNET {
		return errors.New("pod namespace is not a network namespace")
	}
	host, err := netns.GetFromPath("/proc/self/ns/net")
	if err != nil {
		return err
	}
	defer host.Close()
	var podStat, hostStat unix.Stat_t
	if err := unix.Fstat(fd, &podStat); err != nil {
		return err
	}
	if err := unix.Fstat(int(host), &hostStat); err != nil {
		return err
	}
	if podStat.Dev == hostStat.Dev && podStat.Ino == hostStat.Ino {
		return errors.New("pod namespace is the host network namespace")
	}
	return nil
}

func (n *Namespace) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fd == netns.None() {
		return nil
	}
	fd := n.fd
	n.fd = netns.None()
	return fd.Close()
}

// Do keeps namespace-sensitive socket creation on a dedicated OS thread.
func (n *Namespace) Do(action func() error) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fd == netns.None() {
		return os.ErrClosed
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		host, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			done <- err
			return
		}
		defer host.Close()
		if err = netns.Set(n.fd); err != nil {
			runtime.UnlockOSThread()
			done <- err
			return
		}
		err = action()
		if restoreErr := netns.Set(host); restoreErr != nil {
			// Exiting while locked discards the contaminated OS thread.
			done <- errors.Join(err, fmt.Errorf("restore host namespace: %w", restoreErr))
			return
		}
		runtime.UnlockOSThread()
		done <- err
	}()
	return <-done
}

func (n *Namespace) OwnsAddress(addr netip.Addr) (bool, error) {
	if !validPodAddress(addr) {
		return false, errors.New("invalid pod address")
	}
	var owns bool
	err := n.Do(func() (err error) {
		owns, err = ownsAddress(addr)
		return err
	})
	return owns, err
}

func validPodAddress(addr netip.Addr) bool {
	return addr.IsValid() && addr.Zone() == "" && !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLoopback()
}

func ownsAddress(addr netip.Addr) (bool, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Unmap() == addr.Unmap() {
			return true, nil
		}
	}
	return false, nil
}

func tcpNetwork(addr netip.Addr) string {
	if addr.Unmap().Is4() {
		return "tcp4"
	}
	return "tcp6"
}

func (n *Namespace) ListenTCP(ctx context.Context, addr netip.AddrPort) (net.Listener, error) {
	if !addr.IsValid() || !addr.Addr().IsLoopback() || addr.Addr().Zone() != "" {
		return nil, errors.New("capture listener requires a loopback address")
	}
	var listener net.Listener
	err := n.Do(func() (err error) {
		listener, err = (&net.ListenConfig{}).Listen(ctx, tcpNetwork(addr.Addr()), addr.String())
		return err
	})
	if err != nil && listener != nil {
		listener.Close()
		listener = nil
	}
	return listener, err
}

func (n *Namespace) DialLocal(ctx context.Context, dest netip.AddrPort) (net.Conn, error) {
	if !validPodAddress(dest.Addr()) || dest.Port() == 0 {
		return nil, errors.New("local delivery requires a pod address and nonzero port")
	}
	var conn net.Conn
	err := n.Do(func() error {
		owns, err := ownsAddress(dest.Addr())
		if err != nil {
			return err
		}
		if !owns {
			return errors.New("destination is not owned by pod namespace")
		}
		dialer := net.Dialer{Timeout: 5 * time.Second, Control: confineLocalSocket}
		conn, err = dialer.DialContext(ctx, tcpNetwork(dest.Addr()), dest.String())
		return err
	})
	if err != nil && conn != nil {
		conn.Close()
		conn = nil
	}
	return conn, err
}

func confineLocalSocket(_, _ string, raw syscall.RawConn) error {
	var sockErr error
	err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo")
		if sockErr == nil {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, MeshMark)
		}
	})
	return errors.Join(err, sockErr)
}
