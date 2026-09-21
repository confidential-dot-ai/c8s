//go:build linux

package meshnetns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestOpenRejectsUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/proc/self/ns/net", link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "missing"), regular, link} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if ns, err := Open(path); err == nil {
				ns.Close()
				t.Fatal("accepted unsafe namespace path")
			}
		})
	}
}

func TestRejectsHostAndNonNetworkNamespaces(t *testing.T) {
	for _, path := range []string{"/proc/self/ns/net", "/proc/self/ns/uts"} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			fd, err := netns.GetFromPath(path)
			if err != nil {
				t.Fatal(err)
			}
			defer fd.Close()
			if err := validatePodNamespace(int(fd)); err == nil {
				t.Fatal("accepted host or non-network namespace")
			}
		})
	}
}

func TestRejectsInvalidAddressesBeforeEnteringNamespace(t *testing.T) {
	ns := &Namespace{fd: netns.None()}
	for _, addr := range []string{"invalid", "0.0.0.0", "::", "127.0.0.1", "::1", "224.0.0.1", "fe80::1%eth0"} {
		t.Run(addr, func(t *testing.T) {
			ip, _ := netip.ParseAddr(addr)
			if _, err := ns.OwnsAddress(ip); err == nil || errors.Is(err, os.ErrClosed) {
				t.Fatalf("address was not rejected before namespace entry: %v", err)
			}
			if _, err := ns.DialLocal(context.Background(), netip.AddrPortFrom(ip, 80), 30*time.Second); err == nil || errors.Is(err, os.ErrClosed) {
				t.Fatalf("dial address was not rejected: %v", err)
			}
		})
	}
	if _, err := ns.ListenTCP(context.Background(), netip.MustParseAddrPort("10.0.0.1:80")); err == nil || errors.Is(err, os.ErrClosed) {
		t.Fatalf("non-loopback listener was not rejected: %v", err)
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ns.Do(func() error { t.Error("ran action after Close"); return nil }); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Do after Close: %v", err)
	}
}

func TestNamespaceLocalDelivery(t *testing.T) {
	ns := newTestNamespace(t)
	if err := ns.Do(func() error {
		for _, args := range [][]string{
			{"link", "set", "lo", "up"},
			{"link", "add", "eth0", "type", "dummy"},
			{"link", "set", "eth0", "up"},
			{"addr", "add", "10.123.0.2/32", "dev", "eth0"},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
			cancel()
			if err != nil {
				return fmt.Errorf("configure pod namespace: %w: %s", err, output)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	owns, err := ns.OwnsAddress(netip.MustParseAddr("10.123.0.2"))
	if err != nil || !owns {
		t.Fatalf("namespace address lookup: owns=%v err=%v", owns, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	capture, err := ns.ListenTCP(ctx, netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	var listener net.Listener
	if err := ns.Do(func() (err error) {
		listener, err = (&net.ListenConfig{}).Listen(ctx, "tcp4", "10.123.0.2:0")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := ns.DialLocal(ctx, netip.MustParseAddrPort(listener.Addr().String()), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if _, err := ns.DialLocal(ctx, netip.MustParseAddrPort("10.123.0.3:80"), 30*time.Second); err == nil {
		t.Fatal("delivered to an address outside the namespace")
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ns.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// Pin a real namespace so Open exercises the runtime bind-mount path.
func newTestNamespace(t *testing.T) *Namespace {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pod")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	host, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hostNS := &Namespace{fd: host}
	err = hostNS.Do(func() error {
		pod, err := netns.New()
		if err != nil {
			return err
		}
		defer pod.Close()
		return unix.Mount(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), path, "", unix.MS_BIND, "")
	})
	if errors.Is(err, unix.EPERM) {
		t.Skip("network namespace test requires CAP_SYS_ADMIN: ", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount test namespace: %v", err)
		}
	})
	ns, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ns.Close() })
	return ns
}

func TestCloseInvalidatesNamespaceHandle(t *testing.T) {
	for name, closeFails := range map[string]bool{"successful close": false, "close error": true} {
		t.Run(name, func(t *testing.T) {
			ns := &Namespace{fd: netns.NsHandle(-2)}
			if !closeFails {
				fd, err := netns.Get()
				if err != nil {
					t.Fatal(err)
				}
				ns.fd = fd
			}
			err := ns.Close()
			if closeFails && !errors.Is(err, unix.EBADF) {
				t.Fatalf("close invalid handle = %v, want EBADF", err)
			}
			if !closeFails && err != nil {
				t.Fatal(err)
			}
			if err := ns.Close(); err != nil {
				t.Fatalf("second close: %v", err)
			}
			if err := ns.Do(func() error {
				t.Error("ran action after namespace close")
				return nil
			}); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("action after close = %v, want ErrClosed", err)
			}
		})
	}
}

func TestNamespaceActionRequiresSuccessfulEntry(t *testing.T) {
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ns := &Namespace{fd: netns.NsHandle(file.Fd())}
	called := false
	err = ns.Do(func() error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("entered a non-namespace descriptor")
	}
	if called {
		t.Fatal("ran action after failed namespace entry")
	}
}

func TestClosedNamespaceRejectsSocketOperations(t *testing.T) {
	ns := &Namespace{fd: netns.None()}
	podIP := netip.MustParseAddr("10.123.0.2")
	owns, err := ns.OwnsAddress(podIP)
	if owns || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed namespace ownership = %t, %v", owns, err)
	}
	listener, err := ns.ListenTCP(context.Background(), netip.MustParseAddrPort("[::1]:0"))
	if listener != nil || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed namespace listener = %v, %v", listener, err)
	}
	conn, err := ns.DialLocal(context.Background(), netip.AddrPortFrom(podIP, 80))
	if conn != nil || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed namespace connection = %v, %v", conn, err)
	}
}

func TestAddressOwnershipUsesInterfaceAddresses(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) == 0 {
		t.Skip("ownership test requires a configured interface address")
	}
	for _, address := range addresses {
		subnet, ok := address.(*net.IPNet)
		if !ok {
			t.Fatalf("unexpected interface address type %T", address)
		}
		ip, ok := netip.AddrFromSlice(subnet.IP)
		if !ok {
			t.Fatalf("invalid interface address %s", subnet.IP)
		}
		for _, representation := range []netip.Addr{ip.Unmap(), netip.AddrFrom16(ip.As16())} {
			owns, err := ownsAddress(representation)
			if err != nil || !owns {
				t.Fatalf("interface address %s not owned: %v", representation, err)
			}
		}
	}
	if owns, err := ownsAddress(netip.IPv4Unspecified()); err != nil || owns {
		t.Fatalf("unspecified address ownership = %t, %v", owns, err)
	}
}
