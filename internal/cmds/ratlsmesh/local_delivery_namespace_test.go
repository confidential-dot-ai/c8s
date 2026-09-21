//go:build linux

package ratlsmesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/meshnetns"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestPodNamespaceDeliveryConnectsToPodInterface(t *testing.T) {
	directory := t.TempDir()
	ns := deliveryTestNamespace(t, filepath.Join(directory, "pod"))
	if err := os.WriteFile(filepath.Join(directory, "unmounted-placeholder"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var listener net.Listener
	if err := ns.Do(func() (err error) {
		listener, err = (&net.ListenConfig{}).Listen(ctx, "tcp4", "10.123.0.2:0")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	delivery := podNamespaceDelivery{directory: directory, timeout: time.Second, keepAlive: 43 * time.Second}
	conn, err := delivery.DialContext(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var keepAlive int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		keepAlive, socketErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)
	}); err != nil || socketErr != nil || keepAlive != 43 {
		t.Fatalf("keepalive: got %d, control error %v, socket error %v", keepAlive, err, socketErr)
	}
}

func TestPodNamespaceDeliveryRejectsAmbiguousOwnership(t *testing.T) {
	directory := t.TempDir()
	deliveryTestNamespace(t, filepath.Join(directory, "pod-a"))
	deliveryTestNamespace(t, filepath.Join(directory, "pod-b"))
	delivery := podNamespaceDelivery{directory: directory}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ns, err := delivery.findNamespace(ctx, netip.MustParseAddr("10.123.0.2"))
	if ns != nil {
		ns.Close()
		t.Fatal("ambiguous namespace retained")
	}
	if err == nil || !strings.Contains(err.Error(), "multiple runtime namespaces") {
		t.Fatalf("ambiguous ownership was not rejected: %v", err)
	}
}

func TestPodNamespaceDeliveryClosesMatchAfterInventoryError(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "a-pod")
	deliveryTestNamespace(t, path)
	if err := os.Symlink(path, filepath.Join(directory, "z-invalid")); err != nil {
		t.Fatal(err)
	}
	before := namespaceDescriptorCount(t, path)
	delivery := podNamespaceDelivery{directory: directory}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ns, err := delivery.findNamespace(ctx, netip.MustParseAddr("10.123.0.2"))
	if ns != nil {
		ns.Close()
		t.Fatal("namespace returned with failed inventory")
	}
	if err == nil || !strings.Contains(err.Error(), "z-invalid") {
		t.Fatalf("later inventory entry did not fail: %v", err)
	}
	if after := namespaceDescriptorCount(t, path); after != before {
		t.Fatalf("namespace descriptor leak: before=%d after=%d", before, after)
	}
}

func namespaceDescriptorCount(t *testing.T, path string) int {
	t.Helper()
	var target unix.Stat_t
	if err := unix.Stat(path, &target); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Stat(filepath.Join("/proc/self/fd", entry.Name()), &stat); err == nil && stat.Dev == target.Dev && stat.Ino == target.Ino {
			count++
		}
	}
	return count
}

func deliveryTestNamespace(t *testing.T, path string) *meshnetns.Namespace {
	t.Helper()
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
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
		pod, err := netns.New()
		if err != nil {
			runtime.UnlockOSThread()
			done <- err
			return
		}
		defer pod.Close()
		err = unix.Mount(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), path, "", unix.MS_BIND, "")
		restoreErr := netns.Set(host)
		if restoreErr == nil {
			runtime.UnlockOSThread()
		}
		done <- errors.Join(err, restoreErr)
	}()
	err := <-done
	if errors.Is(err, unix.EPERM) {
		t.Skip("pod namespace test requires CAP_SYS_ADMIN: ", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount pod namespace: %v", err)
		}
	})
	ns, err := meshnetns.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ns.Close() })
	if err := ns.Do(func() error {
		for _, args := range [][]string{
			{"link", "set", "lo", "up"}, {"link", "add", "eth0", "type", "dummy"},
			{"link", "set", "eth0", "up"}, {"addr", "add", "10.123.0.2/32", "dev", "eth0"},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
			cancel()
			if err != nil {
				return fmt.Errorf("configure pod interface: %w: %s", err, output)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ns
}
