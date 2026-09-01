//go:build linux

package ratlsmesh

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func mustParseIP(t *testing.T, value string) net.IP {
	t.Helper()
	ip := net.ParseIP(value)
	if ip == nil {
		t.Fatalf("invalid test IP %q", value)
	}
	return ip
}

func localIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("net.InterfaceAddrs: %v", err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.String()
		}
	}
	t.Skip("no non-loopback IPv4 interface address available")
	return ""
}

func stubTrustedNodeIPs(t *testing.T, nodeIPs []string, err error) {
	t.Helper()
	original := discoverTrustedNodeIPs
	discoverTrustedNodeIPs = func() ([]string, error) { return nodeIPs, err }
	t.Cleanup(func() { discoverTrustedNodeIPs = original })
}

func TestTrustedNodeIPsFromRoutes(t *testing.T) {
	ifaces := []ifaceAddrSet{
		{name: "eth0", addrs: []ifaceAddr{{ip: mustParseIP(t, "10.0.0.7")}, {ip: mustParseIP(t, "2001:db8::7")}}},
	}
	got, err := trustedNodeIPsFromRoutes([]trustedNodeRoute{
		{source: "10.0.0.7", iface: "eth0"},
		{source: "2001:db8::7", iface: "eth0"},
	}, ifaces)
	if err != nil {
		t.Fatalf("trustedNodeIPsFromRoutes: %v", err)
	}
	if strings.Join(got, ",") != "10.0.0.7,2001:db8::7" {
		t.Fatalf("trustedNodeIPsFromRoutes = %v", got)
	}
}

func TestTrustedNodeIPsFromRoutesRejectsAmbiguousFamily(t *testing.T) {
	ifaces := []ifaceAddrSet{{name: "eth0", addrs: []ifaceAddr{{ip: mustParseIP(t, "10.0.0.7")}, {ip: mustParseIP(t, "10.0.0.8")}}}}
	_, err := trustedNodeIPsFromRoutes([]trustedNodeRoute{
		{source: "10.0.0.7", iface: "eth0"},
		{source: "10.0.0.8", iface: "eth0"},
	}, ifaces)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("trustedNodeIPsFromRoutes() error = %v, want ambiguity rejection", err)
	}
}

func TestTrustedNodeIPsFromRoutesRejectsMismatchedLocalAddress(t *testing.T) {
	ifaces := []ifaceAddrSet{{name: "eth0", addrs: []ifaceAddr{{ip: mustParseIP(t, "10.0.0.8")}}}}
	_, err := trustedNodeIPsFromRoutes([]trustedNodeRoute{{source: "10.0.0.7", iface: "eth0"}}, ifaces)
	if err == nil || !strings.Contains(err.Error(), "not assigned") {
		t.Fatalf("trustedNodeIPsFromRoutes() error = %v, want local-address mismatch rejection", err)
	}
}

func TestTrustedNodeIPsFromRoutesRejectsNoAddress(t *testing.T) {
	_, err := trustedNodeIPsFromRoutes(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no usable") {
		t.Fatalf("trustedNodeIPsFromRoutes() error = %v, want no-address rejection", err)
	}
}

func TestTrustedNodeIPResolverDoesNotAcceptInjectedEnvironment(t *testing.T) {
	t.Setenv("NODE_IP", "203.0.113.9")
	stubTrustedNodeIPs(t, nil, errors.New("no kernel route"))
	if _, err := discoverTrustedNodeIPs(); err == nil || !strings.Contains(err.Error(), "no kernel route") {
		t.Fatalf("resolver error = %v, want kernel resolver failure despite NODE_IP", err)
	}
}

func TestRunProxyIgnoresNODEIP(t *testing.T) {
	t.Setenv("NODE_IP", "203.0.113.9")
	stubTrustedNodeIPs(t, nil, errors.New("no kernel route"))
	cfg := defaultTestProxyConfig(t)
	cfg.logLevel = "error"
	if err := runProxy(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "no kernel route") {
		t.Fatalf("runProxy() error = %v, want kernel resolver error", err)
	}
}

func TestRunIptablesSyncIgnoresNODEIP(t *testing.T) {
	t.Setenv("NODE_IP", "203.0.113.9")
	stubTrustedNodeIPs(t, nil, errors.New("no kernel route"))
	cfg := defaultTestSyncConfig()
	if err := runIptablesSync(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "no kernel route") {
		t.Fatalf("runIptablesSync() error = %v, want kernel resolver error", err)
	}
}

func TestPrimaryTrustedNodeIP(t *testing.T) {
	got, err := primaryTrustedNodeIP([]string{"2001:db8::7", "10.0.0.7"})
	if err != nil || got != "10.0.0.7" {
		t.Fatalf("primaryTrustedNodeIP() = %q, %v", got, err)
	}
	got, err = primaryTrustedNodeIP([]string{"2001:db8::7"})
	if err != nil || got != "2001:db8::7" {
		t.Fatalf("IPv6 primaryTrustedNodeIP() = %q, %v", got, err)
	}
}
