//go:build linux

package ratlsmesh

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// localIPv4 returns a non-loopback IPv4 address bound to a local interface,
// or skips the test if none exists (runIptablesSync verifies node-IP
// locality against real interfaces).
func localIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("net.InterfaceAddrs: %v", err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		return ip.String()
	}
	t.Skip("no non-loopback IPv4 interface address available")
	return ""
}

func defaultTestSyncConfig() *iptablesSyncConfig {
	return &iptablesSyncConfig{
		outboundPort:            15001,
		uid:                     defaultProxyUID,
		excludeUIDs:             "0",
		excludeSourceNamespaces: defaultMeshExcludedSourceNamespacesCSV(),
		resyncPeriod:            30 * time.Second,
		watchdogPeriod:          2 * time.Second,
		ipsetMaxElem:            defaultIPSetMaxElem,
		cwInboundPassthrough:    formatCWPassthrough(defaultCWPassthrough),
		logLevel:                "error",
	}
}

func TestRunIptablesSyncValidationErrors(t *testing.T) {
	t.Setenv("NODE_IP", "")
	tests := []struct {
		name    string
		mutate  func(*iptablesSyncConfig)
		env     string // NODE_IP value ("" = unset)
		wantErr string
	}{
		{"bad outbound port", func(c *iptablesSyncConfig) { c.outboundPort = 0 }, "", "out of range"},
		{"bad resync period", func(c *iptablesSyncConfig) { c.resyncPeriod = 0 }, "", "resync-period must be positive"},
		{"bad watchdog period", func(c *iptablesSyncConfig) { c.watchdogPeriod = -time.Second }, "", "watchdog-period must be positive"},
		{"bad ipset maxelem", func(c *iptablesSyncConfig) { c.ipsetMaxElem = 0 }, "", "ipset-maxelem must be positive"},
		{"missing node IP", func(c *iptablesSyncConfig) {}, "", "node IP required"},
		{"node IP from env invalid", func(c *iptablesSyncConfig) {}, "not-an-ip", "not a valid IP address"},
		{"node IP not local", func(c *iptablesSyncConfig) { c.nodeIPs = []string{"203.0.113.7"} }, "", "not bound to any local interface"},
		{"bad exclude uids", func(c *iptablesSyncConfig) {
			c.nodeIPs = []string{localIPv4(t)}
			c.excludeUIDs = "root"
		}, "", "invalid exclude-uid"},
		{"bad cw passthrough", func(c *iptablesSyncConfig) {
			c.nodeIPs = []string{localIPv4(t)}
			c.cwInboundPassthrough = "icmp:1"
		}, "", "invalid cw-inbound-passthrough protocol"},
		{"bad log level", func(c *iptablesSyncConfig) {
			c.nodeIPs = []string{localIPv4(t)}
			c.logLevel = "shouty"
		}, "", "--log-level"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NODE_IP", tt.env)
			cfg := defaultTestSyncConfig()
			tt.mutate(cfg)
			err := runIptablesSync(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runIptablesSync() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestStringSetAndNewMembers(t *testing.T) {
	prev := stringSet([]string{"a", "b"})
	curr := stringSet([]string{"b", "c", "d"})
	got := newMembers(prev, curr)
	if len(got) != 2 {
		t.Fatalf("newMembers = %v, want 2 elements", got)
	}
	seen := stringSet(got)
	if _, ok := seen["c"]; !ok {
		t.Errorf("missing c in %v", got)
	}
	if _, ok := seen["d"]; !ok {
		t.Errorf("missing d in %v", got)
	}
}

func TestPodIPSetMembersExceeds(t *testing.T) {
	m := podIPSetMembers{allIPv4: []string{"1.1.1.1", "2.2.2.2"}}
	if !m.exceeds(1) {
		t.Error("exceeds(1) = false, want true")
	}
	if m.exceeds(2) {
		t.Error("exceeds(2) = true, want false")
	}
	if (podIPSetMembers{cwIPv6: []string{"fd00::1", "fd00::2"}}).exceeds(1) != true {
		t.Error("cwIPv6 overflow not detected")
	}
}

func TestCanonicalNodeIPs(t *testing.T) {
	got := canonicalNodeIPs(map[iptablesFamily]string{
		iptablesFamilyIPv6: "fd00::1",
		iptablesFamilyIPv4: "10.0.0.1",
	})
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "fd00::1" {
		t.Errorf("canonicalNodeIPs = %v, want IPv4 first then IPv6", got)
	}
}
