//go:build linux

package ratlsmesh

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

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
	tests := []struct {
		name    string
		mutate  func(*iptablesSyncConfig)
		nodeIPs []string
		nodeErr error
		wantErr string
	}{
		{"bad outbound port", func(c *iptablesSyncConfig) { c.outboundPort = 0 }, []string{"10.0.0.7"}, nil, "out of range"},
		{"bad resync period", func(c *iptablesSyncConfig) { c.resyncPeriod = 0 }, []string{"10.0.0.7"}, nil, "resync-period must be positive"},
		{"bad watchdog period", func(c *iptablesSyncConfig) { c.watchdogPeriod = -time.Second }, []string{"10.0.0.7"}, nil, "watchdog-period must be positive"},
		{"bad ipset maxelem", func(c *iptablesSyncConfig) { c.ipsetMaxElem = 0 }, []string{"10.0.0.7"}, nil, "ipset-maxelem must be positive"},
		{"kernel node address failure", func(c *iptablesSyncConfig) {}, nil, errors.New("no usable route"), "derive node address from kernel"},
		{"bad exclude uids", func(c *iptablesSyncConfig) { c.excludeUIDs = "root" }, []string{"10.0.0.7"}, nil, "invalid exclude-uid"},
		{"bad cw passthrough", func(c *iptablesSyncConfig) { c.cwInboundPassthrough = "icmp:1" }, []string{"10.0.0.7"}, nil, "invalid cw-inbound-passthrough protocol"},
		{"bad log level", func(c *iptablesSyncConfig) { c.logLevel = "shouty" }, []string{"10.0.0.7"}, nil, "--log-level"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubTrustedNodeIPs(t, tt.nodeIPs, tt.nodeErr)
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
	if !(podIPSetMembers{cwIPv6: []string{"fd00::1", "fd00::2"}}).exceeds(1) {
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
