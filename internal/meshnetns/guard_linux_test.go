//go:build linux

package meshnetns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGuardRejectsInvalidConfiguration(t *testing.T) {
	podCIDR := netip.MustParsePrefix("10.52.0.0/16")
	for name, config := range map[string]GuardConfig{
		"loopback CIDR":     {PodCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}},
		"link-local CIDR":   {PodCIDRs: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}},
		"multicast CIDR":    {PodCIDRs: []netip.Prefix{netip.MustParsePrefix("224.0.0.0/4")}},
		"mapped IPv4 CIDR":  {PodCIDRs: []netip.Prefix{netip.MustParsePrefix("::ffff:10.52.0.0/112")}},
		"empty":             {},
		"IPv6 capture":      {PodCIDRs: []netip.Prefix{netip.MustParsePrefix("fd00::/64")}},
		"default route":     {PodCIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		"noncanonical CIDR": {PodCIDRs: []netip.Prefix{netip.MustParsePrefix("10.52.0.1/16")}},
		"invalid DNS":       {PodCIDRs: []netip.Prefix{podCIDR}, DNS: []netip.Addr{{}}},
		"IPv6 DNS":          {PodCIDRs: []netip.Prefix{podCIDR}, DNS: []netip.Addr{netip.MustParseAddr("fd00::53")}},
		"API port zero":     {PodCIDRs: []netip.Prefix{podCIDR}, API: []netip.AddrPort{netip.MustParseAddrPort("10.53.0.1:0")}},
	} {
		config.ServiceCIDRs = []netip.Prefix{netip.MustParsePrefix("10.53.0.0/16")}
		t.Run(name, func(t *testing.T) {
			if _, err := guardRules(config); err == nil {
				t.Fatal("accepted invalid guard configuration")
			}
		})
	}
}

func TestGuardRequiresValidServiceCIDRs(t *testing.T) {
	for _, cidrs := range [][]netip.Prefix{nil, {netip.MustParsePrefix("fd00::/64")}} {
		config := GuardConfig{
			PodCIDRs:     []netip.Prefix{netip.MustParsePrefix("10.52.0.0/16")},
			ServiceCIDRs: cidrs,
		}
		if _, err := guardRules(config); err == nil {
			t.Fatalf("accepted invalid service CIDRs: %v", cidrs)
		}
	}
}

func TestGuardCountsPodTCPAndNonTCPDrops(t *testing.T) {
	ns := newTestNamespace(t)
	for _, binary := range []string{"ip", "iptables", "iptables-restore", "ip6tables", "ip6tables-restore"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := ns.Do(func() error {
		for _, args := range [][]string{
			{"link", "set", "lo", "up"},
			{"link", "add", "eth0", "type", "dummy"},
			{"link", "set", "eth0", "up"},
			{"addr", "add", "10.52.0.2/24", "dev", "eth0"},
			{"route", "add", "default", "dev", "eth0"},
			{"-6", "addr", "add", "fd00::2/64", "dev", "eth0", "nodad"},
			{"-6", "route", "add", "default", "dev", "eth0"},
		} {
			if output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
				return fmt.Errorf("configure namespace: %w: %s", err, output)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	config := GuardConfig{
		PodCIDRs:     []netip.Prefix{netip.MustParsePrefix("10.52.0.0/16")},
		ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.53.0.0/16")},
	}
	for range 2 {
		if err := ns.InstallGuard(ctx, config); err != nil {
			t.Fatal(err)
		}
	}
	beforeTCP := guardDropPackets(t, ns, "iptables")
	if err := ns.Do(func() error {
		probeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp4", "10.52.0.99:8080")
		if err == nil {
			conn.Close()
			return fmt.Errorf("pod TCP bypass connected")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if guardDropPackets(t, ns, "iptables") <= beforeTCP {
		t.Fatal("pod TCP SYN was not counted as dropped")
	}
	for _, probe := range []struct{ network, address, binary string }{
		{"udp4", "192.0.2.1:69", "iptables"},
		{"udp6", "[fd00::99]:69", "ip6tables"},
	} {
		before := guardDropPackets(t, ns, probe.binary)
		if err := ns.Do(func() error {
			conn, err := net.Dial(probe.network, probe.address)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte("denied"))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if count := guardDropPackets(t, ns, probe.binary); count <= before {
			t.Fatalf("%s non-TCP drops = %d, want more than %d", probe.network, count, before)
		}
	}
	before := guardDropPackets(t, ns, "iptables")
	if err := ns.Do(func() error {
		probeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp4", "10.53.0.99:8080")
		if err == nil {
			conn.Close()
			return fmt.Errorf("service VIP bypass connected")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if guardDropPackets(t, ns, "iptables") <= before {
		t.Fatal("service VIP SYN was not counted as dropped")
	}
	if err := ns.Do(func() error {
		return exec.CommandContext(ctx, "iptables", "-I", "INPUT", "1", "-j", "ACCEPT").Run()
	}); err != nil {
		t.Fatal(err)
	}
	if err := ns.InstallGuard(ctx, config); err == nil || !strings.Contains(err.Error(), "guard jump must be first") {
		t.Fatalf("displaced guard reinstall = %v, want jump-position failure", err)
	}

}

func guardDropPackets(t *testing.T, ns *Namespace, binary string) uint64 {
	t.Helper()
	var rules []byte
	err := ns.Do(func() (err error) {
		rules, err = exec.Command(binary+"-save", "-c", "-t", "filter").CombinedOutput()
		return err
	})
	if err != nil {
		t.Fatalf("read guard counters: %v: %s", err, rules)
	}
	matches := regexp.MustCompile(`(?m)^\[([0-9]+):[0-9]+\] -A C8S-MESH-OUTPUT (?:.* )?-j DROP$`).FindAllSubmatch(rules, -1)
	var packets uint64
	for _, match := range matches {
		count, err := strconv.ParseUint(string(match[1]), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		packets += count
	}
	return packets
}
