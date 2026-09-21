//go:build linux

package ratlsmesh

import (
	"strings"
	"testing"
)

const interceptionStatsV4 = `Chain RATLS-MESH-PREROUTING (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       9      540 RETURN     6    --  *      *       0.0.0.0/0            0.0.0.0/0
       5      300 DNAT       6    --  *      *       0.0.0.0/0            0.0.0.0/0            to:10.0.0.1:15001
`

const interceptionStatsV6 = `Chain RATLS-MESH-PREROUTING (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       7      420 DNAT       tcp      *      *       ::/0                 ::/0                 to:[fd00::1]:15001
`

func TestInterceptionCounters(t *testing.T) {
	nf := installFakeNetfilter(t)
	mustInitFakeIptables(t)
	previousIPv4Packets := preroutingIPv4InterceptedPackets.Load()
	previousIPv6Packets := preroutingIPv6InterceptedPackets.Load()
	previousErrors := interceptionCounterReadErrors.Load()
	previousReadAt := interceptionCountersReadAtUnixNano.Load()
	preroutingIPv4InterceptedPackets.Store(0)
	preroutingIPv6InterceptedPackets.Store(0)
	interceptionCounterReadErrors.Store(0)
	interceptionCountersReadAtUnixNano.Store(0)
	t.Cleanup(func() {
		preroutingIPv4InterceptedPackets.Store(previousIPv4Packets)
		preroutingIPv6InterceptedPackets.Store(previousIPv6Packets)
		interceptionCounterReadErrors.Store(previousErrors)
		interceptionCountersReadAtUnixNano.Store(previousReadAt)
	})

	assertSnapshot := func(packets, readErrors int64) {
		t.Helper()
		snapshot := currentIptablesMetricsSnapshot()
		if snapshot.PreroutingInterceptedPackets != packets || snapshot.InterceptionCounterReadErrors != readErrors {
			t.Fatalf("interception snapshot: packets=%d errors=%d; want packets=%d errors=%d",
				snapshot.PreroutingInterceptedPackets, snapshot.InterceptionCounterReadErrors, packets, readErrors)
		}
	}

	if err := refreshInterceptionCounters(); err == nil {
		t.Fatal("missing chains must produce a read error")
	}
	assertSnapshot(0, 2)
	if interceptionCountersReadAtUnixNano.Load() != 0 {
		t.Fatal("initial read failure must leave the successful-read timestamp at zero")
	}

	nf.set("stats_iptables_"+preroutingChainName, interceptionStatsV4)
	nf.set("stats_ip6tables_"+preroutingChainName, interceptionStatsV6)
	if err := refreshInterceptionCounters(); err != nil {
		t.Fatal(err)
	}
	assertSnapshot(12, 2)
	snapshot := currentIptablesMetricsSnapshot()
	if snapshot.IPv4Interception.PreroutingInterceptedPackets != 5 || snapshot.IPv6Interception.PreroutingInterceptedPackets != 7 {
		t.Fatalf("per-family interception packets: IPv4=%d IPv6=%d, want 5 and 7", snapshot.IPv4Interception.PreroutingInterceptedPackets, snapshot.IPv6Interception.PreroutingInterceptedPackets)
	}
	if interceptionCountersReadAtUnixNano.Load() == 0 {
		t.Fatal("successful read must publish its timestamp")
	}

	nf.remove("stats_ip6tables_" + preroutingChainName)
	nf.set("stats_iptables_"+preroutingChainName, strings.Replace(interceptionStatsV4, "5      300 DNAT", "6      360 DNAT", 1))
	if err := refreshInterceptionCounters(); err == nil || !strings.Contains(err.Error(), "ip6tables") {
		t.Fatalf("read failure must identify ip6tables: %v", err)
	}
	assertSnapshot(13, 3)
	if interceptionCountersReadAtUnixNano.Load() != 0 {
		t.Fatal("partial read failure must clear the successful-read timestamp")
	}

	nf.set("stats_iptables_"+preroutingChainName, strings.Replace(interceptionStatsV4, "5      300 DNAT", "0        0 DNAT", 1))
	nf.set("stats_ip6tables_"+preroutingChainName, strings.Replace(interceptionStatsV6, "7      420 DNAT", "0        0 DNAT", 1))
	if err := refreshInterceptionCounters(); err != nil {
		t.Fatal(err)
	}
	assertSnapshot(0, 3)

	nf.set("stats_iptables_"+preroutingChainName, strings.Replace(interceptionStatsV4, "5      300 DNAT", "invalid 300 DNAT", 1))
	if err := refreshInterceptionCounters(); err == nil {
		t.Fatal("malformed packet counter must produce a read error")
	}
	assertSnapshot(0, 4)
}
