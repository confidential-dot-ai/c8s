//go:build linux

package ratlsmesh

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
)

// trustedNodeRoute is one kernel-selected source address and the interface the
// kernel selected for it. It is deliberately not derived from a Pod field, a
// CRI environment variable, or a file written by an installer.
type trustedNodeRoute struct {
	source string
	iface  string
}

// discoverTrustedNodeIPs is a seam for tests. Production obtains both the
// route choice and the address ownership from the node kernel.
var discoverTrustedNodeIPs = defaultTrustedNodeIPs

// defaultTrustedNodeIPs derives at most one usable address per IP family from
// the kernel's selected default-route source. A node can be single-stack, so a
// missing route in one family is allowed. No usable route in either family,
// multiple routes for a family, or a source not assigned to the selected
// interface is a startup error.
func defaultTrustedNodeIPs() ([]string, error) {
	var routes []trustedNodeRoute
	for _, target := range []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("2606:4700:4700::1111"),
	} {
		route, ok, err := trustedRouteForTarget(target)
		if err != nil {
			return nil, err
		}
		if ok {
			routes = append(routes, route)
		}
	}
	ifaces, err := collectInterfaceAddresses()
	if err != nil {
		return nil, err
	}
	return trustedNodeIPsFromRoutes(routes, ifaces)
}

// trustedRouteForTarget asks the kernel to choose the source used for a
// representative Internet destination. RouteGet is a read-only rtnetlink
// operation. It does not transmit a packet and uses the same route and source
// selection the node would use for a peer outside its pod network.
func trustedRouteForTarget(target net.IP) (trustedNodeRoute, bool, error) {
	routes, err := netlink.RouteGet(target)
	if err != nil {
		if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
			return trustedNodeRoute{}, false, nil
		}
		return trustedNodeRoute{}, false, fmt.Errorf("kernel route lookup for %s: %w", target, err)
	}
	if len(routes) == 0 {
		return trustedNodeRoute{}, false, nil
	}
	if len(routes) != 1 {
		return trustedNodeRoute{}, false, fmt.Errorf("kernel route lookup for %s returned %d routes; node address is ambiguous", target, len(routes))
	}
	route := routes[0]
	if route.Src == nil || route.Src.IsUnspecified() {
		return trustedNodeRoute{}, false, fmt.Errorf("kernel route lookup for %s returned no source address", target)
	}
	if route.LinkIndex <= 0 {
		return trustedNodeRoute{}, false, fmt.Errorf("kernel route lookup for %s returned no output interface", target)
	}
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return trustedNodeRoute{}, false, fmt.Errorf("kernel route lookup for %s link %d: %w", target, route.LinkIndex, err)
	}
	return trustedNodeRoute{source: route.Src.String(), iface: link.Attrs().Name}, true, nil
}

// trustedNodeIPsFromRoutes validates the kernel route result against the
// kernel interface-address snapshot. The pure form makes it possible to test
// adversarial route results without modifying a host route table.
func trustedNodeIPsFromRoutes(routes []trustedNodeRoute, ifaces []ifaceAddrSet) ([]string, error) {
	byFamily, err := trustedNodeIPsByFamilyFromRoutes(routes, ifaces)
	if err != nil {
		return nil, err
	}
	return canonicalNodeIPs(byFamily), nil
}

func trustedNodeIPsByFamily(nodeIPs []string) (map[iptablesFamily]string, error) {
	byFamily := make(map[iptablesFamily]string, 2)
	for _, nodeIP := range nodeIPs {
		family, canonical, err := canonicalTrustedNodeIP(nodeIP)
		if err != nil {
			return nil, err
		}
		if previous, exists := byFamily[family]; exists {
			return nil, fmt.Errorf("kernel route returned multiple %s node addresses (%s and %s); refusing ambiguous node identity", family, previous, canonical)
		}
		byFamily[family] = canonical
	}
	if len(byFamily) == 0 {
		return nil, fmt.Errorf("kernel route lookup found no usable node address")
	}
	return byFamily, nil
}

func trustedNodeIPsByFamilyFromRoutes(routes []trustedNodeRoute, ifaces []ifaceAddrSet) (map[iptablesFamily]string, error) {
	byFamily := make(map[iptablesFamily]string, 2)
	for _, route := range routes {
		family, canonical, err := canonicalTrustedNodeIP(route.source)
		if err != nil {
			return nil, err
		}
		if route.iface == "" {
			return nil, fmt.Errorf("kernel route source %s has no output interface", canonical)
		}
		if !interfaceHasAddress(ifaces, route.iface, canonical) {
			return nil, fmt.Errorf("kernel route source %s is not assigned to output interface %s", canonical, route.iface)
		}
		if previous, exists := byFamily[family]; exists {
			return nil, fmt.Errorf("kernel route returned multiple %s node addresses (%s and %s); refusing ambiguous node identity", family, previous, canonical)
		}
		byFamily[family] = canonical
	}
	if len(byFamily) == 0 {
		return nil, fmt.Errorf("kernel route lookup found no usable node address")
	}
	return byFamily, nil
}

func canonicalTrustedNodeIP(raw string) (iptablesFamily, string, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", "", fmt.Errorf("kernel route source %q is not a valid IP address", raw)
	}
	if addr.Zone() != "" || addr.Is4In6() || (addr.Is6() && containsDot(raw)) {
		return "", "", fmt.Errorf("kernel route source %q is an ambiguous address form", raw)
	}
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return "", "", fmt.Errorf("kernel route source %q is not a usable node address", raw)
	}
	if addr.Is4() {
		return iptablesFamilyIPv4, addr.String(), nil
	}
	return iptablesFamilyIPv6, addr.String(), nil
}

func containsDot(s string) bool {
	for _, r := range s {
		if r == '.' {
			return true
		}
	}
	return false
}

func interfaceHasAddress(ifaces []ifaceAddrSet, name, address string) bool {
	for _, iface := range ifaces {
		if iface.name != name {
			continue
		}
		for _, candidate := range iface.addrs {
			if candidate.ip.String() == address {
				return true
			}
		}
	}
	return false
}

// primaryTrustedNodeIP selects the canonical IPv4 address where present. The
// Kubernetes PodStatus.HostIP field is normally IPv4; on an IPv6-only node the
// sole IPv6 route source is used. The caller already has a kernel-validated,
// one-per-family list.
func primaryTrustedNodeIP(nodeIPs []string) (string, error) {
	for _, nodeIP := range nodeIPs {
		if parsed := net.ParseIP(nodeIP); parsed != nil && parsed.To4() != nil {
			return nodeIP, nil
		}
	}
	if len(nodeIPs) == 1 {
		return nodeIPs[0], nil
	}
	return "", fmt.Errorf("kernel route lookup returned no primary node address")
}
