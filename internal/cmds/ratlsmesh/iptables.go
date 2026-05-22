//go:build linux

package ratlsmesh

import (
	"fmt"
	"net"
	"strconv"
)

// chainName is the dedicated iptables chain for locally generated traffic.
// preroutingChainName handles forwarded pod traffic entering the host network
// namespace from pod veth interfaces. Keeping them separate avoids using the
// owner match in PREROUTING, where packets do not have a local socket owner.
const chainName = "RATLS-MESH"
const preroutingChainName = "RATLS-MESH-PREROUTING"

const (
	podIPSetName4      = "RATLS-MESH-PODS"
	podIPSetName6      = "RATLS-MESH-PODS6"
	localPodIPSetName4 = "RATLS-MESH-LOCAL-PODS"
	localPodIPSetName6 = "RATLS-MESH-LOCAL-PODS6"
)

// defaultProxyUID is the UID under which the ratls-mesh sidecar proxy runs.
// Traffic from this UID is excluded from iptables redirect to avoid loops.
// This follows the Istio/Envoy convention of UID 1337.
const defaultProxyUID = 1337

const defaultIPSetMaxElem = 262144

type iptablesRule struct {
	table  string
	chain  string
	label  string
	family iptablesFamily
	args   []string
}

type iptablesFamily string

const (
	iptablesFamilyAll  iptablesFamily = ""
	iptablesFamilyIPv4 iptablesFamily = "ipv4"
	iptablesFamilyIPv6 iptablesFamily = "ipv6"
)

// buildPodIPSetRules computes NAT rules that send pod TCP traffic through the
// mesh. OUTPUT REDIRECT covers host-originated packets to pod IPs and uses
// owner matching to skip the proxy's own UID. PREROUTING covers pod-veth
// traffic and DNATs to this node's outbound listener at nodeIPsByFamily[f]
// for each family with a same-family node IP. Some CNIs (notably Azure CNI
// on AKS) count a PREROUTING REDIRECT rule but never complete the redirected
// pod TCP connect; DNAT to the node-local listener follows the same path
// pods can reach directly. A family without a same-family node IP gets no
// PREROUTING rule at all — installing a known-broken REDIRECT fallback would
// silently revive the AKS bug for that family on dual-stack nodes where the
// operator only configured one family.
//
// INVARIANT: each value in nodeIPsByFamily is a canonical, validated IP
// literal of the matching family. Callers must verify (parseNodeIPs in
// pod_ipsets_linux.go).
func buildPodIPSetRules(outboundPort, uid int, excludeUIDs []uint32, nodeIPsByFamily map[iptablesFamily]string) []iptablesRule {
	portStr := strconv.Itoa(outboundPort)
	uidStr := strconv.Itoa(uid)
	allPortsRange := "1:65535"

	rules := buildExcludeUIDRules(chainName, excludeUIDs)

	for _, spec := range []struct {
		family       iptablesFamily
		dstSetName   string
		localSetName string
	}{
		{iptablesFamilyIPv4, podIPSetName4, localPodIPSetName4},
		{iptablesFamilyIPv6, podIPSetName6, localPodIPSetName6},
	} {
		rules = append(rules, makeRedirectRule(redirectRuleSpec{
			chain:              chainName,
			family:             spec.family,
			labelPrefix:        "output-pod-ipset",
			matchArgs:          []string{"-m", "set", "--match-set", spec.dstSetName, "dst"},
			withOwnerExclusion: true,
			uidStr:             uidStr,
			portStr:            portStr,
			dportRange:         allPortsRange,
		}))
		nodeIP, hasFamily := nodeIPsByFamily[spec.family]
		if !hasFamily {
			continue
		}
		// Defense in depth: parseNodeIPs rejects empty strings, but an empty
		// value here would produce `--to-destination :15001` which iptables
		// accepts syntactically and rejects with a generic error not
		// traceable to this caller. makeDNATRule's panic only catches a
		// fully empty toDestination, not the `:port` form.
		if nodeIP == "" {
			panic(fmt.Sprintf("ratlsmesh: buildPodIPSetRules got empty nodeIP for family %s", spec.family))
		}
		rules = append(rules, makeDNATRule(dnatRuleSpec{
			chain:       preroutingChainName,
			family:      spec.family,
			labelPrefix: "prerouting-pod-ipset",
			matchArgs: []string{
				"-m", "set", "--match-set", spec.localSetName, "src",
				"-m", "set", "--match-set", spec.dstSetName, "dst",
			},
			toDestination: net.JoinHostPort(nodeIP, portStr),
			dportRange:    allPortsRange,
		}))
	}
	return rules
}

// buildExcludeUIDRules emits RETURN rules so system UIDs (e.g. root/0) skip
// the redirect, letting kubelet, containerd, and other host daemons reach
// container registries without going through the mesh.
func buildExcludeUIDRules(chain string, excludeUIDs []uint32) []iptablesRule {
	var rules []iptablesRule
	for _, euid := range excludeUIDs {
		rules = append(rules, iptablesRule{
			table: "nat",
			chain: chain,
			label: fmt.Sprintf("exclude-uid-%d", euid),
			args: []string{
				"-p", "tcp",
				"-m", "owner", "--uid-owner", strconv.FormatUint(uint64(euid), 10),
				"-j", "RETURN",
			},
		})
	}
	return rules
}

type redirectRuleSpec struct {
	chain              string
	family             iptablesFamily
	labelPrefix        string
	matchArgs          []string
	withOwnerExclusion bool
	uidStr             string
	portStr            string
	dportRange         string
}

func makeRedirectRule(spec redirectRuleSpec) iptablesRule {
	label := spec.dportRange
	if spec.labelPrefix != "" {
		label = spec.labelPrefix + "-" + spec.dportRange
	}
	args := []string{"-p", "tcp"}
	args = append(args, spec.matchArgs...)
	if spec.withOwnerExclusion {
		args = append(args, "-m", "owner", "!", "--uid-owner", spec.uidStr)
	}
	args = append(args,
		"--dport", spec.dportRange,
		"-j", "REDIRECT", "--to-port", spec.portStr,
	)
	return iptablesRule{
		table:  "nat",
		chain:  spec.chain,
		label:  label,
		family: spec.family,
		args:   args,
	}
}

type dnatRuleSpec struct {
	chain         string
	family        iptablesFamily
	labelPrefix   string
	matchArgs     []string
	toDestination string
	dportRange    string
}

func makeDNATRule(spec dnatRuleSpec) iptablesRule {
	if spec.toDestination == "" {
		// Fail fast at build time: an empty --to-destination would install
		// successfully on some iptables backends with surprising semantics,
		// and on others surface as a generic "Bad argument" pointing at
		// rule install rather than at the caller bug that produced it.
		panic(fmt.Sprintf("ratlsmesh: makeDNATRule called with empty toDestination (chain=%s family=%s)", spec.chain, spec.family))
	}
	label := spec.dportRange
	if spec.labelPrefix != "" {
		label = spec.labelPrefix + "-" + spec.dportRange
	}
	args := []string{"-p", "tcp"}
	args = append(args, spec.matchArgs...)
	args = append(args,
		"--dport", spec.dportRange,
		"-j", "DNAT", "--to-destination", spec.toDestination,
	)
	return iptablesRule{
		table:  "nat",
		chain:  spec.chain,
		label:  label,
		family: spec.family,
		args:   args,
	}
}

// jumpRules returns the base-chain jumps into ratls-mesh managed chains.
func jumpRules() []iptablesRule {
	return []iptablesRule{
		{
			table: "nat",
			chain: "OUTPUT",
			label: "jump-output-to-" + chainName,
			args:  []string{"-j", chainName},
		},
		{
			table: "nat",
			chain: "PREROUTING",
			label: "jump-prerouting-to-" + preroutingChainName,
			args:  []string{"-j", preroutingChainName},
		},
	}
}
