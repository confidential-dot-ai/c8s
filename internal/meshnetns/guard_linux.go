//go:build linux

package meshnetns

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type GuardConfig struct {
	PodCIDRs     []netip.Prefix
	ServiceCIDRs []netip.Prefix
	DNS          []netip.Addr
	API          []netip.AddrPort
}

type guardChain struct {
	name  string
	rules []string
}

type guardFilter struct {
	binary string
	chains []string
	rules  string
}

func (config GuardConfig) validate() error {
	if err := validateGuardCIDRs(config.PodCIDRs); err != nil {
		return fmt.Errorf("pod CIDRs: %w", err)
	}
	if err := validateGuardCIDRs(config.ServiceCIDRs); err != nil {
		return fmt.Errorf("service CIDRs: %w", err)
	}
	for _, addr := range config.DNS {
		if !validGuardAddress(addr) {
			return fmt.Errorf("invalid IPv4 DNS address %q", addr)
		}
	}
	for _, endpoint := range config.API {
		if !validGuardAddress(endpoint.Addr()) || endpoint.Port() == 0 {
			return fmt.Errorf("invalid IPv4 API endpoint %q", endpoint)
		}
	}
	return nil
}

func validateGuardCIDRs(cidrs []netip.Prefix) error {
	if len(cidrs) == 0 {
		return fmt.Errorf("at least one IPv4 CIDR is required")
	}
	for _, cidr := range cidrs {
		if !cidr.IsValid() || !validGuardAddress(cidr.Addr()) || cidr.Bits() == 0 || cidr != cidr.Masked() {
			return fmt.Errorf("invalid IPv4 CIDR %q", cidr)
		}
	}
	return nil
}

func validGuardAddress(addr netip.Addr) bool {
	return addr.Is4() && addr.IsGlobalUnicast()
}

func guardRules(config GuardConfig) ([]guardFilter, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	mark := strconv.Itoa(MeshMark)
	input := []string{
		"-i lo -j ACCEPT",
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
	}
	output := []string{
		"-m mark --mark " + mark + " ! -o lo -j DROP",
		"-o lo -j ACCEPT",
	}
	for _, dns := range config.DNS {
		for _, protocol := range []string{"udp", "tcp"} {
			match := "-d " + dns.String() + " -p " + protocol + " --dport 53"
			output = append(output, match+" -j ACCEPT")
		}
	}
	for _, api := range config.API {
		match := "-d " + api.Addr().String() + " -p tcp --dport " + strconv.Itoa(int(api.Port()))
		output = append(output, match+" -j ACCEPT")
	}
	for _, cidr := range config.PodCIDRs {
		match := "-d " + cidr.String() + " -p tcp"
		output = append(output, match+" -j DROP")
	}
	for _, cidr := range config.ServiceCIDRs {
		output = append(output, "-d "+cidr.String()+" -j DROP")
	}
	input = append(input, "-j DROP")
	output = append(output, "-p tcp -j ACCEPT", "-j DROP")
	return []guardFilter{
		newGuardFilter("iptables", input, output),
		newGuardFilter("ip6tables", []string{"-i lo -j ACCEPT", "-j DROP"}, []string{"-o lo -j ACCEPT", "-j DROP"}),
	}, nil
}

func newGuardFilter(binary string, input, output []string) guardFilter {
	directions := []guardChain{{"INPUT", input}, {"OUTPUT", output}, {"FORWARD", []string{"-j DROP"}}}
	var rules strings.Builder
	rules.WriteString("*filter\n")
	var chains []string
	for _, direction := range directions {
		chains = append(chains, direction.name)
		chain := "C8S-MESH-" + direction.name
		fmt.Fprintf(&rules, ":%s - [0:0]\n-F %s\n", chain, chain)
		for _, rule := range direction.rules {
			fmt.Fprintf(&rules, "-A %s %s\n", chain, rule)
		}
	}
	rules.WriteString("COMMIT\n")
	return guardFilter{binary: binary, chains: chains, rules: rules.String()}
}

// InstallGuard must finish before any application or certificate-init container starts.
func (n *Namespace) InstallGuard(ctx context.Context, config GuardConfig) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	filters, err := guardRules(config)
	if err != nil {
		return err
	}
	return n.Do(func() error {
		for _, filter := range filters {
			command := exec.CommandContext(ctx, filter.binary+"-restore", "--wait", "5", "--noflush")
			command.Stdin = strings.NewReader(filter.rules)
			if output, err := command.CombinedOutput(); err != nil {
				return fmt.Errorf("install %s filter guard: %w: %s", filter.binary, err, output)
			}
			for _, chain := range filter.chains {
				args := []string{"--wait", "5", "-t", "filter", "-C", chain, "-j", "C8S-MESH-" + chain}
				if exec.CommandContext(ctx, filter.binary, args...).Run() == nil {
					if err := requireFirstGuardJump(ctx, filter, chain); err != nil {
						return err
					}
					continue
				}
				args = []string{"--wait", "5", "-t", "filter", "-I", chain, "1", "-j", "C8S-MESH-" + chain}
				if output, err := exec.CommandContext(ctx, filter.binary, args...).CombinedOutput(); err != nil {
					return fmt.Errorf("attach filter %s guard: %w: %s", chain, err, output)
				}
			}
		}
		return nil
	})
}

func requireFirstGuardJump(ctx context.Context, filter guardFilter, chain string) error {
	args := []string{"--wait", "5", "-t", "filter", "-S", chain, "1"}
	output, err := exec.CommandContext(ctx, filter.binary, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("read filter %s first rule: %w: %s", chain, err, output)
	}
	want := "-A " + chain + " -j C8S-MESH-" + chain
	if strings.TrimSpace(string(output)) != want {
		return fmt.Errorf("%s filter %s guard jump must be first; remove preceding rules before starting containers", filter.binary, chain)
	}
	return nil
}
