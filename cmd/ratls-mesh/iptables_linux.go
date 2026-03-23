//go:build linux

package main

import (
	"flag"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/lunal-dev/c8s/pkg/certutil"
)

func parseIptablesFlags(name string) ([]iptablesRule, iptablesRule) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	outboundPort := fs.Int("outbound-port", 15001, "outbound listener port")
	inboundPort := fs.Int("inbound-port", 15006, "inbound listener port")
	uid := fs.Int("uid", defaultProxyUID, "UID to exclude from redirect")
	excludeUIDsStr := fs.String("exclude-uids", "0", "comma-separated UIDs to skip (e.g. root=0 so kubelet/containerd can reach registries)")
	fs.Parse(os.Args[2:])

	var excludeUIDs []int
	for _, s := range strings.Split(*excludeUIDsStr, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			slog.Error("invalid exclude-uid value", "value", s, "error", err)
			os.Exit(1)
		}
		excludeUIDs = append(excludeUIDs, v)
	}

	return buildRules(*outboundPort, *inboundPort, *uid, excludeUIDs), jumpRule()
}

// iptablesBinaries lists the binaries for IPv4 and IPv6 NAT rules.
// Both must be configured to prevent IPv6 traffic from bypassing the mesh.
var iptablesBinaries = []string{"iptables", "ip6tables"}

func iptablesSetup() {
	logger := certutil.NewJSONLogger("info")
	rules, jump := parseIptablesFlags("iptables-setup")

	for _, bin := range iptablesBinaries {
		// Ensure the custom chain exists (idempotent: -N fails if it already exists).
		if err := runIptablesCmd(bin, []string{"-t", "nat", "-N", chainName}); err != nil {
			// Chain already exists — that's fine.
			logger.Debug("chain already exists (expected on restart)", "bin", bin, "chain", chainName)
		} else {
			logger.Info("chain created", "bin", bin, "chain", chainName)
		}

		// Flush the chain to remove any stale rules from a previous version or
		// crash. This is the key improvement: on restart after a crash, stale
		// rules (possibly from a different port configuration) are cleared.
		if err := runIptablesCmd(bin, []string{"-t", "nat", "-F", chainName}); err != nil {
			logger.Error("flush chain failed", "bin", bin, "chain", chainName, "error", err)
			os.Exit(1)
		}
		logger.Info("chain flushed", "bin", bin, "chain", chainName)

		// Add redirect rules to the custom chain.
		for _, r := range rules {
			addArgs := append([]string{"-t", r.table, "-A", r.chain}, r.args...)
			if err := runIptablesCmd(bin, addArgs); err != nil {
				logger.Error("rule failed", "bin", bin, "label", r.label, "error", err)
				os.Exit(1)
			}
			logger.Info("rule installed", "bin", bin, "chain", r.chain, "dport", r.label)
		}

		// Ensure OUTPUT jumps to our chain (idempotent: check before add).
		checkArgs := append([]string{"-t", jump.table, "-C", jump.chain}, jump.args...)
		if runIptablesCmd(bin, checkArgs) == nil {
			logger.Info("jump rule already exists", "bin", bin)
			continue
		}
		addArgs := append([]string{"-t", jump.table, "-A", jump.chain}, jump.args...)
		if err := runIptablesCmd(bin, addArgs); err != nil {
			logger.Error("jump rule failed", "bin", bin, "error", err)
			os.Exit(1)
		}
		logger.Info("jump rule installed", "bin", bin, "chain", jump.chain)
	}
}

func iptablesCleanup() {
	logger := certutil.NewJSONLogger("info")
	_, jump := parseIptablesFlags("iptables-cleanup")

	for _, bin := range iptablesBinaries {
		// Remove the jump from OUTPUT to our chain.
		deleteArgs := append([]string{"-t", jump.table, "-D", jump.chain}, jump.args...)
		if err := runIptablesCmd(bin, deleteArgs); err != nil {
			logger.Warn("jump rule not found", "bin", bin, "label", jump.label)
		} else {
			logger.Info("jump rule removed", "bin", bin, "chain", jump.chain)
		}

		// Flush and delete the custom chain.
		if err := runIptablesCmd(bin, []string{"-t", "nat", "-F", chainName}); err != nil {
			logger.Warn("flush chain failed (may not exist)", "bin", bin, "chain", chainName)
		}
		if err := runIptablesCmd(bin, []string{"-t", "nat", "-X", chainName}); err != nil {
			logger.Warn("delete chain failed (may not exist)", "bin", bin, "chain", chainName)
		} else {
			logger.Info("chain removed", "bin", bin, "chain", chainName)
		}
	}
}

func runIptablesCmd(binary string, args []string) error {
	cmd := exec.Command(binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
