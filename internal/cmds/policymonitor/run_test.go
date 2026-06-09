//go:build linux

package policymonitor

import (
	"strings"
	"testing"
)

func TestNewRootCommand_HasMonitorSubcommand(t *testing.T) {
	root := newRootCommand()
	var got []string
	for _, c := range root.Commands() {
		got = append(got, c.Name())
	}
	if len(got) != 1 || got[0] != "monitor" {
		t.Errorf("subcommands = %v, want [monitor]", got)
	}
}

func TestConfig_FillDefaults(t *testing.T) {
	var c Config
	c.fillDefaults()
	if c.AllowlistPath != defaultAllowlistPath {
		t.Errorf("AllowlistPath = %q, want %q", c.AllowlistPath, defaultAllowlistPath)
	}
	if c.WatchDir != defaultWatchDir {
		t.Errorf("WatchDir = %q, want %q", c.WatchDir, defaultWatchDir)
	}
	if c.CgroupRoot != defaultCgroupRoot {
		t.Errorf("CgroupRoot = %q, want %q", c.CgroupRoot, defaultCgroupRoot)
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", c.LogLevel)
	}
}

func TestNewRootCommand_HelpMentionsBakedAllowlist(t *testing.T) {
	root := newRootCommand()
	for _, c := range root.Commands() {
		if c.Name() == "monitor" {
			if !strings.Contains(c.Long, "/etc/c8s/bootstrap-allowlist.json") {
				t.Errorf("monitor help text does not mention the allowlist path")
			}
			return
		}
	}
	t.Fatal("monitor subcommand missing")
}
