//go:build linux

package policymonitor

import (
	"context"
	"path/filepath"
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

func TestNewMonitorCommand_FlagParsing(t *testing.T) {
	cmd := newMonitorCommand()
	err := cmd.Flags().Parse([]string{
		"--allowlist", "/tmp/a.json",
		"--watch-dir", "/tmp/watch",
		"--cgroup-root", "/tmp/cg",
		"--log-level", "warn",
		"--cds-url", "https://cds",
		"--cds-measurements", "abc,def",
		"--attestation-service-url", "http://127.0.0.1:9000",
		"--allowlist-refresh-interval", "5s",
	})
	if err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	get := func(name string) string {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("flag %q missing", name)
		}
		return f.Value.String()
	}
	if got := get("allowlist"); got != "/tmp/a.json" {
		t.Errorf("allowlist = %q", got)
	}
	if got := get("allowlist-refresh-interval"); got != "5s" {
		t.Errorf("refresh-interval = %q", got)
	}
	if got := get("cds-url"); got != "https://cds" {
		t.Errorf("cds-url = %q", got)
	}
}

func TestNewMonitorCommand_RunEErrorsOnMissingAllowlist(t *testing.T) {
	cmd := newMonitorCommand()
	// Force a deterministic failure: a non-existent allowlist path. Use a
	// short-lived already-cancelled context so the run never blocks even if
	// it somehow got past the allowlist load.
	if err := cmd.Flags().Parse([]string{
		"--allowlist", filepath.Join(t.TempDir(), "absent.json"),
		"--watch-dir", t.TempDir(),
		"--cgroup-root", t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd.SetContext(ctx)
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected RunE to error on missing allowlist")
	}
}

func TestConfig_FillDefaults_FromEnv(t *testing.T) {
	t.Setenv("C8S_CDS_URL", "https://cds.from.env")
	t.Setenv("C8S_CDS_MEASUREMENTS", "aabb")
	t.Setenv("C8S_ATTESTATION_SERVICE_URL", "http://attester.env")
	var c Config
	c.fillDefaults()
	if c.CDSURL != "https://cds.from.env" {
		t.Errorf("CDSURL = %q", c.CDSURL)
	}
	if c.CDSMeasurements != "aabb" {
		t.Errorf("CDSMeasurements = %q", c.CDSMeasurements)
	}
	if c.AttestationServiceURL != "http://attester.env" {
		t.Errorf("AttestationServiceURL = %q", c.AttestationServiceURL)
	}
	if c.RefreshInterval != defaultRefreshInterval {
		t.Errorf("RefreshInterval = %v, want default", c.RefreshInterval)
	}
}

func TestConfig_FillDefaults_AttestationFallback(t *testing.T) {
	t.Setenv("C8S_CDS_URL", "")
	t.Setenv("C8S_CDS_MEASUREMENTS", "")
	t.Setenv("C8S_ATTESTATION_SERVICE_URL", "")
	var c Config
	c.fillDefaults()
	if c.AttestationServiceURL != defaultAttestationServiceURL {
		t.Errorf("AttestationServiceURL = %q, want %q", c.AttestationServiceURL, defaultAttestationServiceURL)
	}
}

func TestRun_UnknownSubcommandErrors(t *testing.T) {
	if err := Run([]string{"nonexistent-subcommand"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}
