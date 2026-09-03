package policymeasure

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/attestproxy"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The node image wires this command and its siblings through files nothing
// else ties to the binary: the measurer unit, the socket unit, the preset
// that creates their RequiredBy links, the tmpfiles that create /run/confai,
// and the sync hook that renders the platform drop-in. Load them here so a
// drift between a unit and the binary fails `go test`.
const (
	nodeImageDir      = "../../../node-guest-image/c8s"
	measureService    = nodeImageDir + "/mkosi.extra/etc/systemd/system/c8s-policy-measure.service"
	socketService     = nodeImageDir + "/mkosi.extra/etc/systemd/system/c8s-attest-socket.service"
	nodeImagePreset   = nodeImageDir + "/mkosi.extra/usr/lib/systemd/system-preset/50-rke2.preset"
	nodeImageTmpfiles = nodeImageDir + "/mkosi.extra/etc/tmpfiles.d/confos-rke2.conf"
	nodeImageSync     = nodeImageDir + "/mkosi.sync"

	attestationSocket = "/run/confai/attestation-api.sock"
	rke2Pair          = "rke2-server.service rke2-agent.service"
)

// unitFile reads a unit with continuation lines joined, refusing the
// backslash-then-whitespace form systemd does not treat as a continuation.
func unitFile(t *testing.T, path string) string {
	t.Helper()
	unit, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if regexp.MustCompile(`\\[ \t]+\n`).Match(unit) {
		t.Fatalf("%s has a backslash followed by whitespace: not a systemd continuation", path)
	}
	return strings.ReplaceAll(string(unit), "\\\n", " ")
}

// directives returns every value of name= in the unit, in order.
func directives(unit, name string) []string {
	var values []string
	for _, line := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(line, name+"="); ok {
			values = append(values, strings.TrimSpace(v))
		}
	}
	return values
}

// execStart returns the single ExecStart's argv.
func execStart(t *testing.T, unit, path string) []string {
	t.Helper()
	values := directives(unit, "ExecStart")
	if len(values) != 1 {
		t.Fatalf("%s ExecStart directive count = %d, want exactly 1", path, len(values))
	}
	return strings.Fields(values[0])
}

func TestNodeImagePolicyMeasureService(t *testing.T) {
	unit := unitFile(t, measureService)
	args := execStart(t, unit, measureService)
	if len(args) < 2 || args[0] != "/usr/local/bin/c8s" || args[1] != "policy-measure" {
		t.Fatalf("ExecStart = %q, want /usr/local/bin/c8s policy-measure ...", args)
	}
	// The platform is the only environment expansion: anything else would
	// let a drop-in's Environment= repoint a disk or the policy dir.
	var flagArgs []string
	for _, arg := range args[2:] {
		if arg == "--platform=${POLICY_PLATFORM}" {
			continue
		}
		if strings.Contains(arg, "$") {
			t.Errorf("ExecStart argument %q expands the environment", arg)
		}
		flagArgs = append(flagArgs, arg)
	}
	if !slices.Contains(args, "--platform=${POLICY_PLATFORM}") {
		t.Error("ExecStart does not pass --platform=${POLICY_PLATFORM}")
	}
	// Every path is the binary default: the consumers (cred-release, the
	// plugin, CDS) build on those defaults, not on the unit.
	flags := NewCmd().Flags()
	if err := flags.Parse(flagArgs); err != nil {
		t.Fatalf("parse baked ExecStart flags: %v", err)
	}
	for _, name := range []string{"policy-dir", "opkey-disk", "policy-disk", "operator-pubkey"} {
		if flags.Changed(name) {
			t.Errorf("ExecStart overrides --%s; the consumers assume the binary default", name)
		}
	}

	for _, tc := range []struct {
		directive string
		want      string
	}{
		{"Before", rke2Pair},
		{"RequiredBy", rke2Pair},
		{"FailureAction", "poweroff-force"},
		{"RestrictAddressFamilies", "AF_UNIX"},
		{"Type", "oneshot"},
		{"RemainAfterExit", "yes"},
	} {
		if got := directives(unit, tc.directive); !slices.Contains(got, tc.want) {
			t.Errorf("c8s-policy-measure.service %s = %q, want %q", tc.directive, got, tc.want)
		}
	}
	// The unit always runs: the mode is measured on every boot.
	if got := directives(unit, "ConditionPathExists"); len(got) != 0 {
		t.Errorf("c8s-policy-measure.service has ConditionPathExists=%q; the measurer must run on every boot", got)
	}
	// Mounting the ISO and extending the register need the kernel
	// interfaces these settings would remove.
	for _, forbidden := range []string{"ProtectKernelTunables", "PrivateDevices", "CapabilityBoundingSet"} {
		if got := directives(unit, forbidden); len(got) != 0 {
			t.Errorf("c8s-policy-measure.service sets %s=%q, which breaks the mount or the sysfs extend", forbidden, got)
		}
	}
	if rw := directives(unit, "ReadWritePaths"); !slices.Contains(rw, filepath.Dir(policybundle.DefaultPolicyDir)) {
		t.Errorf("ReadWritePaths = %q, want %s (the policy dir and the ISO mountpoint)", rw, filepath.Dir(policybundle.DefaultPolicyDir))
	}
	requireOptionalReadOnlyPath(t, unit, "c8s-policy-measure.service", filepath.Dir(DefaultOperatorPubkey))
}

// requireOptionalReadOnlyPath asserts that dir appears in ReadOnlyPaths= only
// with the `-` prefix. The confos initrd creates /etc/confai only on an
// opkeydata boot; without the prefix systemd fails the unit's mount
// namespace setup on every other boot, before ExecStart runs.
func requireOptionalReadOnlyPath(t *testing.T, unit, name, dir string) {
	t.Helper()
	var paths []string
	for _, value := range directives(unit, "ReadOnlyPaths") {
		paths = append(paths, strings.Fields(value)...)
	}
	if slices.Contains(paths, dir) {
		t.Errorf("%s ReadOnlyPaths = %q, want -%s: the initrd creates %s only on an opkeydata boot", name, paths, dir, dir)
	}
	if !slices.Contains(paths, "-"+dir) {
		t.Errorf("%s ReadOnlyPaths = %q, want -%s", name, paths, dir)
	}
}

func TestNodeImageAttestSocketService(t *testing.T) {
	unit := unitFile(t, socketService)
	args := execStart(t, unit, socketService)
	if len(args) < 2 || args[0] != "/usr/local/bin/c8s" || args[1] != "attest-proxy" {
		t.Fatalf("ExecStart = %q, want /usr/local/bin/c8s attest-proxy ...", args)
	}
	for _, arg := range args {
		if strings.Contains(arg, "$") {
			t.Errorf("ExecStart argument %q expands the environment", arg)
		}
	}
	flags := attestproxy.NewCmd().Flags()
	if err := flags.Parse(args[2:]); err != nil {
		t.Fatalf("parse baked ExecStart flags: %v", err)
	}
	if socket, _ := flags.GetString("socket"); socket != attestationSocket {
		t.Errorf("baked --socket = %q, want %q", socket, attestationSocket)
	}
	if filepath.Dir(attestationSocket) != filepath.Dir(policybundle.DefaultPolicyDir) {
		t.Errorf("socket dir %s and policy dir parent %s differ; tmpfiles creates one /run/confai", filepath.Dir(attestationSocket), filepath.Dir(policybundle.DefaultPolicyDir))
	}
	// The literal in the unit must be the constant the chart hands CDS as a
	// supplementary group, or the CDS pod cannot connect.
	if gid, _ := flags.GetInt("socket-gid"); gid != workloadclaims.InventorySocketGID {
		t.Errorf("baked --socket-gid = %d, want workloadclaims.InventorySocketGID %d", gid, workloadclaims.InventorySocketGID)
	}
	if !slices.Contains(args, strconv.Itoa(workloadclaims.InventorySocketGID)) {
		t.Errorf("ExecStart does not spell out --socket-gid %d", workloadclaims.InventorySocketGID)
	}
	if upstream, _ := flags.GetString("upstream"); upstream != "http://127.0.0.1:8400" {
		t.Errorf("baked --upstream = %q, want the confos attestation-api at http://127.0.0.1:8400", upstream)
	}
	for _, tc := range []struct {
		directive string
		want      string
	}{
		{"After", "attestation-api.service"},
		{"Requires", "attestation-api.service"},
		{"Before", rke2Pair},
		{"RequiredBy", rke2Pair},
	} {
		if got := directives(unit, tc.directive); !slices.Contains(got, tc.want) {
			t.Errorf("c8s-attest-socket.service %s = %q, want %q", tc.directive, got, tc.want)
		}
	}
	// The vsock fence: serves AF_UNIX, dials loopback AF_INET, nothing else.
	if got := directives(unit, "RestrictAddressFamilies"); !slices.Contains(got, "AF_UNIX AF_INET") {
		t.Errorf("RestrictAddressFamilies = %q, want AF_UNIX AF_INET", got)
	}
	if got := directives(unit, "User"); len(got) != 0 {
		t.Errorf("User=%q; the socket must be root-owned for attestationclient's owner check", got)
	}
	// Before= on a simple unit orders only the fork. The plugin self-attests
	// over the socket once at startup, so the unit must not count as started
	// until a probe through the socket reaches attestation-api.
	post := directives(unit, "ExecStartPost")
	if len(post) != 1 || !strings.Contains(post[0], "attest-proxy healthcheck --socket "+attestationSocket) {
		t.Errorf("ExecStartPost = %q, want one readiness gate running attest-proxy healthcheck --socket %s", post, attestationSocket)
	}
	if got := directives(unit, "TimeoutStartSec"); len(got) != 1 {
		t.Errorf("TimeoutStartSec = %q, want one bound on the readiness gate", got)
	}
}

func TestNodeImagePresetTmpfilesAndSync(t *testing.T) {
	preset, err := os.ReadFile(filepath.Clean(nodeImagePreset))
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"c8s-policy-measure.service", "c8s-attest-socket.service", "cred-release.service"} {
		if !slices.Contains(strings.Split(string(preset), "\n"), "enable "+unit) {
			t.Errorf("50-rke2.preset does not enable %s; without it the RequiredBy links are never created", unit)
		}
	}

	tmpfiles, err := os.ReadFile(filepath.Clean(nodeImageTmpfiles))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Dir(policybundle.DefaultPolicyDir), policybundle.DefaultPolicyDir} {
		if !regexp.MustCompile(`(?m)^d ` + regexp.QuoteMeta(dir) + ` 0755 root root`).Match(tmpfiles) {
			t.Errorf("confos-rke2.conf does not create %s 0755 root root", dir)
		}
	}
	// tmpfiles, not RuntimeDirectory=: a unit restart must not remove the
	// other unit's files under /run/confai.
	for _, path := range []string{measureService, socketService} {
		if got := directives(unitFile(t, path), "RuntimeDirectory"); len(got) != 0 {
			t.Errorf("%s sets RuntimeDirectory=%q, which is removed on stop", path, got)
		}
	}

	sync, err := os.ReadFile(filepath.Clean(nodeImageSync))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sync), "Environment=POLICY_PLATFORM=") ||
		!strings.Contains(string(sync), "c8s-policy-measure.service.d/10-platform.conf") {
		t.Error("mkosi.sync does not render the c8s-policy-measure platform drop-in (Environment=POLICY_PLATFORM=)")
	}
}
