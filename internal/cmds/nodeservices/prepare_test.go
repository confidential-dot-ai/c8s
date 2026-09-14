package nodeservices

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

func TestArgumentsRequireAStagedRole(t *testing.T) {
	if _, err := Arguments("cds", nil, ""); err == nil || !strings.Contains(err.Error(), "missing staged") {
		t.Fatalf("nil document: %v", err)
	}
	if _, err := Arguments("cds", document("observer"), ""); err == nil || !strings.Contains(err.Error(), "invalid staged role") {
		t.Fatalf("unknown role: %v", err)
	}
}

func TestNodeIPRoundTrip(t *testing.T) {
	root := t.TempDir()
	if _, err := readNodeIP(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing node IP: %v", err)
	}
	doc := document(launchconfig.Follower)
	doc.Node.IP = "192.0.2.22"
	if err := PublishNodeIP(root, doc); err != nil {
		t.Fatal(err)
	}
	ip, err := readNodeIP(root)
	if err != nil || ip != "192.0.2.22" {
		t.Fatalf("got %q, %v", ip, err)
	}
	if _, err := NodeIP(); err == nil {
		t.Skip("the fixed node IP path exists on this host")
	}
}

func TestPublishNodeIPResolvesTheHostRoute(t *testing.T) {
	old := primaryIPv4
	t.Cleanup(func() { primaryIPv4 = old })
	doc := document(launchconfig.Follower)

	primaryIPv4 = func() (string, error) { return "", errors.New("no default route") }
	if err := PublishNodeIP(t.TempDir(), doc); err == nil || !strings.Contains(err.Error(), "no default route") {
		t.Fatalf("route failure: %v", err)
	}
	primaryIPv4 = func() (string, error) { return "2001:db8::1", nil }
	if err := PublishNodeIP(t.TempDir(), doc); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("IPv6 route: %v", err)
	}
	primaryIPv4 = func() (string, error) { return "192.0.2.30", nil }
	root := t.TempDir()
	if err := PublishNodeIP(root, doc); err != nil {
		t.Fatal(err)
	}
	if ip, err := readNodeIP(root); err != nil || ip != "192.0.2.30" {
		t.Fatalf("got %q, %v", ip, err)
	}

	blocked := t.TempDir()
	if err := os.WriteFile(filepath.Join(blocked, "var"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PublishNodeIP(blocked, doc); err == nil {
		t.Fatal("published through a blocked parent directory")
	}
}

func TestPrepareFailsClosedOnBrokenBakedInputs(t *testing.T) {
	overwrite := func(root, name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "usr/lib/c8s", name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name   string
		role   launchconfig.Role
		break_ func(root string)
		want   string
	}{
		{"missing policy", launchconfig.Follower, func(root string) { os.Remove(filepath.Join(root, "usr/lib/c8s/image-policy.yaml")) }, "image-policy.yaml"},
		{"invalid policy yaml", launchconfig.Follower, func(root string) { overwrite(root, "image-policy.yaml", "allowlist: [") }, "baked NRI policy"},
		{"policy without allowlist", launchconfig.Follower, func(root string) { overwrite(root, "image-policy.yaml", "platform: tdx\n") }, "missing allowlist"},
		{"policy without pull", launchconfig.Follower, func(root string) { overwrite(root, "image-policy.yaml", "allowlist:\n  always_allow: {}\n") }, "missing pull"},
		{"missing nginx template", launchconfig.Leader, func(root string) { os.Remove(filepath.Join(root, "usr/lib/c8s/nginx.conf.in")) }, "nginx.conf.in"},
		{"nginx template without hostname", launchconfig.Leader, func(root string) { overwrite(root, "nginx.conf.in", "server_name other;\n") }, "missing hostname"},
		{"missing seed", launchconfig.Leader, func(root string) { os.Remove(filepath.Join(root, "usr/lib/c8s/allowlist-seed.json")) }, "allowlist-seed.json"},
		{"invalid seed", launchconfig.Leader, func(root string) { overwrite(root, "allowlist-seed.json", "{") }, "baked workload seed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			tc.break_(root)
			err := Prepare(root, document(tc.role))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(root, launchDir, "allowlist-seed.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published a seed from broken inputs")
			}
		})
	}
}

func TestPrepareRejectsInvalidLaunchWorkloads(t *testing.T) {
	root := prepareRoot(t)
	doc := document(launchconfig.Leader)
	doc.Workloads = `{"schema":"c8s.allowlist/v1","workloads":`
	err := Prepare(root, doc)
	if err == nil || !strings.Contains(err.Error(), "launch workloads") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, launchDir, "allowlist-seed.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published a seed with rejected launch workloads")
	}
	// The nginx template is still rendered before the seed is validated, with
	// the signed SAN in place of the baked placeholder.
	conf, err := os.ReadFile(filepath.Join(root, launchDir, "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "server_name c8s.local;") || strings.Contains(string(conf), "c8s-node.invalid") {
		t.Fatalf("nginx.conf = %q", conf)
	}
}
