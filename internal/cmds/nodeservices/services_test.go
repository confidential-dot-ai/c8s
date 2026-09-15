package nodeservices

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"gopkg.in/yaml.v3"
)

func document(role launchconfig.Role) *launchconfig.Document {
	return &launchconfig.Document{Role: role, Image: launchconfig.Image{Platform: "tdx"}, Leader: launchconfig.LeaderConfig{Address: "192.0.2.10"}, TLSSAN: "c8s.local"}
}

func TestFollowerCannotRunLeaderServices(t *testing.T) {
	for _, name := range []string{"cds", "get-cert", "cds-attest", "allowlist-proxy", "join-release"} {
		if _, err := Arguments(name, document(launchconfig.Follower), "192.0.2.11"); err == nil {
			t.Errorf("follower can run %s", name)
		}
	}
	for _, name := range []string{"mesh", "mesh-sync", "attest-proxy", "join"} {
		if _, err := Arguments(name, document(launchconfig.Follower), "192.0.2.11"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Arguments("arbitrary", document(launchconfig.Leader), ""); err == nil {
		t.Fatal("unknown service accepted")
	}
}

func TestEveryCDSClientUsesLeaderPolicy(t *testing.T) {
	for _, name := range []string{"mesh", "get-cert", "allowlist-proxy"} {
		args, err := Arguments(name, document(launchconfig.Leader), "192.0.2.10")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, arg := range args {
			if strings.HasPrefix(arg, "--measurements-config=") || strings.HasPrefix(arg, "--cds-measurements-config=") {
				if strings.HasSuffix(arg, "/cds.json") {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s has no complete leader policy: %v", name, args)
		}
		if !slices.Contains(args, "--cds-url=https://192.0.2.10:30808") {
			t.Errorf("%s ignores leader endpoint", name)
		}
	}
	for _, ip := range []string{"", "0.0.0.0", "127.0.0.1", "192.0.2.10 --other-flag"} {
		if _, err := Arguments("mesh", document(launchconfig.Leader), ip); err == nil {
			t.Errorf("accepted node IP %q", ip)
		}
	}
}

const floor = "platform: tdx\nallowlist:\n  always_allow:\n    immutable: system\n  pull:\n    url: https://127.0.0.1:30808\n    timeout: 30s\n    cds_measurements: []\npolicy:\n  mode: fail-closed\n  enforce_existing: true\n"
const seed = `{"schema":"c8s.allowlist/v1","workloads":{"operator":{"containers":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`

func prepareRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range map[string]string{"image-policy.yaml": floor, "nginx.conf.in": "server_name c8s-node.invalid;\n", "allowlist-seed.json": seed} {
		p := filepath.Join(root, "usr/lib/c8s", name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestPreparePreservesFloorAndPinsLeaderBeforeRKE2(t *testing.T) {
	for _, role := range []launchconfig.Role{launchconfig.Leader, launchconfig.Follower} {
		t.Run(string(role), func(t *testing.T) {
			root := prepareRoot(t)
			doc := document(role)
			if err := Prepare(root, doc); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var got, before map[string]any
			if err := yaml.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal([]byte(floor), &before); err != nil {
				t.Fatal(err)
			}
			ga := got["allowlist"].(map[string]any)
			if !reflect.DeepEqual(got["policy"], before["policy"]) || !reflect.DeepEqual(ga["always_allow"], before["allowlist"].(map[string]any)["always_allow"]) {
				t.Fatal("changed baked floor")
			}
			pull := ga["pull"].(map[string]any)
			if pull["url"] != doc.CDSURL() || pull["cds_measurements_config"] != launchDir+"cds.json" || pull["timeout"] != "30s" {
				t.Fatalf("bad pull config: %v", pull)
			}
			if _, exists := pull["cds_measurements"]; exists {
				t.Fatal("flat pins retained")
			}
			_, err = os.Stat(filepath.Join(root, launchDir, "allowlist-seed.json"))
			if role == launchconfig.Follower && !os.IsNotExist(err) {
				t.Fatal("follower received leader seed")
			}
			if role == launchconfig.Leader && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPrepareCannotReplaceBakedWorkload(t *testing.T) {
	root := prepareRoot(t)
	doc := document(launchconfig.Leader)
	doc.Workloads = seed
	if err := Prepare(root, doc); err == nil || !strings.Contains(err.Error(), "replaces a baked component") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, launchDir, "allowlist-seed.json")); !os.IsNotExist(err) {
		t.Fatal("published rejected seed")
	}

	doc.Workloads = strings.ReplaceAll(strings.ReplaceAll(seed, "operator", "application"), strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err := Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, launchDir, "allowlist-seed.json"))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := allowlist.ParseJSON(data)
	if err != nil || len(merged.Workloads) != 2 {
		t.Fatalf("merged policy: %v %v", merged, err)
	}
}

func TestPublishNodeIPHonorsAuthenticatedAddress(t *testing.T) {
	root := t.TempDir()
	doc := document(launchconfig.Follower)
	doc.Node.IP = "192.0.2.22"
	if err := PublishNodeIP(root, doc); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, nodeIPPath))
	if err != nil || string(data) != "192.0.2.22\n" {
		t.Fatalf("got %q, %v", data, err)
	}
	for _, ip := range []string{"0.0.0.0", "127.0.0.1", "::1"} {
		doc.Node.IP = ip
		if err := PublishNodeIP(t.TempDir(), doc); err == nil {
			t.Errorf("accepted %s", ip)
		}
	}
}

func TestJoinServicesRequireTheirSeparateRolePolicies(t *testing.T) {
	leader := document(launchconfig.Leader)
	if _, err := Arguments("join", leader, ""); err == nil {
		t.Fatal("leader can execute follower enrollment")
	}
	if _, err := Arguments("join-release", leader, ""); err == nil {
		t.Fatal("leader with no authorized followers can release join tokens")
	}
	leader.FollowerOperatorPublicKeys = []string{"authorized follower"}
	args, err := Arguments("join-release", leader, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--measurements-config="+launchDir+"followers.json") {
		t.Fatal("join release does not restrict callers to the follower policy")
	}
	args, err = Arguments("join", document(launchconfig.Follower), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--measurements-config=" + launchDir + "cds.json", "--server=192.0.2.10:8444", "--token-out=/run/confos/rke2-agent-token", "--fragment-out="} {
		if !slices.Contains(args, required) {
			t.Fatalf("missing enrollment argument %s", required)
		}
	}
}
