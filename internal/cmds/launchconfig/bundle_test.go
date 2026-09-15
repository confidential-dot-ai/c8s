package launchconfig

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

// writeManifest writes a build manifest of the given platform, with the
// register values every test compares against.
func writeManifest(t *testing.T, platform string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	var body string
	switch platform {
	case "tdx":
		body = `{"version":1,"build":{"platform":"tdx"},"tdx":{"mrtd":"` + strings.Repeat("11", 48) +
			`","rtmr1":"` + strings.Repeat("22", 48) + `","rtmr2":"` + strings.Repeat("33", 48) + `"}}`
	case "snp":
		body = `{"snp_variants":[` +
			`{"smp":4,"measurement":{"snp_launch_digest":"` + strings.Repeat("44", 48) + `","algorithm":"sha384"}},` +
			`{"smp":8,"measurement":{"snp_launch_digest":"` + strings.Repeat("55", 48) + `","algorithm":"sha384"}}]}`
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readBundleDocument(t *testing.T, dir, node string) (*Document, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, node, documentFile))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatalf("%s document does not parse: %v", node, err)
	}
	return doc, data
}

// runBundleCmd drives the real cobra command so flag wiring is under test.
func runBundleCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	return cmd.Execute()
}

// stageBundleNode proves the bundle's document for node is what the guest
// accepts: Stage verifies the signature against the node's pubkey with the
// production code path and a self-report matching the manifest pins.
func stageBundleNode(t *testing.T, dir, node string) {
	t.Helper()
	doc, _ := readBundleDocument(t, dir, node)
	pub, err := os.ReadFile(filepath.Join(dir, node, pubkeyFile))
	if err != nil {
		t.Fatal(err)
	}
	testLoader(t, *doc, string(pub))
	cfg := Config{
		Platform:      doc.Image.Platform,
		RootDir:       t.TempDir(),
		DocumentPath:  filepath.Join(dir, node, documentFile),
		SignaturePath: filepath.Join(dir, node, signatureFile),
	}
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatalf("stage %s from the bundle: %v", node, err)
	}
	staged, err := LoadStaged(cfg.path(DefaultStagedPath))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Node.Name != doc.Node.Name || staged.Role != doc.Role {
		t.Fatalf("staged %s %q for bundle entry %q", staged.Role, staged.Node.Name, node)
	}
}

func TestNewBundleBootsLeaderAndFollowersOnBothPlatforms(t *testing.T) {
	for _, platform := range []string{"tdx", "snp"} {
		t.Run(platform, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundle")
			args := []string{"new", "--out", dir, "--cluster-id", "demo", "--image-manifest", writeManifest(t, platform),
				"--leader-address", "10.0.0.10", "--follower", "demo-f1", "--follower", "demo-f2"}
			if platform == "snp" {
				args = append(args, "--vcpus", "8")
			}
			if err := runBundleCmd(t, args...); err != nil {
				t.Fatal(err)
			}
			leader, _ := readBundleDocument(t, dir, leaderDir)
			if leader.Role != Leader || leader.Node.Name != "demo-leader" || leader.ClusterID != "demo" || leader.TLSSAN != defaultTLSSAN {
				t.Fatalf("unexpected leader document: %+v", leader)
			}
			if leader.Image.Platform != platform {
				t.Fatalf("leader image platform %q", leader.Image.Platform)
			}
			if platform == "tdx" {
				if leader.Image.Measurement != strings.Repeat("11", 48) || leader.Image.RTMRs[1] != strings.Repeat("22", 48) || leader.Image.RTMRs[2] != strings.Repeat("33", 48) {
					t.Fatalf("TDX pins not taken from the manifest: %+v", leader.Image)
				}
			} else if leader.Image.Measurement != strings.Repeat("55", 48) || len(leader.Image.RTMRs) != 0 {
				t.Fatalf("SNP pin is not the 8-vCPU variant: %+v", leader.Image)
			}
			if leader.RKE2.ServerToken == leader.RKE2.AgentToken || !tokenRE.MatchString(leader.RKE2.ServerToken) {
				t.Fatalf("tokens not generated independently: %+v", leader.RKE2)
			}
			for _, name := range []string{"demo-f1", "demo-f2"} {
				follower, data := readBundleDocument(t, dir, name)
				if follower.Role != Follower || follower.Node.Name != name || follower.Leader.Address != "10.0.0.10" {
					t.Fatalf("unexpected follower %s: %+v", name, follower)
				}
				if bytes.Contains(data, []byte(leader.RKE2.ServerToken)) || bytes.Contains(data, []byte("serverToken")) {
					t.Fatalf("follower %s carries the server token", name)
				}
				if follower.RKE2.AgentToken != leader.RKE2.AgentToken || !reflect.DeepEqual(follower.Image, leader.Image) ||
					follower.Leader.OperatorPublicKey != leader.Leader.OperatorPublicKey ||
					follower.FollowerOperatorPublicKeys[0] != leader.FollowerOperatorPublicKeys[0] {
					t.Fatalf("follower %s diverges from the leader's cluster facts", name)
				}
				pub, _ := os.ReadFile(filepath.Join(dir, name, pubkeyFile))
				if string(pub) != leader.FollowerOperatorPublicKeys[0] {
					t.Fatalf("follower %s pubkey is not the trusted follower key", name)
				}
			}
			// The leader's pubkey is the exact PEM the leader document names.
			pub, _ := os.ReadFile(filepath.Join(dir, leaderDir, pubkeyFile))
			if string(pub) != leader.Leader.OperatorPublicKey {
				t.Fatal("leader pubkey differs from leader.operatorPublicKey")
			}
			for _, node := range []string{leaderDir, "demo-f1", "demo-f2"} {
				stageBundleNode(t, dir, node)
			}
			// leader.key is the key the leader document was signed with, so it
			// also serves get-kubeconfig --operator-key.
			key, err := certutil.LoadECPrivateKeyFile(filepath.Join(dir, leaderKeyFile))
			if err != nil {
				t.Fatal(err)
			}
			wantPub, _ := publicKeyPEM(key)
			if wantPub != leader.Leader.OperatorPublicKey {
				t.Fatal("leader.key does not match the leader's launch public key")
			}
			// The client policy pins exactly the leader entry Stage derives.
			policy, err := measurements.Load(filepath.Join(dir, leaderPolicy))
			if err != nil {
				t.Fatal(err)
			}
			want, _ := leader.referenceValues()
			if len(policy.Entries) != 1 || policy.TEE != want.TEE || !bytes.Equal(policy.Entries[0].OperatorKey, want.Entries[0].OperatorKey) ||
				!bytes.Equal(policy.Entries[0].Digest, want.Entries[0].Digest) {
				t.Fatalf("leader.json pins %+v, want the leader entry %+v", policy, want.Entries[0])
			}
			for _, f := range []string{leaderKeyFile, followerKeyFile, filepath.Join(leaderDir, documentFile), filepath.Join("demo-f1", signatureFile)} {
				info, err := os.Stat(filepath.Join(dir, f))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Fatalf("%s is %v, want 0600", f, info.Mode().Perm())
				}
			}
		})
	}
}

func TestAddFollowerExtendsAnExistingBundle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, "new", "--out", dir, "--cluster-id", "demo", "--image-manifest", writeManifest(t, "tdx")); err != nil {
		t.Fatal(err)
	}
	if err := runBundleCmd(t, "add-follower", "--bundle", dir, "--name", "late"); err == nil || !strings.Contains(err.Error(), "--leader-address") {
		t.Fatalf("a follower of an autodetecting leader needs an explicit address, got %v", err)
	}
	if err := runBundleCmd(t, "add-follower", "--bundle", dir, "--name", "late", "--leader-address", "10.0.0.10"); err != nil {
		t.Fatal(err)
	}
	leader, _ := readBundleDocument(t, dir, leaderDir)
	follower, _ := readBundleDocument(t, dir, "late")
	if follower.Role != Follower || follower.Leader.Address != "10.0.0.10" || follower.RKE2.AgentToken != leader.RKE2.AgentToken {
		t.Fatalf("unexpected late follower: %+v", follower)
	}
	stageBundleNode(t, dir, "late")
	for _, bad := range []string{"late", leaderDir, "demo-leader", "Not_A_Label"} {
		if err := runBundleCmd(t, "add-follower", "--bundle", dir, "--name", bad, "--leader-address", "10.0.0.10"); err == nil {
			t.Fatalf("add-follower accepted %q", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, leaderDir, documentFile)); err != nil {
		t.Fatal("a rejected follower must not disturb the bundle:", err)
	}
}

func TestNewBundleRefusesBadInputsAndLeavesNothingBehind(t *testing.T) {
	tdx, snp := writeManifest(t, "tdx"), writeManifest(t, "snp")
	base := t.TempDir()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"snp without vcpus", []string{"--image-manifest", snp}, "--vcpus is required"},
		{"snp unknown vcpus", []string{"--image-manifest", snp, "--vcpus", "6"}, "no SNP launch digest"},
		{"tdx with vcpus", []string{"--image-manifest", tdx, "--vcpus", "4"}, "SNP manifests only"},
		{"follower without address", []string{"--image-manifest", tdx, "--follower", "f1"}, "--leader-address is required"},
		{"bad cluster id", []string{"--image-manifest", tdx, "--cluster-id", "Demo"}, "clusterID"},
		{"bad follower name", []string{"--image-manifest", tdx, "--leader-address", "10.0.0.10", "--follower", "leader"}, "reserved"},
		{"loopback leader", []string{"--image-manifest", tdx, "--leader-address", "127.0.0.1"}, "leader.address"},
		{"not a manifest", []string{"--image-manifest", filepath.Join(base, "missing.json")}, "--image-manifest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(base, strings.ReplaceAll(tc.name, " ", "-"))
			args := append([]string{"new", "--out", dir, "--cluster-id", "demo"}, tc.args...)
			err := runBundleCmd(t, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Fatalf("failed bundle left %s behind", dir)
			}
		})
	}
	dir := filepath.Join(base, "existing")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runBundleCmd(t, "new", "--out", dir, "--cluster-id", "demo", "--image-manifest", tdx); err == nil {
		t.Fatal("an existing directory must not be reused for a new bundle")
	}
}

func TestNewBundleCarriesAnInitialAllowlist(t *testing.T) {
	workloads := filepath.Join(t.TempDir(), "workloads.json")
	if err := os.WriteFile(workloads, []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	err := runBundleCmd(t, "new", "--out", dir, "--cluster-id", "demo", "--image-manifest", writeManifest(t, "tdx"),
		"--tls-san", "cluster.example", "--workloads", workloads)
	if err != nil {
		t.Fatal(err)
	}
	leader, _ := readBundleDocument(t, dir, leaderDir)
	if leader.TLSSAN != "cluster.example" || leader.Workloads == "" {
		t.Fatalf("SAN or workloads not carried: %+v", leader)
	}
	stageBundleNode(t, dir, leaderDir)
}
