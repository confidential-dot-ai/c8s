package launchconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func testKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func testDocument(t *testing.T, platform string, role Role) (Document, *ecdsa.PrivateKey, string) {
	t.Helper()
	leaderKey, leaderPub := testKey(t)
	followerKey, followerPub := testKey(t)
	doc := Document{
		SchemaVersion: SchemaVersion, ClusterID: "cluster-one", Role: role,
		Image:                      Image{Platform: platform, Measurement: strings.Repeat("11", 48)},
		Node:                       Node{Name: "node-one", IP: "10.0.0.2", ExternalIP: "192.0.2.4"},
		RKE2:                       RKE2{AgentToken: strings.Repeat("a", 64)},
		Leader:                     LeaderConfig{Address: "10.0.0.1", OperatorPublicKey: leaderPub},
		FollowerOperatorPublicKeys: []string{followerPub},
	}
	if platform == "tdx" {
		doc.Image.RTMRs = map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}
	}
	if role == Leader {
		doc.RKE2.ServerToken = strings.Repeat("b", 64)
		return doc, leaderKey, leaderPub
	}
	return doc, followerKey, followerPub
}

func testLoader(t *testing.T, doc Document, pub string) {
	t.Helper()
	old := loadMeasuredOperatorKeyAndOwnMeasurement
	t.Cleanup(func() { loadMeasuredOperatorKeyAndOwnMeasurement = old })
	digest := mustDecodeHex(doc.Image.Measurement)
	rtmrs := make(map[int][]byte)
	for i, value := range doc.Image.RTMRs {
		rtmrs[i] = mustDecodeHex(value)
	}
	loadMeasuredOperatorKeyAndOwnMeasurement = func(context.Context, string, string) ([]byte, error, []byte, map[int][]byte, error) {
		return []byte(pub), nil, digest, rtmrs, nil
	}
}

func testConfig(t *testing.T, doc Document, key *ecdsa.PrivateKey) Config {
	t.Helper()
	cfg := Config{Platform: doc.Image.Platform, RootDir: t.TempDir()}
	cfg.DocumentPath = filepath.Join(t.TempDir(), "launch.yaml")
	cfg.SignaturePath = cfg.DocumentPath + ".sig"
	signDocument(t, cfg, doc, key)
	return cfg
}

func signDocument(t *testing.T, cfg Config, doc Document, key *ecdsa.PrivateKey) {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	signBytes(t, cfg, data, key)
}

func signBytes(t *testing.T, cfg Config, data []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	sig, err := operatorauth.SignDetached(key, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.DocumentPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SignaturePath, []byte(sig+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStageBothRolesAndPlatforms(t *testing.T) {
	for _, platform := range []string{"snp", "tdx"} {
		for _, role := range []Role{Leader, Follower} {
			t.Run(platform+"/"+string(role), func(t *testing.T) {
				doc, key, pub := testDocument(t, platform, role)
				doc.Node.IP = "0.0.0.0"
				doc.Workloads = `{"schema":"c8s.allowlist/v1","workloads":{}}`
				testLoader(t, doc, pub)
				cfg := testConfig(t, doc, key)
				if err := Stage(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				staged, err := LoadStaged(cfg.path(DefaultStagedPath))
				if err != nil {
					t.Fatal(err)
				}
				if staged.Role != role || staged.TLSSAN != "c8s.local" || staged.Node.IP != "" {
					t.Fatalf("incorrect staged role/default/address")
				}
				peers, err := measurements.Load(cfg.path(Dir + "/peers.json"))
				if err != nil {
					t.Fatal(err)
				}
				cds, err := measurements.Load(cfg.path(Dir + "/cds.json"))
				if err != nil {
					t.Fatal(err)
				}
				if len(peers.Entries) != 2 || len(cds.Entries) != 1 || !bytes.Equal(cds.Entries[0].OperatorKey, []byte(doc.Leader.OperatorPublicKey)) {
					t.Fatal("node and leader policy sets are not separated")
				}
				for _, entry := range peers.Entries {
					if !bytes.Equal(entry.Digest, mustDecodeHex(doc.Image.Measurement)) {
						t.Fatal("peer policy changed the shared image")
					}
					if platform == "tdx" && len(entry.RTMRs) != 2 {
						t.Fatal("TDX peer omitted runtime image pins")
					}
				}
				fragment, err := os.ReadFile(cfg.path(rke2FragmentPath))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(fragment), "node-ip:") {
					t.Fatal("RKE2 must autodetect 0.0.0.0")
				}
				if role == Leader {
					requirePresent(t, cfg.path(serverMarker))
					requireAbsent(t, cfg.path(agentMarker))
					requirePresent(t, cfg.path(serverTokenPath))
					if !bytes.Contains(fragment, []byte("agent-token-file: "+agentTokenPath)) {
						t.Fatal("leader must configure the separate agent token")
					}
					manifest, err := os.ReadFile(cfg.path(runtimeManifestPath))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Contains(manifest, []byte("cds-url: https://10.0.0.1:30808")) || bytes.Contains(manifest, []byte(doc.RKE2.ServerToken)) {
						t.Fatal("runtime ConfigMap must contain leader discovery but no credentials")
					}
				} else {
					requirePresent(t, cfg.path(agentMarker))
					requireAbsent(t, cfg.path(serverMarker))
					requireAbsent(t, cfg.path(serverTokenPath))
					requireAbsent(t, cfg.path(runtimeManifestPath))
					if !bytes.Contains(fragment, []byte("server: https://10.0.0.1:9345")) {
						t.Fatal("follower does not join signed leader")
					}
				}
				for _, path := range []string{DefaultStagedPath, agentTokenPath, Dir + "/workloads.json", rke2FragmentPath} {
					info, err := os.Stat(cfg.path(path))
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != 0o600 {
						t.Fatalf("%s mode = %v", path, info.Mode())
					}
				}
			})
		}
	}
}

func TestVerifyRejectsUnauthorizedRoleOrImage(t *testing.T) {
	tests := []struct {
		name   string
		role   Role
		change func(*Document)
		want   string
	}{
		{"MRTD", Leader, func(d *Document) { d.Image.Measurement = strings.Repeat("44", 48) }, "measurement"},
		{"kernel RTMR", Leader, func(d *Document) { d.Image.RTMRs[1] = strings.Repeat("44", 48) }, "RTMR[1]"},
		{"rootfs RTMR", Leader, func(d *Document) { d.Image.RTMRs[2] = strings.Repeat("44", 48) }, "RTMR[2]"},
		{"missing RTMR", Leader, func(d *Document) { delete(d.Image.RTMRs, 2) }, "exactly RTMR"},
		{"platform", Leader, func(d *Document) { d.Image.Platform = "snp"; d.Image.RTMRs = nil }, "platform"},
		{"follower as leader", Follower, func(d *Document) { d.Role = Leader; d.RKE2.ServerToken = strings.Repeat("b", 64) }, "leader launch key"},
		{"leader as follower", Leader, func(d *Document) { d.Role = Follower; d.RKE2.ServerToken = "" }, "different launch key"},
		{"follower carries server token", Follower, func(d *Document) { d.RKE2.ServerToken = strings.Repeat("b", 64) }, "must not carry"},
		{"shared role keys", Follower, func(d *Document) {
			d.FollowerOperatorPublicKeys = []string{strings.TrimSpace(d.Leader.OperatorPublicKey)}
		}, "distinct"},
		{"unlisted follower", Follower, func(d *Document) { _, pub := testKey(t); d.FollowerOperatorPublicKeys = []string{pub} }, "not in"},
		{"missing role", Leader, func(d *Document) { d.Role = "" }, "role"},
		{"token equality", Leader, func(d *Document) { d.RKE2.ServerToken = d.RKE2.AgentToken }, "must differ"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, key, pub := testDocument(t, "tdx", tc.role)
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			tc.change(&doc)
			signDocument(t, cfg, doc, key)
			_, err := Verify(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSignaturePrecedesParsing(t *testing.T) {
	doc, key, pub := testDocument(t, "tdx", Leader)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	wrong, _ := testKey(t)
	signBytes(t, cfg, []byte("invalid: [yaml"), wrong)
	_, err := Verify(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want signature rejection before parse, got %v", err)
	}
}

func TestParseRejectsAmbiguousOrUnexpectedFields(t *testing.T) {
	doc, _, _ := testDocument(t, "snp", Follower)
	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"duplicate":          append(append([]byte{}, raw...), []byte("role: leader\n")...),
		"multiple":           append(append([]byte{}, raw...), []byte("---\n{}\n")...),
		"unknown":            append(append([]byte{}, raw...), []byte("helmValues: {}\n")...),
		"nested unknown":     bytes.Replace(raw, []byte("    agentToken:"), []byte("    arbitraryFlag: hello\n    agentToken:"), 1),
		"alias":              bytes.Replace(raw, []byte("role: follower"), []byte("role: &role follower"), 1),
		"empty server token": bytes.Replace(raw, []byte("    agentToken:"), []byte("    serverToken: ''\n    agentToken:"), 1),
		"null server token":  bytes.Replace(raw, []byte("    agentToken:"), []byte("    serverToken: null\n    agentToken:"), 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatalf("accepted %s input", name)
			}
		})
	}
}

func TestParseRejectsNoncanonicalRTMRIndex(t *testing.T) {
	doc, _, _ := testDocument(t, "tdx", Leader)
	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Replace(raw, []byte("        1:"), []byte("        01:"), 1)
	if bytes.Equal(data, raw) {
		t.Fatal("fixture did not replace RTMR index")
	}
	if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "noncanonical") {
		t.Fatalf("want noncanonical index rejection, got %v", err)
	}
}

func TestKeylessAndFailedAttestationNeverStageARole(t *testing.T) {
	for _, keyErr := range []error{credrelease.ErrNoOperatorKey, os.ErrNotExist, errors.New("binding mismatch")} {
		t.Run(keyErr.Error(), func(t *testing.T) {
			doc, key, pub := testDocument(t, "snp", Leader)
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			loadMeasuredOperatorKeyAndOwnMeasurement = func(context.Context, string, string) ([]byte, error, []byte, map[int][]byte, error) {
				return nil, keyErr, mustDecodeHex(doc.Image.Measurement), nil, nil
			}
			if err := Stage(context.Background(), cfg); err == nil {
				t.Fatal("accepted unauthenticated launch key")
			}
			requireAbsent(t, cfg.path(serverMarker))
			requireAbsent(t, cfg.path(agentMarker))
		})
	}
}

func TestFailedRestagingClearsAuthorizationAndSecrets(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Leader)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SignaturePath, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Stage(context.Background(), cfg); err == nil {
		t.Fatal("accepted tampered signature")
	}
	for _, path := range []string{serverMarker, agentMarker, serverTokenPath, agentTokenPath, DefaultStagedPath, runtimeManifestPath, rke2FragmentPath} {
		requireAbsent(t, cfg.path(path))
	}
}

func TestWriteFailureCannotPublishRole(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Leader)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	verified, err := Verify(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.path("/var/lib/rancher/rke2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.path("/var/lib/rancher/rke2/server"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stageVerified(cfg, verified); err == nil {
		t.Fatal("expected manifest output failure")
	}
	requireAbsent(t, cfg.path(serverMarker))
	requireAbsent(t, cfg.path(agentMarker))
}

func TestBoundedDocumentAndMissingConfig(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Leader)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := os.WriteFile(cfg.DocumentPath, bytes.Repeat([]byte("a"), MaxDocumentSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), cfg); err == nil {
		t.Fatal("accepted oversized input")
	}
	if err := os.Remove(cfg.DocumentPath); err != nil {
		t.Fatal(err)
	}
	if err := Stage(context.Background(), cfg); err == nil {
		t.Fatal("defaulted a missing launch to a role")
	}
}

func requireAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s must not exist: %v", path, err)
	}
}
func requirePresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
}

func TestLeaderAddressResolution(t *testing.T) {
	tests := []struct {
		name, nodeIP, resolved, want string
		resolveErr                   error
	}{
		{name: "signed node address", nodeIP: "10.0.0.8", want: "10.0.0.8"},
		{name: "primary route", resolved: "10.0.0.9", want: "10.0.0.9"},
		{name: "no route", resolveErr: errors.New("no default route")},
		{name: "IPv6 only", resolved: "2001:db8::1"},
		{name: "unspecified result", resolved: "0.0.0.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, key, pub := testDocument(t, "snp", Leader)
			doc.Leader.Address = ""
			doc.Node.IP = tc.nodeIP
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			old := chooseHostInterface
			t.Cleanup(func() { chooseHostInterface = old })
			chooseHostInterface = func() (net.IP, error) {
				if tc.nodeIP != "" {
					t.Fatal("resolver should not replace signed node IP")
				}
				if tc.resolveErr != nil {
					return nil, tc.resolveErr
				}
				return net.ParseIP(tc.resolved), nil
			}
			err := Stage(context.Background(), cfg)
			if tc.want == "" {
				if err == nil {
					t.Fatal("expected address resolution failure")
				}
				requireAbsent(t, cfg.path(serverMarker))
				requireAbsent(t, cfg.path(agentMarker))
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			staged, err := LoadStaged(cfg.path(DefaultStagedPath))
			if err != nil {
				t.Fatal(err)
			}
			if staged.Leader.Address != tc.want || staged.Node.IP != tc.want {
				t.Fatal("resolved address not staged consistently")
			}
		})
	}
	doc, _, _ := testDocument(t, "snp", Follower)
	doc.Leader.Address = ""
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err == nil {
		t.Fatal("follower requires an explicit leader address")
	}
}
