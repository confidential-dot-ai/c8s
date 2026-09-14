package launchconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidateRejectsEachMalformedField(t *testing.T) {
	_, otherPub := testKey(t)
	tests := []struct {
		name   string
		role   Role
		change func(*Document)
		want   string
	}{
		{"schema", Leader, func(d *Document) { d.SchemaVersion = "c8s-launch/v0" }, "schemaVersion"},
		{"cluster label", Leader, func(d *Document) { d.ClusterID = "Cluster_One" }, "clusterID"},
		{"node label", Leader, func(d *Document) { d.Node.Name = "-node" }, "node.name"},
		{"platform", Leader, func(d *Document) { d.Image.Platform = "sgx" }, "image.platform"},
		{"measurement length", Leader, func(d *Document) { d.Image.Measurement = "abcd" }, "image.measurement"},
		{"measurement case", Leader, func(d *Document) { d.Image.Measurement = strings.Repeat("AB", 48) }, "image.measurement"},
		{"measurement hex", Leader, func(d *Document) { d.Image.Measurement = strings.Repeat("zz", 48) }, "image.measurement"},
		{"snp with rtmrs", Leader, func(d *Document) {
			d.Image.RTMRs = map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}
		}, "SNP image cannot"},
		{"leader address", Leader, func(d *Document) { d.Leader.Address = "224.0.0.1" }, "leader.address"},
		{"leader address v6", Leader, func(d *Document) { d.Leader.Address = "2001:db8::1" }, "leader.address"},
		{"node ip", Leader, func(d *Document) { d.Node.IP = "not-an-ip" }, "node.ip"},
		{"external ip", Leader, func(d *Document) { d.Node.ExternalIP = "127.0.0.1" }, "node.externalIP"},
		{"agent token", Leader, func(d *Document) { d.RKE2.AgentToken = "short" }, "rke2.agentToken"},
		{"missing server token", Leader, func(d *Document) { d.RKE2.ServerToken = "" }, "rke2.serverToken"},
		{"leader key", Leader, func(d *Document) { d.Leader.OperatorPublicKey = "not a key" }, "leader.operatorPublicKey"},
		{"follower key", Leader, func(d *Document) { d.FollowerOperatorPublicKeys = []string{"not a key"} }, "followerOperatorPublicKeys"},
		{"duplicate follower keys", Leader, func(d *Document) {
			d.FollowerOperatorPublicKeys = append(d.FollowerOperatorPublicKeys, d.FollowerOperatorPublicKeys[0])
		}, "nonduplicated"},
		{"too many follower keys", Leader, func(d *Document) {
			d.FollowerOperatorPublicKeys = make([]string, maxFollowerKeys+1)
			for i := range d.FollowerOperatorPublicKeys {
				d.FollowerOperatorPublicKeys[i] = otherPub
			}
		}, "too many"},
		{"follower without keys", Follower, func(d *Document) { d.FollowerOperatorPublicKeys = nil }, "requires followerOperatorPublicKeys"},
		{"tls san length", Leader, func(d *Document) { d.TLSSAN = strings.Repeat("a", 254) }, "DNS name length"},
		{"tls san label", Leader, func(d *Document) { d.TLSSAN = "C8S.Local" }, "lowercase DNS hostname"},
		{"workloads json", Leader, func(d *Document) { d.Workloads = "{" }, "valid JSON"},
		{"workloads schema", Leader, func(d *Document) { d.Workloads = `{"schema":"other/v1","workloads":{}}` }, "workloads:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, _ := testDocument(t, "snp", tc.role)
			tc.change(&doc)
			data, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseRejectsEmptyAndMalformedYAML(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":            nil,
		"oversized":        bytes.Repeat([]byte("a"), MaxDocumentSize+1),
		"invalid":          []byte("role: [leader"),
		"merge key":        []byte("base: &b {}\nrole: leader\n<<: *b\n"),
		"non-scalar key":   []byte("? [a, b]\n: leader\n"),
		"deep nesting":     []byte(strings.Repeat("[", 40) + strings.Repeat("]", 40)),
		"rtmr index alias": []byte("image:\n  rtmrs:\n    0x1: a\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatalf("accepted %s input", name)
			}
		})
	}
}

func TestYAMLPathPresent(t *testing.T) {
	var tree yaml.Node
	if err := yaml.Unmarshal([]byte("rke2:\n  agentToken: a\nrole: leader\n"), &tree); err != nil {
		t.Fatal(err)
	}
	if !yamlPathPresent(&tree, "rke2", "agentToken") {
		t.Error("present nested key not found")
	}
	if yamlPathPresent(&tree, "rke2", "serverToken") {
		t.Error("absent nested key reported present")
	}
	if yamlPathPresent(&tree, "role", "nested") {
		t.Error("descended into a scalar")
	}
}

func TestParseLaunchKeyShape(t *testing.T) {
	_, valid := testKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongCurve := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	badDER := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")}))
	withHeaders := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"a": "b"}, Bytes: der}))
	for name, raw := range map[string]string{
		"too large":     strings.Repeat("x", 8193),
		"not pem":       "not a key",
		"wrong type":    strings.ReplaceAll(valid, "PUBLIC KEY", "CERTIFICATE"),
		"headers":       withHeaders,
		"trailing data": valid + "trailing",
		"bad der":       badDER,
		"wrong curve":   wrongCurve,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLaunchKey(raw); err == nil {
				t.Fatalf("accepted %s key", name)
			}
		})
	}
	if _, err := parseLaunchKey(valid); err != nil {
		t.Fatal(err)
	}
}

func TestReadBoundedRejectsIrregularFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := readBounded(dir, 16); err == nil {
		t.Error("read a directory")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(empty, 16); err == nil {
		t.Error("read an empty file")
	}
	if _, err := readBounded(filepath.Join(dir, "missing"), 16); err == nil {
		t.Error("read a missing file")
	}
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readBounded(small, 16); err != nil || string(data) != "ok" {
		t.Errorf("got %q, %v", data, err)
	}
}

func TestVerifyRejectsBadConfigBeforeReadingFiles(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Leader)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)

	bad := cfg
	bad.Platform = "sgx"
	if _, err := Verify(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("platform: %v", err)
	}
	bad = cfg
	bad.SignaturePath = ""
	if _, err := Verify(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "--signature") {
		t.Fatalf("missing signature path: %v", err)
	}
	bad = cfg
	bad.SignaturePath = filepath.Join(t.TempDir(), "missing.sig")
	if _, err := Verify(context.Background(), bad); err == nil {
		t.Fatal("missing signature file accepted")
	}

	old := loadMeasuredOperatorKeyAndOwnMeasurement
	t.Cleanup(func() { loadMeasuredOperatorKeyAndOwnMeasurement = old })
	loadMeasuredOperatorKeyAndOwnMeasurement = func(context.Context, string, string) ([]byte, error, []byte, map[int][]byte, error) {
		return nil, nil, nil, nil, errors.New("attestation-api unreachable")
	}
	if _, err := Verify(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "verify this boot's identity") {
		t.Fatalf("self-report failure: %v", err)
	}
	loadMeasuredOperatorKeyAndOwnMeasurement = func(context.Context, string, string) ([]byte, error, []byte, map[int][]byte, error) {
		return []byte("not a key"), nil, mustDecodeHex(doc.Image.Measurement), nil, nil
	}
	if _, err := Verify(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "measured launch key") {
		t.Fatalf("malformed measured key: %v", err)
	}
}

func TestLoadStagedTrustsOnlyCompleteArtifacts(t *testing.T) {
	doc, _, _ := testDocument(t, "snp", Leader)
	write := func(t *testing.T, data []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	encode := func(t *testing.T, d Document) []byte {
		t.Helper()
		data, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if _, err := LoadStaged(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("loaded a missing artifact")
	}
	if _, err := LoadStaged(write(t, []byte(`{"schemaVersion":"c8s-launch/v1","unknown":1}`))); err == nil || !strings.Contains(err.Error(), "decode staged") {
		t.Errorf("unknown field: %v", err)
	}
	if _, err := LoadStaged(write(t, append(encode(t, doc), []byte("{}")...))); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Errorf("trailing data: %v", err)
	}
	invalid := doc
	invalid.Role = "observer"
	if _, err := LoadStaged(write(t, encode(t, invalid))); err == nil || !strings.Contains(err.Error(), "role") {
		t.Errorf("invalid document: %v", err)
	}
	unresolved := doc
	unresolved.Leader.Address = ""
	if _, err := LoadStaged(write(t, encode(t, unresolved))); err == nil || !strings.Contains(err.Error(), "resolved leader address") {
		t.Errorf("unresolved leader: %v", err)
	}
	staged, err := LoadStaged(write(t, encode(t, doc)))
	if err != nil || staged.ClusterID != doc.ClusterID {
		t.Fatalf("got %v, %v", staged, err)
	}
}

func TestPrimaryIPv4FollowsTheHostRoute(t *testing.T) {
	old := chooseHostInterface
	t.Cleanup(func() { chooseHostInterface = old })
	chooseHostInterface = func() (net.IP, error) { return nil, errors.New("no default route") }
	if _, err := primaryIPv4(); err == nil {
		t.Fatal("route failure ignored")
	}
	chooseHostInterface = func() (net.IP, error) { return net.ParseIP("192.0.2.9"), nil }
	if ip, err := primaryIPv4(); err != nil || ip != "192.0.2.9" {
		t.Fatalf("got %q, %v", ip, err)
	}

	// Stage consults it only when a leader omits both addresses and no
	// resolver is configured.
	doc, key, pub := testDocument(t, "snp", Leader)
	doc.Leader.Address = ""
	doc.Node.IP = ""
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	staged, err := LoadStaged(cfg.path(DefaultStagedPath))
	if err != nil || staged.Leader.Address != "192.0.2.9" {
		t.Fatalf("got %v, %v", staged, err)
	}
}

func TestConfigPathWithoutRootIsAbsolute(t *testing.T) {
	if got := (Config{}).path(serverMarker); got != serverMarker {
		t.Fatalf("got %q", got)
	}
	if got := (Config{RootDir: "/tmp/root"}).path(serverMarker); got != filepath.Join("/tmp/root", serverMarker) {
		t.Fatalf("got %q", got)
	}
}

func TestStageCommandFailsClosed(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Leader)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)

	cmd := NewCmd()
	cmd.SetArgs([]string{"stage", "--platform", "snp", "--config", cfg.DocumentPath})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("missing required flag: %v", err)
	}

	cmd = NewCmd()
	cmd.SetArgs([]string{"stage", "--platform", "sgx", "--config", cfg.DocumentPath, "--signature", cfg.SignaturePath})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("unsupported platform: %v", err)
	}
}
