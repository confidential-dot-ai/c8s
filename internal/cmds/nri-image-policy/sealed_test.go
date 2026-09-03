package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/tdxrtmr"
	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	testPodUID    = "11111111-2222-3333-4444-555555555555"
	testSandboxID = "sandbox0123"
)

func str(s string) *string { return &s }

// sealedDocument is a complete sealed document with one unprivileged web
// entry (pushDigestA) and one privileged node-TCB entry (pushDigestB), in the
// canonical bytes a node measures.
func sealedDocument(t *testing.T) (*allowlist.Allowlist, []byte) {
	t.Helper()
	web := allowlist.Container{
		Digest:  mustDigest(t, pushDigestA),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/app"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"serve"}},
		Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact,
			Destinations: []string{"/etc/hosts", "/data", "/var/run/secrets/kubernetes.io/serviceaccount"},
			Rules: map[string]allowlist.MountRule{
				"/etc/hosts": {Source: allowlist.SourcePlatform},
				"/data":      {Source: allowlist.SourceEmptyDir},
				"/var/run/secrets/kubernetes.io/serviceaccount": {Source: allowlist.SourceServiceAccountToken, Review: "the app reads nothing there"},
			}},
		Env: allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Names: []string{"PATH", "POD_NAME", "NODE"},
			Values: map[string]allowlist.EnvValue{
				"PATH":     {Value: str("/bin")},
				"POD_NAME": {From: allowlist.FromPodName},
				"NODE":     {From: allowlist.FromNodeName},
			}},
	}
	agent := allowlist.Container{
		Digest:  mustDigest(t, pushDigestB),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/agent"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
		Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Destinations: []string{"/host/modules"},
			Rules: map[string]allowlist.MountRule{"/host/modules": {Source: allowlist.SourceHostPath, Path: "/lib/modules/"}}},
		Env: allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Names: []string{"PATH"},
			Values: map[string]allowlist.EnvValue{"PATH": {Value: str("/bin")}}},
		Privileges: &allowlist.Privileges{Privileged: true, HostNamespaces: []string{allowlist.HostNamespaceNet},
			HostPaths: []string{"/lib/modules/"}, Review: "node TCB: the CNI agent"},
	}
	raw, err := json.Marshal(&allowlist.Allowlist{Schema: allowlist.Schema, Digests: map[string]string{}, Workloads: map[string]allowlist.Workload{
		"web":   {Containers: []allowlist.Container{web}},
		"agent": {Containers: []allowlist.Container{agent}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := allowlist.ParseJSON(raw)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	canonical, err := doc.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := allowlist.LintSealed(canonical); err != nil {
		t.Fatalf("fixture is not sealed: %v", err)
	}
	return doc, canonical
}

// writeRegister points tdxrtmr at a temp sysfs root holding RTMR[3] = value.
func writeRegister(t *testing.T, value [runtimemeasure.Size]byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "rtmr3:sha384"), value[:], 0o600); err != nil {
		t.Fatal(err)
	}
	prev := tdxrtmr.SysfsRoot
	tdxrtmr.SysfsRoot = root
	t.Cleanup(func() { tdxrtmr.SysfsRoot = prev })
}

// writePolicyDir lays out what c8s-policy-measure writes for a static boot
// and sets the register to match; mutate edits the files before the load.
func writePolicyDir(t *testing.T, doc []byte) (dir string, bundle policybundle.Bundle) {
	t.Helper()
	dir = t.TempDir()
	bundle, err := policybundle.FromMembers(map[string][]byte{policybundle.MemberStaticAllowlist: doc})
	if err != nil {
		t.Fatal(err)
	}
	digest := bundle.IndexDigest()
	for name, content := range map[string]string{
		policybundle.ModeFile:              policybundle.StaticMode + "\n",
		policybundle.DigestFile:            hex.EncodeToString(digest[:]) + "\n",
		policybundle.MemberStaticAllowlist: string(doc),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	writeRegister(t, bundle.RTMR3())
	return dir, bundle
}

// overwrite replaces a read-only policy file the way a tampering host would.
func overwrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// recordPoweroff swaps the package poweroff for a counter.
func recordPoweroff(t *testing.T) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	prev := poweroff
	poweroff = func() error { calls.Add(1); return nil }
	t.Cleanup(func() { poweroff = prev })
	return &calls
}

// loadSealed takes the bundle policybundle.ReadDir already re-indexed, so
// these cases mutate the member bytes and the register, not the directory.
func TestLoadSealed(t *testing.T) {
	_, doc := sealedDocument(t)
	for _, tc := range []struct {
		name    string
		member  []byte
		mutate  func(t *testing.T)
		wantErr string
	}{
		{"valid", doc, nil, ""},
		{"member not canonical", append(append([]byte{}, doc...), '\n'), nil, "not its canonical form"},
		{"member not sealed", []byte(`{"schema":"c8s.allowlist/v1","digests":{"` + pushDigestA + `":"a"},"workloads":{}}`), nil, "digests must be empty"},
		{"member not json", []byte("{"), nil, "decode allowlist"},
		{"register mismatch", doc, func(t *testing.T) {
			writeRegister(t, runtimemeasure.ForDynamic(runtimemeasure.Zero))
		}, "RTMR[3] is"},
		{"register unreadable", doc, func(t *testing.T) {
			tdxrtmr.SysfsRoot = t.TempDir()
		}, "is this a TDX guest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, err := policybundle.FromMembers(map[string][]byte{policybundle.MemberStaticAllowlist: tc.member})
			if err != nil {
				t.Fatal(err)
			}
			writeRegister(t, bundle.RTMR3())
			if tc.mutate != nil {
				tc.mutate(t)
			}
			sealed, err := loadSealed(bundle)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("loadSealed(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadSealed(%s) = %v, want nil", tc.name, err)
			}
			want := bundle.RTMR3()
			if sealed.rtmr3 != want || len(sealed.doc.Workloads) != 2 {
				t.Fatalf("loadSealed(%s) = rtmr3 %x, %d workloads; want %x, 2", tc.name, sealed.rtmr3[:4], len(sealed.doc.Workloads), want[:4])
			}
		})
	}
}

func TestCheckDynamicRegister(t *testing.T) {
	pub := []byte("-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n")
	for _, tc := range []struct {
		name     string
		pubkey   *[]byte
		register [runtimemeasure.Size]byte
		wantErr  string
	}{
		{"no key, chained zero", nil, runtimemeasure.ForDynamic(runtimemeasure.Zero), ""},
		{"key, chained key", &pub, runtimemeasure.ForDynamic(runtimemeasure.ForOperatorKey(pub)), ""},
		{"key, bare seed", &pub, runtimemeasure.ForOperatorKey(pub), "ForDynamic(seed)"},
		{"no key, static register", nil, runtimemeasure.ForStaticAllowlist([]byte("{}")), "ForDynamic(seed)"},
		{"empty key file reads as no key", new([]byte), runtimemeasure.ForDynamic(runtimemeasure.Zero), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "operator-pubkey")
			if tc.pubkey != nil {
				if err := os.WriteFile(path, *tc.pubkey, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			writeRegister(t, tc.register)
			err := checkDynamicRegister(path)
			if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("checkDynamicRegister(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
			}
		})
	}
	t.Run("unreadable key file", func(t *testing.T) {
		writeRegister(t, runtimemeasure.ForDynamic(runtimemeasure.Zero))
		if err := checkDynamicRegister(t.TempDir()); err == nil || !strings.Contains(err.Error(), "read operator pubkey") {
			t.Fatalf("checkDynamicRegister(dir) = %v, want a read error", err)
		}
	})
}

func TestOwnTuplePins_SocketAbsentIsAnError(t *testing.T) {
	_, err := ownTuplePins(t.Context(), "unix://"+filepath.Join(t.TempDir(), "absent.sock"), runtimemeasure.Zero)
	if err == nil || !strings.Contains(err.Error(), "attest self") {
		t.Fatalf("ownTuplePins(absent socket) = %v, want an attest error", err)
	}
}

func hexReg(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), runtimemeasure.Size) }

// TestOwnTuplePins covers the plugin's own rule over the shared tuple
// derivation: the verifier's RTMR[3] must be the sealed register. The
// verdict checks themselves are pkg/attestationclient's.
func TestOwnTuplePins(t *testing.T) {
	var sealed [runtimemeasure.Size]byte
	copy(sealed[:], bytes.Repeat([]byte{0x33}, runtimemeasure.Size))
	good := testattest.TDXVerdict(hexReg(0x11), map[int]string{0: hexReg(0x00), 1: hexReg(0x21), 2: hexReg(0x22), 3: hex.EncodeToString(sealed[:])})
	foreign := testattest.TDXVerdict(hexReg(0x11), map[int]string{0: hexReg(0x00), 1: hexReg(0x21), 2: hexReg(0x22), 3: hexReg(0x44)})
	unsigned := good
	unsigned.SignatureValid = false
	for _, tc := range []struct {
		name    string
		verdict testattest.Verdict
		wantErr string
	}{
		{"own tuple", good, ""},
		{"foreign RTMR[3]", foreign, "the verifier reports RTMR[3]"},
		{"signature invalid", unsigned, "verify self-report"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub, url := testattest.NewUnix(t)
			stub.SetPlatform(types.PlatformTdx)
			stub.SetVerdict(tc.verdict)
			pins, err := ownTuplePins(t.Context(), url, sealed)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ownTuplePins(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ownTuplePins(%s) = %v, want nil", tc.name, err)
			}
			if len(pins.Entries) != 1 || len(pins.Measurements) != 0 || len(pins.RTMRs) != 0 {
				t.Fatalf("ownTuplePins(%s) = %+v, want exactly one entry and no loose pins", tc.name, pins)
			}
			entry := pins.Entries[0]
			if hex.EncodeToString(entry.Digest) != hexReg(0x11) || len(entry.RTMRs) != 3 || !bytes.Equal(entry.RTMRs[3], sealed[:]) {
				t.Fatalf("ownTuplePins(%s) entry = digest %x, %d RTMRs, RTMR[3] %x; want %s, 3, the sealed register", tc.name, entry.Digest, len(entry.RTMRs), entry.RTMRs[3], hexReg(0x11))
			}
		})
	}
}

func TestNodeIP(t *testing.T) {
	withFile := t.TempDir()
	if err := os.WriteFile(filepath.Join(withFile, NodeIPFile), []byte(" 10.0.0.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, socketDir, want string
		wantOK                bool
	}{
		{"no socket dir", "", "", false},
		{"file absent", t.TempDir(), "", false},
		{"file present", withFile, "10.0.0.7", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config{WorkloadClaims: workloadClaimsConfig{SocketDir: tc.socketDir}}
			if got, ok := nodeIP(cfg); got != tc.want || ok != tc.wantOK {
				t.Fatalf("nodeIP(%s) = %q, %v, want %q, %v", tc.name, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestKubeletNodeName(t *testing.T) {
	for in, want := range map[string]string{
		"Node-A":     "node-a",
		" node-b \n": "node-b",
		"node-c":     "node-c",
	} {
		if got := kubeletNodeName(in); got != want {
			t.Errorf("kubeletNodeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProtectFromOOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oom_score_adj")
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := oomScoreAdjPath
	oomScoreAdjPath = path
	t.Cleanup(func() { oomScoreAdjPath = prev })
	protectFromOOM(discardLogger())
	if b, _ := os.ReadFile(path); strings.TrimSpace(string(b)) != "-1000" {
		t.Fatalf("oom_score_adj = %q, want -1000", b)
	}
	// An unwritable path only logs.
	oomScoreAdjPath = filepath.Join(t.TempDir(), "missing", "oom_score_adj")
	protectFromOOM(discardLogger())
}

// --- Run: policy mode at startup ---

func sealedConfigYAML(t *testing.T, policyDir, platform string) string {
	t.Helper()
	dir := t.TempDir()
	return fmt.Sprintf(`
platform: %s
plugin:
  health_addr: unix://%s/health.sock
containerd:
  socket: %s/ctr.sock
allowlist:
  policy_dir: %s
  always_allow:
    "%s": image-a
  pull:
    url: https://cds.example:8443
    attestation_api_url: unix://%s/attestation-api.sock
policy:
  mode: fail-closed
  enforce_existing: false
logging:
  level: error
`, platform, dir, dir, policyDir, pushDigestC, dir)
}

// A sealed store holds the measured bundle alone: the config's always_allow
// floor and pull URL, which the baked image-policy.yaml carries for dynamic
// boots, must not reach the index or start the pull loop.
func TestStartupPolicy(t *testing.T) {
	doc, _ := sealedDocument(t)
	cfg, err := loadConfig(writeConfigYAML(t, sealedConfigYAML(t, t.TempDir(), "tdx")))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PullEnabled() || len(cfg.Allowlist.AlwaysAllow) != 1 {
		t.Fatalf("fixture config: pull %v, always_allow %d; want a pull URL and one floor digest", cfg.PullEnabled(), len(cfg.Allowlist.AlwaysAllow))
	}
	for _, tc := range []struct {
		name          string
		sealed        *sealedPolicy
		wantFloor     bool
		wantBootstrap bool
		wantPull      bool
	}{
		{"sealed", &sealedPolicy{doc: doc}, false, false, false},
		{"dynamic", nil, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, bootstrap, pull := startupPolicy(cfg, tc.sealed)
			if got := store.current().index.AdmitsDigest(pushDigestC); got != tc.wantFloor {
				t.Errorf("startupPolicy(%s) index admits the always_allow digest = %v, want %v", tc.name, got, tc.wantFloor)
			}
			if (bootstrap != nil) != tc.wantBootstrap || pull != tc.wantPull {
				t.Errorf("startupPolicy(%s) = bootstrap %v, pull %v; want bootstrap %v, pull %v", tc.name, bootstrap != nil, pull, tc.wantBootstrap, tc.wantPull)
			}
			if tc.sealed != nil && !store.current().index.AdmitsDigest(pushDigestA) {
				t.Errorf("startupPolicy(%s) index lacks the bundle's own digest", tc.name)
			}
		})
	}
}

func TestRun_PolicyMode(t *testing.T) {
	_, doc := sealedDocument(t)
	for _, tc := range []struct {
		name         string
		platform     string
		layout       func(t *testing.T) string
		wantErr      string
		wantPoweroff int32
	}{
		{"mode file missing powers off", "snp", func(t *testing.T) string { return t.TempDir() }, "policy mode", 1},
		{"foreign mode powers off", "snp", func(t *testing.T) string {
			dir := t.TempDir()
			overwrite(t, filepath.Join(dir, policybundle.ModeFile), []byte("audit\n"))
			return dir
		}, `holds "audit"`, 1},
		{"dynamic on tdx with a foreign register powers off", "tdx", func(t *testing.T) string {
			dir := t.TempDir()
			overwrite(t, filepath.Join(dir, policybundle.ModeFile), []byte("dynamic\n"))
			writeRegister(t, runtimemeasure.ForStaticAllowlist([]byte("{}")))
			prev := operatorPubkeyPath
			operatorPubkeyPath = filepath.Join(dir, "no-such-key")
			t.Cleanup(func() { operatorPubkeyPath = prev })
			return dir
		}, "dynamic boot: RTMR[3]", 1},
		{"static with a broken bundle powers off", "tdx", func(t *testing.T) string {
			dir, _ := writePolicyDir(t, doc)
			os.Remove(filepath.Join(dir, policybundle.DigestFile))
			return dir
		}, "policy digest", 1},
		{"static with no verifier socket powers off", "tdx", func(t *testing.T) string {
			dir, _ := writePolicyDir(t, doc)
			return dir
		}, "pin CDS to the node's own tuple", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := recordPoweroff(t)
			prevOOM := oomScoreAdjPath
			oomScoreAdjPath = filepath.Join(t.TempDir(), "oom_score_adj")
			t.Cleanup(func() { oomScoreAdjPath = prevOOM })
			policyDir := tc.layout(t)
			err := runWithDeadline(t, 20*time.Second, []string{"-config", writeConfigYAML(t, sealedConfigYAML(t, policyDir, tc.platform))})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Run(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
			}
			if got := calls.Load(); got != tc.wantPoweroff {
				t.Fatalf("Run(%s) powered off %d times, want %d", tc.name, got, tc.wantPoweroff)
			}
		})
	}
}

// A dynamic boot on SEV-SNP has no register to check: Run must not read
// sysfs (a foreign RTMR[3] there is ignored) and must get as far as NRI
// registration. With the config's pull URL in force on a dynamic boot, the
// plugin dies registering (no NRI socket here) during the initial pull,
// which Run reports as errPluginDied.
func TestRun_DynamicOnSNPSkipsRegister(t *testing.T) {
	calls := recordPoweroff(t)
	dir := t.TempDir()
	overwrite(t, filepath.Join(dir, policybundle.ModeFile), []byte("dynamic\n"))
	writeRegister(t, runtimemeasure.ForStaticAllowlist([]byte("{}")))
	err := runWithDeadline(t, 20*time.Second, []string{"-config", writeConfigYAML(t, sealedConfigYAML(t, dir, "snp"))})
	if !errors.Is(err, errPluginDied) {
		t.Fatalf("Run(dynamic on snp) = %v, want %v from NRI registration", err, errPluginDied)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("Run(dynamic on snp) powered off %d times, want 0", got)
	}
}

// The own-quote round trip may outlast containerd's registration window, so
// Run must have the stub registering before it attests: the registration
// request is on the wire by the time the pin function runs.
func TestRun_SealedRegistersBeforeSelfAttest(t *testing.T) {
	_, doc := sealedDocument(t)
	policyDir, _ := writePolicyDir(t, doc)
	calls := recordPoweroff(t)
	prevOOM := oomScoreAdjPath
	oomScoreAdjPath = filepath.Join(t.TempDir(), "oom_score_adj")
	t.Cleanup(func() { oomScoreAdjPath = prevOOM })
	peer := holdNRISocket(t)

	registered := make(chan error, 1)
	prev := pinOwnTuple
	pinOwnTuple = func(context.Context, string, [runtimemeasure.Size]byte) (ratls.Pins, error) {
		_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := peer.Read(make([]byte, 1))
		registered <- err
		return ratls.Pins{}, errors.New("verifier down")
	}
	t.Cleanup(func() { pinOwnTuple = prev })

	err := runWithDeadline(t, 20*time.Second, []string{"-config", writeConfigYAML(t, sealedConfigYAML(t, policyDir, "tdx"))})
	if err == nil || !strings.Contains(err.Error(), "verifier down") {
		t.Fatalf("Run(sealed, verifier down) = %v, want the pin error", err)
	}
	select {
	case err := <-registered:
		if err != nil {
			t.Fatalf("no registration request reached the runtime before the self-attestation: %v", err)
		}
	default:
		t.Fatal("Run returned without attesting")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("Run(sealed, verifier down) powered off %d times, want 1", got)
	}
}

func TestSealedFatal_ReportsPoweroffFailure(t *testing.T) {
	prev := poweroff
	poweroff = func() error { return errors.New("no systemd") }
	t.Cleanup(func() { poweroff = prev })
	cause := errors.New("bundle gone")
	if err := sealedFatal(discardLogger(), cause); !errors.Is(err, cause) {
		t.Fatalf("sealedFatal(cause) = %v, want the cause back", err)
	}
}
