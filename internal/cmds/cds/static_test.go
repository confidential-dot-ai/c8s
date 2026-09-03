package cds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/testattest"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// staticMember is the bundle member the static tests seal: one sealed entry
// in canonical form, the only shape a node measures, so the seed has
// something to add and the store serves it back byte for byte.
var staticMember = canonicalMember(`{"schema":"c8s.allowlist/v1","digests":{},"workloads":{"web":{"containers":[{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","destinations":["/etc/hosts"],"rules":{"/etc/hosts":{"source":"platform"}}},"env":{"policy":"exact","names":["PATH"],"values":{"PATH":{"value":"/bin"}}}}]}}}`)

func canonicalMember(doc string) string {
	al, err := pkgallowlist.ParseJSON([]byte(doc))
	if err != nil {
		panic(err)
	}
	out, err := al.Canonical()
	if err != nil {
		panic(err)
	}
	return string(out)
}

// staticFixture is the bundle, image tuple and static entry the tests share.
type staticFixture struct {
	bundle policybundle.Bundle
	pins   runtimemeasure.ImagePins
	entry  measurements.Entry
}

func newStaticFixture(t *testing.T) staticFixture {
	t.Helper()
	bundle, err := policybundle.FromMembers(map[string][]byte{policybundle.MemberStaticAllowlist: []byte(staticMember)})
	if err != nil {
		t.Fatal(err)
	}
	var pins runtimemeasure.ImagePins
	copy(pins.MRTD[:], mustDecode(t, testMRTD))
	copy(pins.RTMR1[:], mustDecode(t, testRTMR1))
	copy(pins.RTMR2[:], mustDecode(t, testRTMR2))
	set := measurements.StaticReferenceValues(pins, bundle.RTMR3())
	return staticFixture{bundle: bundle, pins: pins, entry: set.Entries[0]}
}

// writeMeasurementsConfig renders the fixture's static entry the way install
// hands it to the chart.
func (f staticFixture) writeMeasurementsConfig(t *testing.T) string {
	t.Helper()
	doc, err := measurements.Format(measurements.StaticReferenceValues(f.pins, f.bundle.RTMR3()))
	if err != nil {
		t.Fatal(err)
	}
	return writeConfig(t, string(doc))
}

// writePolicyDir lays out what c8s-policy-measure leaves behind: the member,
// the index digest and the mode.
func (f staticFixture) writePolicyDir(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	digest := f.bundle.IndexDigest()
	for name, data := range map[string][]byte{
		policybundle.MemberStaticAllowlist: f.bundle.Members[policybundle.MemberStaticAllowlist],
		policybundle.DigestFile:            []byte(hex.EncodeToString(digest[:]) + "\n"),
		policybundle.ModeFile:              []byte(mode + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// verdict is a TDX verdict carrying the fixture's tuple with rtmr3 as given.
func (f staticFixture) verdict(t *testing.T, rtmr3 string) testattest.Verdict {
	t.Helper()
	v := tdxVerdict(t, testMRTD, testRTMR1, testRTMR2)
	v.Claims.PlatformData["rtmr_3"] = rtmr3
	return v
}

func (f staticFixture) rtmr3Hex() string {
	r := f.bundle.RTMR3()
	return hex.EncodeToString(r[:])
}

// unixAttestStub serves the fake attestation-api on a unix socket, the only
// transport static mode accepts. The socket lives under a short temp path:
// a unix path is capped at 108 bytes and t.TempDir() names can exceed it.
func unixAttestStub(t *testing.T) (*testattest.Stub, string) {
	t.Helper()
	stub := testattest.New(t)
	stub.SetPlatform(types.PlatformTdx)
	dir, err := os.MkdirTemp("", "cds-static")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "attestation-api.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { _ = http.Serve(l, stub.Config.Handler) }()
	return stub, "unix://" + socket
}

func TestValidateStaticConfig(t *testing.T) {
	f := newStaticFixture(t)
	set := measurements.StaticReferenceValues(f.pins, f.bundle.RTMR3())
	valid := func() config {
		return config{
			ratlsPlatform:      "tdx",
			measurementsConfig: "cds.json",
			allowlistSeed:      "/run/confai/policy/static-allowlist.json",
			policyDir:          "/run/confai/policy",
			attestationApiURL:  "unix:///run/confai/attestation-api.sock",
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(cfg *config)
		set    measurements.ReferenceValues
		want   string
	}{
		{"valid", func(*config) {}, set, ""},
		{"snp platform", func(c *config) { c.ratlsPlatform = "snp" }, set, "--ratls-platform=tdx"},
		{"no measurements config", func(c *config) { c.measurementsConfig = "" }, set, "requires --measurements-config"},
		{"operator keys", func(c *config) { c.operatorKeys = "keys.pem" }, set, "--operator-keys"},
		{"persistent store", func(c *config) { c.allowlistPersistent = true }, set, "--allowlist-persistent"},
		{"seed elsewhere", func(c *config) { c.allowlistSeed = "/etc/cds/allowlist-seed.json" }, set, "--allowlist-seed=/run/confai/policy/static-allowlist.json"},
		{"tcp verifier", func(c *config) { c.attestationApiURL = "http://127.0.0.1:8400" }, set, "unix://"},
		{"entry without rtmr3", func(*config) {}, measurements.ReferenceValues{TEE: measurements.TEETDX, Entries: []measurements.Entry{{Digest: set.Entries[0].Digest, RTMRs: map[int][]byte{1: set.Entries[0].RTMRs[1], 2: set.Entries[0].RTMRs[2]}}}}, "must pin RTMR[3]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(&cfg)
			entry, err := validateStaticConfig(cfg, tc.set)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("validateStaticConfig(%s) = %v, want nil", tc.name, err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("validateStaticConfig(%s) = %v, want error containing %q", tc.name, err, tc.want)
			case tc.want == "" && entry.Name != measurements.StaticEntryName:
				t.Fatalf("validateStaticConfig(%s) entry = %q, want %q", tc.name, entry.Name, measurements.StaticEntryName)
			}
		})
	}
}

func TestVerifyStaticNode(t *testing.T) {
	f := newStaticFixture(t)
	for _, tc := range []struct {
		name  string
		mode  string
		rtmr3 string
		tweak func(t *testing.T, dir string, cfg *config)
		want  string
	}{
		{"sealed node", policybundle.StaticMode, f.rtmr3Hex(), nil, ""},
		{"dynamic boot", policybundle.DynamicMode, f.rtmr3Hex(), nil, `mode "dynamic", want static`},
		{"missing policy dir", policybundle.StaticMode, f.rtmr3Hex(), func(t *testing.T, dir string, cfg *config) {
			cfg.policyDir = filepath.Join(dir, "absent")
		}, "policy mode"},
		{"member rewritten after measurement", policybundle.StaticMode, f.rtmr3Hex(), func(t *testing.T, dir string, _ *config) {
			member := filepath.Join(dir, policybundle.MemberStaticAllowlist)
			if err := os.Remove(member); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(member, []byte(`{"schema":"c8s.allowlist/v1","digests":{},"workloads":{}}`), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "members index to"},
		// Node root can rewrite the member AND the digest file consistently;
		// only the register says which bundle was measured.
		{"member and digest rewritten together", policybundle.StaticMode, f.rtmr3Hex(), func(t *testing.T, dir string, _ *config) {
			other, err := policybundle.FromMembers(map[string][]byte{policybundle.MemberStaticAllowlist: []byte(`{"schema":"c8s.allowlist/v1","digests":{},"workloads":{}}`)})
			if err != nil {
				t.Fatal(err)
			}
			digest := other.IndexDigest()
			for name, data := range map[string][]byte{
				policybundle.MemberStaticAllowlist: other.Members[policybundle.MemberStaticAllowlist],
				policybundle.DigestFile:            []byte(hex.EncodeToString(digest[:]) + "\n"),
			} {
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o444); err != nil {
					t.Fatal(err)
				}
			}
		}, "derive RTMR[3]"},
		{"node sealed to another bundle", policybundle.StaticMode, strings.Repeat("ee", 48), nil, "RTMR[3] does not match"},
		{"unsealed node of the same image", policybundle.StaticMode, strings.Repeat("00", 48), nil, "RTMR[3] does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub, url := unixAttestStub(t)
			stub.SetVerdict(f.verdict(t, tc.rtmr3))
			dir := f.writePolicyDir(t, tc.mode)
			cfg := config{policyDir: dir, attestationApiURL: url}
			if tc.tweak != nil {
				tc.tweak(t, dir, &cfg)
			}
			bundle, err := verifyStaticNode(context.Background(), cfg, f.entry)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("verifyStaticNode(%s) = %v, want error containing %q", tc.name, err, tc.want)
				}
				if tc.name == "member and digest rewritten together" && len(stub.AttestRequests()) != 0 {
					t.Error("a bundle the register does not vouch for was self-attested; the register tie comes first")
				}
				return
			}
			if err != nil {
				t.Fatalf("verifyStaticNode(%s) = %v, want nil", tc.name, err)
			}
			if got := string(bundle.Members[policybundle.MemberStaticAllowlist]); got != staticMember {
				t.Errorf("verifyStaticNode(%s) member = %q, want the measured bytes", tc.name, got)
			}
			// The verdict that admitted this pod is the one every requester
			// gets: the nonce this pod sent must be what the verifier bound.
			reqs, verifies := stub.AttestRequests(), stub.VerifyRequests()
			if len(reqs) != 1 || len(verifies) != 1 {
				t.Fatalf("attest/verify requests = %d/%d, want 1/1", len(reqs), len(verifies))
			}
			if verifies[0].Params == nil || verifies[0].Params.ExpectedReportData == nil {
				t.Fatal("self-report verified without an expected report_data: the verdict would be replayable")
			}
		})
	}
}

// Evidence from a non-TDX platform is refused before /verify: the static
// tuple pins RTMRs, which only TDX reports. (The unix:// transport rule is a
// flag check, asserted by TestValidateStaticConfig.)
func TestVerifySelfEvidenceRejectsNonTDXPlatform(t *testing.T) {
	f := newStaticFixture(t)
	stub, url := unixAttestStub(t)
	stub.SetPlatform(types.PlatformSnp)
	stub.SetVerdict(f.verdict(t, f.rtmr3Hex()))
	err := verifySelfEvidence(context.Background(), url, f.entry)
	if err == nil || !strings.Contains(err.Error(), "want TDX") {
		t.Fatalf("verifySelfEvidence(snp) = %v, want a platform refusal", err)
	}
}

// The stamp every leaf carries is the digest of the document the store
// serves, and `c8s verify --static-allowlist` holds it to SHA-256 of the
// measured member; the two agree only when the member is already in the
// store's form. A member without "digests":{} passes the sealed lint yet
// re-serializes differently, so CDS must refuse it rather than stamp a digest
// no bundle holder can match.
func TestCheckStaticStamp(t *testing.T) {
	for _, tc := range []struct {
		name   string
		member string
		want   string
	}{
		{"store form", staticMember, ""},
		{"digests null", strings.Replace(staticMember, `"digests":{}`, `"digests":null`, 1), "not in the form the store serves"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := allowlist.OpenInMemory()
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := seedStoreFrom(&store, []byte(tc.member), "static-allowlist.json"); err != nil {
				t.Fatal(err)
			}
			err = checkStaticStamp(&store, []byte(tc.member))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("checkStaticStamp(%s) = %v, want nil", tc.name, err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("checkStaticStamp(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
			if tc.want != "" {
				return
			}
			snapshot, err := loadPolicySnapshot(&store)
			if err != nil {
				t.Fatal(err)
			}
			if want := sha256.Sum256([]byte(tc.member)); !bytes.Equal(snapshot.Digest, want[:]) {
				t.Errorf("snapshot digest = %x, want SHA-256 of the member %x", snapshot.Digest, want)
			}
		})
	}
}

// run() wires the gate before the seed: a dynamic node never seeds, and a
// sealed node seeds the measured member and carries on. The sealed case is
// stopped right after the seed by an invalid inventory CIDR, the first
// failure point past it, so the test needs no RA-TLS listener.
func TestRun_StaticAllowlist(t *testing.T) {
	f := newStaticFixture(t)
	staticConfig := func(t *testing.T, url, policyDir string) config {
		t.Helper()
		cfg := validRunConfig(t, url)
		cfg.ratlsPlatform = "tdx"
		cfg.staticAllowlist = true
		cfg.policyDir = policyDir
		cfg.allowlistSeed = staticSeedPath(policyDir)
		cfg.measurementsConfig = f.writeMeasurementsConfig(t)
		cfg.inventoryCIDRs = []string{"not-a-cidr"}
		return cfg
	}

	t.Run("dynamic node exits before seeding", func(t *testing.T) {
		stub, url := unixAttestStub(t)
		stub.SetVerdict(f.verdict(t, f.rtmr3Hex()))
		cfg := staticConfig(t, url, f.writePolicyDir(t, policybundle.DynamicMode))
		err := run(cfg)
		if err == nil || !strings.Contains(err.Error(), "--static-allowlist") {
			t.Fatalf("run() = %v, want the static gate to refuse a dynamic node", err)
		}
		if len(stub.AttestRequests()) != 0 {
			t.Error("run() attested itself on a dynamic node; the mode file is checked first")
		}
	})

	t.Run("operator keys refused", func(t *testing.T) {
		_, url := unixAttestStub(t)
		cfg := staticConfig(t, url, f.writePolicyDir(t, policybundle.StaticMode))
		cfg.operatorKeys = writeOperatorKeysPEM(t)
		err := run(cfg)
		if err == nil || !strings.Contains(err.Error(), "--operator-keys") {
			t.Fatalf("run() = %v, want --operator-keys refused under --static-allowlist", err)
		}
	})

	t.Run("sealed node seeds the measured member", func(t *testing.T) {
		stub, url := unixAttestStub(t)
		stub.SetVerdict(f.verdict(t, f.rtmr3Hex()))
		cfg := staticConfig(t, url, f.writePolicyDir(t, policybundle.StaticMode))
		cfg.logLevel = "info"

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		orig := os.Stdout
		os.Stdout = w
		runErr := run(cfg)
		os.Stdout = orig
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
		_ = w.Close()
		logged, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		if runErr == nil || !strings.Contains(runErr.Error(), "inventory CIDR") {
			t.Fatalf("run() = %v, want the inventory CIDR failure past the static gate", runErr)
		}
		for _, want := range []string{"static allowlist mode: node evidence matches", `"workloads_added":1`} {
			if !strings.Contains(string(logged), want) {
				t.Errorf("startup log missing %q:\n%s", want, logged)
			}
		}
	})
}

func TestNewCmdStaticAllowlistFlags(t *testing.T) {
	flags := NewCmd().Flags()
	for _, tc := range []struct{ flag, want string }{
		{"static-allowlist", "false"},
		{"policy-dir", "/run/confai/policy"},
	} {
		f := flags.Lookup(tc.flag)
		if f == nil {
			t.Fatalf("missing --%s flag", tc.flag)
		}
		if f.DefValue != tc.want {
			t.Errorf("default --%s = %q, want %q", tc.flag, f.DefValue, tc.want)
		}
	}
}
