package launchvalues

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// genOperatorKey generates a P-256 key and its PKIX "PUBLIC KEY" PEM — the
// same shape c8s keys new writes and operatorauth.ParsePublicKeysPEM parses.
func genOperatorKey(t *testing.T) (priv *ecdsa.PrivateKey, pubPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, pubPEM
}

const ownMeasurement = "00172e354c536a71889fa6bdc4dbe2f900172e354c536a71889fa6bdc4dbe2f900172e354c536a71889fa6bdc4dbe2f9"

// fakeOwnMeasurementBytes/fakeRTMRs are the fixed measurement and RTMR pins
// every fake loader below hands back, standing in for
// credrelease.OwnLaunchMeasurement (no real tdx_guest sysfs or
// attestation-api under `go test`).
func fakeOwnMeasurementBytes() []byte {
	b, err := hex.DecodeString(ownMeasurement)
	if err != nil {
		panic(err)
	}
	return b
}

func fakeRTMRs() map[int][]byte {
	return map[int][]byte{
		1: bytes.Repeat([]byte{0x11}, 48),
		2: bytes.Repeat([]byte{0x22}, 48),
	}
}

// fakeCombinedLoader returns a loadMeasuredOperatorKeyAndOwnMeasurementFunc
// that hands back pubPEM (with pubErr nil) and the fixed test measurement/
// RTMRs, standing in for credrelease.LoadMeasuredOperatorKeyAndOwnMeasurement
// on the common "operator key present, measurement resolves" path.
func fakeCombinedLoader(pubPEM []byte) loadMeasuredOperatorKeyAndOwnMeasurementFunc {
	return func(context.Context, string, string) ([]byte, error, []byte, map[int][]byte, error) {
		return pubPEM, nil, fakeOwnMeasurementBytes(), fakeRTMRs(), nil
	}
}

// noOperatorKeyLoader stands in for the combined loader on a boot with no
// opkeydata pubkey staged: pubErr wraps credrelease.ErrNoOperatorKey, which
// is what Render branches on. The own measurement still resolves: a
// non-operator boot needs it too.
func noOperatorKeyLoader(context.Context, string, string) ([]byte, error, []byte, map[int][]byte, error) {
	err := fmt.Errorf("%w: /etc/confai/operator-pubkey (test fixture)", credrelease.ErrNoOperatorKey)
	return nil, err, fakeOwnMeasurementBytes(), fakeRTMRs(), nil
}

// missingRegisterLoader simulates a staged operator key whose TDX binding
// check failed because RTMR[3] could not be read: an ENOENT, but from the
// sysfs, not the pubkey. Render must fail closed, not treat it as a
// non-operator boot.
func missingRegisterLoader(context.Context, string, string) ([]byte, error, []byte, map[int][]byte, error) {
	_, err := os.Open(filepath.Join(os.TempDir(), "c8s-launchvalues-test-rtmr3-does-not-exist"))
	return nil, fmt.Errorf("read rtmr3: %w", err), fakeOwnMeasurementBytes(), fakeRTMRs(), nil
}

var errSubstitutedKey = errors.New("operator pubkey does not match the measured RTMR[3]")

// failingLoader simulates the combined loader's fail-closed behavior when the
// pubkey was substituted after boot (not a "does not exist" failure, so
// Render must not treat it as a non-operator boot). The own measurement
// still resolves — verifyKeyLaunchBound/verifyKeyMeasured failing does not
// stop credrelease from reading this guest's own sysfs state.
func failingLoader(context.Context, string, string) ([]byte, error, []byte, map[int][]byte, error) {
	return nil, errSubstitutedKey, fakeOwnMeasurementBytes(), fakeRTMRs(), nil
}

// unresolvableMeasurementLoader simulates the combined loader's hard-fail
// path: this guest's own launch measurement itself cannot be read (e.g. the
// tdx_guest sysfs is gone), which fails the whole call regardless of the
// operator key.
func unresolvableMeasurementLoader(context.Context, string, string) ([]byte, error, []byte, map[int][]byte, error) {
	return nil, nil, nil, nil, errors.New("tdx_guest sysfs unreadable (test fixture)")
}

// withLoader overrides the package-level combined seam for the duration of
// the test.
func withLoader(t *testing.T, fn loadMeasuredOperatorKeyAndOwnMeasurementFunc) {
	t.Helper()
	orig := loadMeasuredOperatorKeyAndOwnMeasurement
	loadMeasuredOperatorKeyAndOwnMeasurement = fn
	t.Cleanup(func() { loadMeasuredOperatorKeyAndOwnMeasurement = orig })
}

// signFragment signs data the way `c8s keys sign-values` does, as a single
// line.
func signFragment(t *testing.T, priv *ecdsa.PrivateKey, data []byte) string {
	t.Helper()
	sig, err := operatorauth.SignDetached(priv, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig + "\n"
}

func writeFragment(t *testing.T, dir string, data []byte, sigLine string) (fragPath, sigPath string) {
	t.Helper()
	fragPath = filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(fragPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sigPath = fragPath + ".sig"
	if err := os.WriteFile(sigPath, []byte(sigLine), 0o644); err != nil {
		t.Fatal(err)
	}
	return fragPath, sigPath
}

// attachSignedFragment builds a fragment naming ownMeasurement with the
// given values YAML body (indented under "values:" by the caller), signs it
// with priv, writes both files under a fresh temp dir, and wires cfg's
// FragmentPath/SignaturePath to them — the setup every fragment-path test
// below repeats.
func attachSignedFragment(t *testing.T, cfg *Config, priv *ecdsa.PrivateKey, valuesYAML string) {
	t.Helper()
	fragYAML := []byte("measurement: \"" + ownMeasurement + "\"\nvalues:\n" + valuesYAML)
	sig := signFragment(t, priv, fragYAML)
	dir := t.TempDir()
	fragPath, sigPath := writeFragment(t, dir, fragYAML, sig)
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath
}

func baseConfig() Config {
	return Config{
		Platform:          "tdx",
		AttestationAPIURL: "http://127.0.0.1:8400",
	}
}

func TestRenderNoFragmentEmitsBootDerivedTreeOnly(t *testing.T) {
	_, pubPEM := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()

	out, err := Render(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal([]byte(out), &tree); err != nil {
		t.Fatalf("parse rendered YAML: %v\n%s", err, out)
	}
	cds, ok := tree["cds"].(map[string]any)
	if !ok {
		t.Fatalf("no cds key in rendered tree: %v", tree)
	}
	if cds["operatorKeys"] != string(pubPEM) {
		t.Errorf("cds.operatorKeys = %v, want the measured operator pubkey", cds["operatorKeys"])
	}
	measurements, ok := cds["measurements"].([]any)
	if !ok || len(measurements) != 1 || measurements[0] != ownMeasurement {
		t.Errorf("cds.measurements = %v, want [%s]", cds["measurements"], ownMeasurement)
	}
	ratlsMesh, ok := tree["ratlsMesh"].(map[string]any)
	if !ok {
		t.Fatalf("no ratlsMesh key: %v", tree)
	}
	rmMeasurements, ok := ratlsMesh["measurements"].([]any)
	if !ok || len(rmMeasurements) != 1 || rmMeasurements[0] != ownMeasurement {
		t.Errorf("ratlsMesh.measurements = %v, want [%s]", ratlsMesh["measurements"], ownMeasurement)
	}
	rtmrs, ok := cds["rtmrs"].([]any)
	if !ok || len(rtmrs) != 2 {
		t.Errorf("cds.rtmrs = %v, want 2 entries", cds["rtmrs"])
	}
}

func TestRenderValidFragmentMergesUnderBootDerivedKeys(t *testing.T) {
	priv, pubPEM := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()
	attachSignedFragment(t, &cfg, priv, ""+
		"  tlsLb:\n"+
		"    san:\n"+
		"      - example.com\n"+
		"    cors:\n"+
		"      enabled: true\n"+
		"  cds:\n"+
		"    rateLimit: 42\n"+
		"    rateBurst: 84\n"+
		"  nriImagePolicy:\n"+
		"    policy:\n"+
		"      exemptNamespaces:\n"+
		"        - kube-system\n"+
		"    bootstrapAllowlist:\n"+
		"      workloads:\n"+
		"        example:\n"+
		"          containers:\n"+
		"            - digest: sha256:abc\n"+
		"              image: ghcr.io/example/img:v1\n"+
		"              command: {policy: any}\n"+
		"              args: {policy: any}\n"+
		"  volumed:\n"+
		"    enabled: true\n")

	out, err := Render(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal([]byte(out), &tree); err != nil {
		t.Fatalf("parse rendered YAML: %v\n%s", err, out)
	}

	// Fragment values landed.
	tlsLb := tree["tlsLb"].(map[string]any)
	if san, ok := tlsLb["san"].([]any); !ok || len(san) != 1 || san[0] != "example.com" {
		t.Errorf("tlsLb.san = %v", tlsLb["san"])
	}
	cors := tlsLb["cors"].(map[string]any)
	if cors["enabled"] != true {
		t.Errorf("tlsLb.cors.enabled = %v, want true", cors["enabled"])
	}

	// Boot-derived keys survived the merge.
	cds := tree["cds"].(map[string]any)
	if cds["operatorKeys"] != string(pubPEM) {
		t.Errorf("cds.operatorKeys clobbered by merge: %v", cds["operatorKeys"])
	}
	measurements := cds["measurements"].([]any)
	if len(measurements) != 1 || measurements[0] != ownMeasurement {
		t.Errorf("cds.measurements clobbered: %v", measurements)
	}
	if cds["rateLimit"] != 42 {
		t.Errorf("cds.rateLimit = %v, want 42", cds["rateLimit"])
	}
	if cds["rateBurst"] != 84 {
		t.Errorf("cds.rateBurst = %v, want 84", cds["rateBurst"])
	}

	volumed := tree["volumed"].(map[string]any)
	if volumed["enabled"] != true {
		t.Errorf("volumed.enabled = %v, want true", volumed["enabled"])
	}
}

func TestRenderRejectsBadSignature(t *testing.T) {
	priv, pubPEM := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()
	attachSignedFragment(t, &cfg, priv, "  tlsLb:\n    san: [a]\n")
	// Tamper with the fragment after signing.
	tampered, err := os.ReadFile(cfg.FragmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.FragmentPath, append(tampered, []byte("# tampered\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error for a tampered fragment")
	}
	if !strings.Contains(err.Error(), "signature invalid") {
		t.Errorf("error = %v, want it to name a signature failure", err)
	}
}

func TestRenderRejectsSignatureFromWrongKey(t *testing.T) {
	_, pubPEM := genOperatorKey(t)
	otherPriv, _ := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()
	attachSignedFragment(t, &cfg, otherPriv, "  tlsLb:\n    san: [a]\n") // signed by a DIFFERENT key

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error for a signature from a key that is not the measured operator key")
	}
}

func TestRenderRejectsWrongMeasurement(t *testing.T) {
	priv, pubPEM := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()

	otherMeasurement := strings.Repeat("ff", 48)
	fragYAML := []byte("measurement: \"" + otherMeasurement + "\"\nvalues:\n  tlsLb:\n    san: [a]\n")
	sig := signFragment(t, priv, fragYAML)
	dir := t.TempDir()
	fragPath, sigPath := writeFragment(t, dir, fragYAML, sig)
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error when the fragment's measurement does not match this guest's own")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error = %v, want it to name the measurement mismatch", err)
	}
}

func TestRenderRejectsDisallowedPath(t *testing.T) {
	priv, pubPEM := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()
	attachSignedFragment(t, &cfg, priv, "  cds:\n    image:\n      digest: sha256:evil\n")

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error for cds.image.digest, which is not on the allowlist")
	}
	if !strings.Contains(err.Error(), "cds.image.digest") {
		t.Errorf("error = %v, want it to name the offending path", err)
	}
}

func TestRenderRejectsOperatorKeysOverrideAttempt(t *testing.T) {
	priv, pubPEM := genOperatorKey(t)
	_, evilPubPEM := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()
	attachSignedFragment(t, &cfg, priv, ""+
		"  cds:\n"+
		"    operatorKeys: |\n"+
		"      "+strings.ReplaceAll(string(evilPubPEM), "\n", "\n      ")+"\n")

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error for a fragment attempting to override cds.operatorKeys")
	}
	if !strings.Contains(err.Error(), "cds.operatorKeys") {
		t.Errorf("error = %v, want it to name cds.operatorKeys", err)
	}
}

func TestRenderFailsClosedWhenLoaderFails(t *testing.T) {
	withLoader(t, failingLoader)
	cfg := baseConfig()

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error when LoadMeasuredOperatorKey fails (substituted key)")
	}
	if errors.Is(err, credrelease.ErrNoOperatorKey) {
		t.Errorf("error = %v, want it NOT classified as a non-operator boot (a substituted key must fail closed, not be treated as absent)", err)
	}
}

// TestRenderFailsClosedOnMissingRegister covers a staged operator key whose
// binding check hit ENOENT on the sysfs register: that is not an absent
// pubkey and must not silently drop cds.operatorKeys.
func TestRenderFailsClosedOnMissingRegister(t *testing.T) {
	withLoader(t, missingRegisterLoader)
	cfg := baseConfig()

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error when the register read fails")
	}
	if !strings.Contains(err.Error(), "load measured operator key") {
		t.Errorf("error = %v, want the load-failure path, not the non-operator branch", err)
	}
}

func TestRenderRequiresSignatureWhenFragmentSet(t *testing.T) {
	_, pubPEM := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()
	dir := t.TempDir()
	fragPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(fragPath, []byte("measurement: \""+ownMeasurement+"\"\nvalues: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.FragmentPath = fragPath
	// cfg.SignaturePath deliberately left empty.

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error: a fragment without a signature must fail the boot")
	}
	if !strings.Contains(err.Error(), "--signature") {
		t.Errorf("error = %v, want it to name --signature", err)
	}
}

func TestRenderRejectsUnknownTopLevelKey(t *testing.T) {
	priv, pubPEM := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()

	fragYAML := []byte("measurement: \"" + ownMeasurement + "\"\nvalues: {}\nextra: true\n")
	sig := signFragment(t, priv, fragYAML)
	dir := t.TempDir()
	fragPath, sigPath := writeFragment(t, dir, fragYAML, sig)
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error for an unexpected top-level key")
	}
}

func TestRenderRequiresPlatform(t *testing.T) {
	_, pubPEM := genOperatorKey(t)
	withLoader(t, fakeCombinedLoader(pubPEM))
	cfg := baseConfig()
	cfg.Platform = "not-a-platform"

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error for an invalid platform")
	}
}

func TestRenderFailsClosedWhenOwnMeasurementUnresolvable(t *testing.T) {
	withLoader(t, unresolvableMeasurementLoader)
	cfg := baseConfig()

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error when this guest's own launch measurement cannot be resolved")
	}
}

// TestRenderNonOperatorBootOmitsOperatorKeys covers a launch with no
// opkeydata pubkey at all: Render must still succeed (this guest's own
// measurement is independent of the operator key), must not call
// operatorauth.ParsePublicKeysPEM (nothing to parse), and must classify the
// loader's ErrNoOperatorKey as "non-operator boot" rather than a hard failure —
// the original c8s-chart-values.sh behavior this replaces just omitted
// cds.operatorKeys entirely rather than failing the boot.
func TestRenderNonOperatorBootOmitsOperatorKeys(t *testing.T) {
	withLoader(t, noOperatorKeyLoader)
	cfg := baseConfig()

	out, err := Render(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal([]byte(out), &tree); err != nil {
		t.Fatalf("parse rendered YAML: %v\n%s", err, out)
	}
	cds := tree["cds"].(map[string]any)
	if _, has := cds["operatorKeys"]; has {
		t.Errorf("cds.operatorKeys = %v, want it omitted on a non-operator boot", cds["operatorKeys"])
	}
	measurements, ok := cds["measurements"].([]any)
	if !ok || len(measurements) != 1 || measurements[0] != ownMeasurement {
		t.Errorf("cds.measurements = %v, want [%s]", cds["measurements"], ownMeasurement)
	}
}

// TestRenderNonOperatorBootRejectsFragment covers a fragment somehow present
// with no operator key to verify it against — nothing can authenticate it,
// so it must fail closed rather than being silently ignored.
func TestRenderNonOperatorBootRejectsFragment(t *testing.T) {
	withLoader(t, noOperatorKeyLoader)
	cfg := baseConfig()
	dir := t.TempDir()
	fragPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(fragPath, []byte("measurement: \""+ownMeasurement+"\"\nvalues: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = fragPath + ".sig"

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error: a fragment with no operator key to verify it against must fail closed")
	}
}

// TestRenderRejectsMeasurementsConfig: the chart renders measurementsConfig
// INSTEAD of the boot-derived pins, so a fragment must not be able to set it.
func TestRenderRejectsMeasurementsConfig(t *testing.T) {
	for _, path := range []string{"cds.measurementsConfig", "ratlsMesh.measurementsConfig"} {
		t.Run(path, func(t *testing.T) {
			if allowedPath(path) {
				t.Fatalf("%s must not be on the launch-time allowlist", path)
			}
		})
	}
}

// TestRenderHelmChartConfigManifestValuesContentIsString pins the wire
// shape: spec.valuesContent is a string block scalar (what the
// helm.cattle.io/v1 CRD declares), not a nested mapping.
func TestRenderHelmChartConfigManifestValuesContentIsString(t *testing.T) {
	values := "cds:\n  operatorKeys: |\n    -----BEGIN PUBLIC KEY-----\n  measurements:\n    - \"" + ownMeasurement + "\"\n"
	manifest, err := renderHelmChartConfigManifest(values)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Spec       struct {
			ValuesContent any `yaml:"valuesContent"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(manifest, &doc); err != nil {
		t.Fatalf("parse manifest: %v\n%s", err, manifest)
	}
	if doc.APIVersion != "helm.cattle.io/v1" || doc.Kind != "HelmChartConfig" {
		t.Errorf("header = %s/%s", doc.APIVersion, doc.Kind)
	}
	got, ok := doc.Spec.ValuesContent.(string)
	if !ok {
		t.Fatalf("spec.valuesContent is %T, want string\n%s", doc.Spec.ValuesContent, manifest)
	}
	if got != values {
		t.Errorf("spec.valuesContent round-trip mismatch:\n got %q\nwant %q", got, values)
	}
}
