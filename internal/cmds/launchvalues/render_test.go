package launchvalues

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// fakeLoader returns a loadMeasuredOperatorKeyFunc that hands back pubPEM
// unconditionally, standing in for credrelease.LoadMeasuredOperatorKey (a
// real TDX/SNP guest is not available under `go test`).
func fakeLoader(pubPEM []byte) loadMeasuredOperatorKeyFunc {
	return func(_ context.Context, _, _ string) ([]byte, error) {
		return pubPEM, nil
	}
}

// failingLoader simulates LoadMeasuredOperatorKey's fail-closed behavior when
// the pubkey was substituted after boot.
func failingLoader(_ context.Context, _, _ string) ([]byte, error) {
	return nil, errSubstitutedKey
}

var errSubstitutedKey = &substitutedKeyError{}

type substitutedKeyError struct{}

func (*substitutedKeyError) Error() string {
	return "operator pubkey does not match the measured RTMR[3]"
}

// withLoader overrides the package-level seam for the duration of the test.
func withLoader(t *testing.T, fn loadMeasuredOperatorKeyFunc) {
	t.Helper()
	orig := loadMeasuredOperatorKey
	loadMeasuredOperatorKey = fn
	t.Cleanup(func() { loadMeasuredOperatorKey = orig })
}

func writeOperatorPubkeyFile(t *testing.T, pubPEM []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "operator-pubkey")
	if err := os.WriteFile(path, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// signFragment signs sha256(fragmentYAML) with priv, ASN.1 DER, base64,
// single line — the exact shape `c8s keys sign-values` writes.
func signFragment(t *testing.T, priv *ecdsa.PrivateKey, data []byte) string {
	t.Helper()
	digest := sha256.Sum256(data)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der) + "\n"
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

const ownMeasurement = "00172e354c536a71889fa6bdc4dbe2f900172e354c536a71889fa6bdc4dbe2f900172e354c536a71889fa6bdc4dbe2f9"

func baseConfig(t *testing.T, pubkeyPath string) Config {
	t.Helper()
	if len(ownMeasurement) != 96 {
		t.Fatalf("test fixture ownMeasurement is %d hex chars, want 96", len(ownMeasurement))
	}
	return Config{
		Platform:           "tdx",
		AttestationAPIURL:  "http://127.0.0.1:8400",
		OperatorPubkeyPath: pubkeyPath,
		OwnMeasurementHex:  ownMeasurement,
		RTMRs:              []string{"1=" + strings.Repeat("11", 48), "2=" + strings.Repeat("22", 48)},
	}
}

func TestRenderNoFragmentEmitsBootDerivedTreeOnly(t *testing.T) {
	_, pubPEM := genOperatorKey(t)
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))

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
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))

	fragYAML := []byte("measurement: \"" + ownMeasurement + "\"\n" +
		"values:\n" +
		"  tlsLb:\n" +
		"    san:\n" +
		"      - example.com\n" +
		"    cors:\n" +
		"      enabled: true\n" +
		"  cds:\n" +
		"    rateLimit: 42\n" +
		"    rateBurst: 84\n" +
		"  nriImagePolicy:\n" +
		"    policy:\n" +
		"      exemptNamespaces:\n" +
		"        - kube-system\n" +
		"    bootstrapAllowlist:\n" +
		"      digests:\n" +
		"        sha256:abc: \"ghcr.io/example/img:v1\"\n" +
		"  volumed:\n" +
		"    enabled: true\n")
	sig := signFragment(t, priv, fragYAML)
	dir := t.TempDir()
	fragPath, sigPath := writeFragment(t, dir, fragYAML, sig)
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath

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
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))

	fragYAML := []byte("measurement: \"" + ownMeasurement + "\"\nvalues:\n  tlsLb:\n    san: [a]\n")
	sig := signFragment(t, priv, fragYAML)
	dir := t.TempDir()
	fragPath, sigPath := writeFragment(t, dir, fragYAML, sig)
	// Tamper with the fragment after signing.
	if err := os.WriteFile(fragPath, append(fragYAML, []byte("# tampered\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath

	_, err := Render(context.Background(), cfg)
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
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))

	fragYAML := []byte("measurement: \"" + ownMeasurement + "\"\nvalues:\n  tlsLb:\n    san: [a]\n")
	sig := signFragment(t, otherPriv, fragYAML) // signed by a DIFFERENT key
	dir := t.TempDir()
	fragPath, sigPath := writeFragment(t, dir, fragYAML, sig)
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error for a signature from a key that is not the measured operator key")
	}
}

func TestRenderRejectsWrongMeasurement(t *testing.T) {
	priv, pubPEM := genOperatorKey(t)
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))

	otherMeasurement := strings.Repeat("ff", 48)
	fragYAML := []byte("measurement: \"" + otherMeasurement + "\"\nvalues:\n  tlsLb:\n    san: [a]\n")
	sig := signFragment(t, priv, fragYAML)
	dir := t.TempDir()
	fragPath, sigPath := writeFragment(t, dir, fragYAML, sig)
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error when the fragment's measurement does not match --own-measurement")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error = %v, want it to name the measurement mismatch", err)
	}
}

func TestRenderRejectsDisallowedPath(t *testing.T) {
	priv, pubPEM := genOperatorKey(t)
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))

	fragYAML := []byte("measurement: \"" + ownMeasurement + "\"\n" +
		"values:\n" +
		"  cds:\n" +
		"    image:\n" +
		"      digest: sha256:evil\n")
	sig := signFragment(t, priv, fragYAML)
	dir := t.TempDir()
	fragPath, sigPath := writeFragment(t, dir, fragYAML, sig)
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath

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
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))

	fragYAML := []byte("measurement: \"" + ownMeasurement + "\"\n" +
		"values:\n" +
		"  cds:\n" +
		"    operatorKeys: |\n" +
		"      " + strings.ReplaceAll(string(evilPubPEM), "\n", "\n      ") + "\n")
	sig := signFragment(t, priv, fragYAML)
	dir := t.TempDir()
	fragPath, sigPath := writeFragment(t, dir, fragYAML, sig)
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath

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
	_, pubPEM := genOperatorKey(t)
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error when LoadMeasuredOperatorKey fails (substituted key)")
	}
}

func TestRenderRequiresSignatureWhenFragmentSet(t *testing.T) {
	_, pubPEM := genOperatorKey(t)
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))
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
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))

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
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))
	cfg.Platform = "not-a-platform"

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error for an invalid platform")
	}
}

func TestRenderRequiresOwnMeasurement(t *testing.T) {
	_, pubPEM := genOperatorKey(t)
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))
	cfg.OwnMeasurementHex = ""

	_, err := Render(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error when --own-measurement is empty")
	}
}

// TestRenderNonOperatorBootOmitsOperatorKeys covers a launch with no
// opkeydata pubkey at all: Render must still succeed (this guest's own
// measurement is independent of the operator key) and must not call the
// measured-key loader — there is nothing staged for it to load, and the
// original c8s-chart-values.sh behavior this replaces just omitted
// cds.operatorKeys entirely rather than failing the boot.
func TestRenderNonOperatorBootOmitsOperatorKeys(t *testing.T) {
	withLoader(t, func(context.Context, string, string) ([]byte, error) {
		t.Fatal("loadMeasuredOperatorKey must not be called on a non-operator boot")
		return nil, nil
	})
	cfg := baseConfig(t, filepath.Join(t.TempDir(), "does-not-exist"))

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
	withLoader(t, func(context.Context, string, string) ([]byte, error) {
		t.Fatal("loadMeasuredOperatorKey must not be called on a non-operator boot")
		return nil, nil
	})
	cfg := baseConfig(t, filepath.Join(t.TempDir(), "does-not-exist"))
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
