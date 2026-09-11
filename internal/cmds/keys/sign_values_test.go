package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func writeOperatorKey(t *testing.T) (path string, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pem, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	path = filepath.Join(dir, "operator.key")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, key
}

// writeValues writes content to <dir>/values.yaml and returns its path — the
// fragment every sign-values test signs.
func writeValues(t *testing.T, dir string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runSign runs `c8s keys sign-values --key <keyPath> <valuesPath>` through
// the real cobra command, the shape every test below exercises.
func runSign(keyPath, valuesPath string, args ...string) error {
	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	argv := []string{"sign-values"}
	if keyPath != "" {
		argv = append(argv, "--key", keyPath)
	}
	argv = append(argv, args...)
	argv = append(argv, valuesPath)
	cmd.SetArgs(argv)
	return cmd.Execute()
}

func TestSignValuesWritesVerifiableSignature(t *testing.T) {
	keyPath, key := writeOperatorKey(t)
	dir := t.TempDir()
	content := []byte("measurement: deadbeef\nvalues:\n  tlsLb:\n    san: [\"a\"]\n")
	valuesPath := writeValues(t, dir, content)

	if err := runSign(keyPath, valuesPath); err != nil {
		t.Fatalf("execute: %v", err)
	}

	sigPath := valuesPath + ".sig"
	sigLine, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	trimmed := strings.TrimSuffix(string(sigLine), "\n")
	if strings.Contains(trimmed, "\n") {
		t.Fatalf("signature file is not a single line: %q", trimmed)
	}
	der, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	digest := sha256.Sum256(content)
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
		t.Fatal("signature does not verify against the signing key over sha256(values.yaml)")
	}
}

func TestSignValuesRefusesToOverwrite(t *testing.T) {
	keyPath, _ := writeOperatorKey(t)
	dir := t.TempDir()
	valuesPath := writeValues(t, dir, []byte("measurement: aa\nvalues: {}\n"))
	if err := os.WriteFile(valuesPath+".sig", []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runSign(keyPath, valuesPath)
	if err == nil || !strings.Contains(err.Error(), "values.yaml.sig") {
		t.Fatalf("want refusal naming the existing sig file, got %v", err)
	}
}

func TestSignValuesRequiresKey(t *testing.T) {
	dir := t.TempDir()
	valuesPath := writeValues(t, dir, []byte("measurement: aa\nvalues: {}\n"))
	if err := runSign("", valuesPath); err == nil {
		t.Fatal("want an error when --key is missing")
	}
}

func TestSignValuesDetectsTamperedContent(t *testing.T) {
	keyPath, key := writeOperatorKey(t)
	dir := t.TempDir()
	valuesPath := writeValues(t, dir, []byte("measurement: aa\nvalues: {}\n"))
	if err := runSign(keyPath, valuesPath); err != nil {
		t.Fatalf("execute: %v", err)
	}
	sigLine, err := os.ReadFile(valuesPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(string(sigLine), "\n"))
	if err != nil {
		t.Fatal(err)
	}
	tamperedDigest := sha256.Sum256([]byte("measurement: aa\nvalues:\n  extra: true\n"))
	if ecdsa.VerifyASN1(&key.PublicKey, tamperedDigest[:], der) {
		t.Fatal("signature verified against tampered content")
	}
}
