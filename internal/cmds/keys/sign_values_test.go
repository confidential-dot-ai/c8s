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

func TestSignValuesWritesVerifiableSignature(t *testing.T) {
	keyPath, key := writeOperatorKey(t)
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	content := []byte("measurement: deadbeef\nvalues:\n  tlsLb:\n    san: [\"a\"]\n")
	if err := os.WriteFile(valuesPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"sign-values", "--key", keyPath, valuesPath})
	if err := cmd.Execute(); err != nil {
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
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("measurement: aa\nvalues: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valuesPath+".sig", []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"sign-values", "--key", keyPath, valuesPath})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "values.yaml.sig") {
		t.Fatalf("want refusal naming the existing sig file, got %v", err)
	}
}

func TestSignValuesRequiresKey(t *testing.T) {
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("measurement: aa\nvalues: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"sign-values", valuesPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("want an error when --key is missing")
	}
}

func TestSignValuesDetectsTamperedContent(t *testing.T) {
	keyPath, key := writeOperatorKey(t)
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte("measurement: aa\nvalues: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"sign-values", "--key", keyPath, valuesPath})
	if err := cmd.Execute(); err != nil {
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
