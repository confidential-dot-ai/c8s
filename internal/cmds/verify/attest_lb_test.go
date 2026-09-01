package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func buildAttestLBJSON(t *testing.T, id *endpointIdentity, nonce, servingLeafDER []byte) []byte {
	t.Helper()
	operatorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operatorDER, err := x509.MarshalPKIXPublicKey(&operatorKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	operatorPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: operatorDER})
	keySetHash, err := operatorauth.KeySetHash([]*ecdsa.PublicKey{&operatorKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := overenc.LBTranscriptHash(nonce, servingLeafDER, id.leaf.Raw, id.ca.Raw)
	if err != nil {
		t.Fatal(err)
	}
	transcript, err = overenc.BindOperatorKeySetHash(transcript, keySetHash)
	if err != nil {
		t.Fatal(err)
	}
	servingHash := sha256.Sum256(servingLeafDER)
	body := map[string]any{
		"version":              types.BindingAttestLB,
		"platform":             "tdx",
		"nonce":                base64.RawURLEncoding.EncodeToString(nonce),
		"evidence":             map[string]any{"quote": "tdx-evidence"},
		"operator_keys_pem":    string(operatorPEM),
		"operator_keys_sha256": keySetHash,
		"cds_cert_pem":         id.chainPEM,
		"identity_proof":       id.proofJSON(t, transcript),
		"serving_leaf_sha256":  base64.RawURLEncoding.EncodeToString(servingHash[:]),
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEvidenceFromAttestLBBindsObservedLeafNonceAndOperatorSet(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x8a}, nonceSize)
	mesh := mintEndpointIdentity(t)
	serving := mintEndpointIdentity(t).leaf.Raw
	body := buildAttestLBJSON(t, mesh, nonce, serving)

	ev, err := evidenceFromAttestLBJSON(body, nonce, serving, "saved response")
	if err != nil {
		t.Fatal(err)
	}
	want, err := overenc.LBTranscriptHash(nonce, serving, mesh.leaf.Raw, mesh.ca.Raw)
	if err != nil {
		t.Fatal(err)
	}
	var response attestationResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	want, err = overenc.BindOperatorKeySetHash(want, response.OperatorKeysSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.erd, want) {
		t.Fatalf("report-data transcript = %x, want %x", ev.erd, want)
	}
	servingHash := sha256.Sum256(serving)
	if !ev.fresh || !ev.tlsBindingVerified || ev.servingLeafSHA256 != hex.EncodeToString(servingHash[:]) {
		t.Fatalf("binding fields: fresh=%t verified=%t digest=%q", ev.fresh, ev.tlsBindingVerified, ev.servingLeafSHA256)
	}
}

func TestEvidenceFromAttestLBRejectsSubstitutionAndReplay(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x8a}, nonceSize)
	mesh := mintEndpointIdentity(t)
	serving := mintEndpointIdentity(t).leaf.Raw
	body := buildAttestLBJSON(t, mesh, nonce, serving)

	for _, tc := range []struct {
		name    string
		nonce   []byte
		serving []byte
		want    string
	}{
		{"different challenge", bytes.Repeat([]byte{0x8b}, nonceSize), serving, "does not echo"},
		{"different live leaf", nonce, mintEndpointIdentity(t).leaf.Raw, "does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := evidenceFromAttestLBJSON(body, tc.nonce, tc.serving, "saved response")
			if err == nil || !isSecurityError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want security error containing %q", err, tc.want)
			}
		})
	}

	t.Run("operator policy substitution", func(t *testing.T) {
		var obj map[string]any
		if err := json.Unmarshal(body, &obj); err != nil {
			t.Fatal(err)
		}
		obj["operator_keys_sha256"] = strings.Repeat("0", 64)
		mutated, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromAttestLBJSON(mutated, nonce, serving, "saved response"); err == nil || !isSecurityError(err) {
			t.Fatalf("operator substitution accepted: %v", err)
		}
	})
}

func TestValidateAttestLBConfigRequiresCallerObservedInputs(t *testing.T) {
	valid := config{
		mode: "attest-lb", fromFile: "bundle.json",
		observedServingCert: "leaf.der",
		attestationNonce:    base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, nonceSize)),
	}
	if err := validateAttestLBConfig(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.fromFile = "" },
		func(c *config) { c.observedServingCert = "" },
		func(c *config) { c.attestationNonce = "" },
		func(c *config) { c.attestationNonce = "AA" },
		func(c *config) { c.expectedRDHex = "01" },
	} {
		cfg := valid
		mutate(&cfg)
		if err := validateAttestLBConfig(cfg); err == nil {
			t.Fatalf("invalid config passed: %+v", cfg)
		}
	}
}
