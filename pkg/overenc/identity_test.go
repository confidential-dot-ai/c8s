package overenc

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cross-language contract: c8s-verify-js/test/identity.test.ts must reproduce
// the v1 transcript vector pinned here.
func TestIdentityTranscriptHashBindsEveryField(t *testing.T) {
	ek := bytes.Repeat([]byte{0x11}, XWingEKBytes)
	ct := bytes.Repeat([]byte{0x22}, XWingCTBytes)
	sessionID := bytes.Repeat([]byte{0x44}, SessionIDBytes)
	nonce := bytes.Repeat([]byte{0x33}, identityNonceBytes)
	leaf := []byte("leaf-der")
	ca := []byte("ca-der")

	base, err := IdentityTranscriptHash(ek, ct, sessionID, nonce, leaf, ca)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != sha512.Size384 {
		t.Fatalf("transcript hash length = %d, want %d", len(base), sha512.Size384)
	}
	const vector = "0825f574219c593d55c84deef941c516cdecb09f6ef33e8f9fdbd5728ada3764d85d20eccaa835f9512b64dd2ab1d35f"
	if hex.EncodeToString(base) != vector {
		t.Fatalf("cross-language transcript vector = %x, want %s", base, vector)
	}

	tests := []struct {
		name                     string
		ek, ct, sessionID, nonce []byte
		leaf, ca                 []byte
	}{
		{name: "ek", ek: bytes.Repeat([]byte{0x55}, XWingEKBytes), ct: ct, sessionID: sessionID, nonce: nonce, leaf: leaf, ca: ca},
		{name: "ct", ek: ek, ct: bytes.Repeat([]byte{0x66}, XWingCTBytes), sessionID: sessionID, nonce: nonce, leaf: leaf, ca: ca},
		{name: "session id", ek: ek, ct: ct, sessionID: bytes.Repeat([]byte{0x77}, SessionIDBytes), nonce: nonce, leaf: leaf, ca: ca},
		{name: "nonce", ek: ek, ct: ct, sessionID: sessionID, nonce: bytes.Repeat([]byte{0x88}, identityNonceBytes), leaf: leaf, ca: ca},
		{name: "leaf", ek: ek, ct: ct, sessionID: sessionID, nonce: nonce, leaf: []byte("other-leaf"), ca: ca},
		{name: "ca", ek: ek, ct: ct, sessionID: sessionID, nonce: nonce, leaf: leaf, ca: []byte("other-ca")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IdentityTranscriptHash(tt.ek, tt.ct, tt.sessionID, tt.nonce, tt.leaf, tt.ca)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatal("changed field did not change transcript hash")
			}
		})
	}
}

func TestLBTranscriptHashBindsEveryField(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x33}, identityNonceBytes)
	serving := []byte("serving-der")
	leaf := []byte("leaf-der")
	ca := []byte("ca-der")

	base, err := LBTranscriptHash(nonce, serving, leaf, ca)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != sha512.Size384 {
		t.Fatalf("transcript hash length = %d, want %d", len(base), sha512.Size384)
	}

	tests := []struct {
		name                     string
		nonce, serving, leaf, ca []byte
	}{
		{name: "nonce", nonce: bytes.Repeat([]byte{0x66}, identityNonceBytes), serving: serving, leaf: leaf, ca: ca},
		{name: "serving leaf", nonce: nonce, serving: []byte("other-serving"), leaf: leaf, ca: ca},
		{name: "mesh leaf", nonce: nonce, serving: serving, leaf: []byte("other-leaf"), ca: ca},
		{name: "ca", nonce: nonce, serving: serving, leaf: leaf, ca: []byte("other-ca")},
		// Swapping the serving and mesh leaves must change the hash: the
		// per-field positions are load-bearing, not just the field set.
		{name: "serving/mesh swap", nonce: nonce, serving: leaf, leaf: serving, ca: ca},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LBTranscriptHash(tt.nonce, tt.serving, tt.leaf, tt.ca)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatal("changed field did not change transcript hash")
			}
		})
	}
}

func TestLBTranscriptHashValidatesShape(t *testing.T) {
	nonce := make([]byte, identityNonceBytes)
	for _, tc := range []struct {
		name                     string
		nonce, serving, leaf, ca []byte
		wantErr                  string
	}{
		{name: "nonce short", nonce: make([]byte, 16), serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}, wantErr: "lb transcript nonce must be 32 bytes, got 16"},
		{name: "nonce long", nonce: make([]byte, 33), serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}, wantErr: "lb transcript nonce must be 32 bytes, got 33"},
		{name: "serving leaf empty", nonce: nonce, leaf: []byte{2}, ca: []byte{3}, wantErr: "lb transcript requires serving leaf, mesh leaf, and CA certificates"},
		{name: "mesh leaf empty", nonce: nonce, serving: []byte{1}, ca: []byte{3}, wantErr: "lb transcript requires serving leaf, mesh leaf, and CA certificates"},
		{name: "ca empty", nonce: nonce, serving: []byte{1}, leaf: []byte{2}, wantErr: "lb transcript requires serving leaf, mesh leaf, and CA certificates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LBTranscriptHash(tc.nonce, tc.serving, tc.leaf, tc.ca)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestLBTranscriptGoldenVectors pins the attest-lb transcript encoding.
// Cross-repo contract: TEErminator reimplements this transcript; its
// internal/verifier/endpoint_test.go must reproduce these vectors.
func TestLBTranscriptGoldenVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "attest_lb_transcript_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Description    string `json:"description"`
		NonceB64       string `json:"nonce_b64"`
		ServingLeafB64 string `json:"serving_leaf_der_b64"`
		MeshLeafB64    string `json:"mesh_leaf_der_b64"`
		MeshCAB64      string `json:"mesh_ca_der_b64"`
		ReportDataB64  string `json:"report_data_b64"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no golden vectors")
	}
	decode := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("bad vector base64 %q: %v", s, err)
		}
		return b
	}
	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			got, err := LBTranscriptHash(decode(v.NonceB64), decode(v.ServingLeafB64), decode(v.MeshLeafB64), decode(v.MeshCAB64))
			if err != nil {
				t.Fatal(err)
			}
			if want := decode(v.ReportDataB64); !bytes.Equal(got, want) {
				t.Fatalf("report_data = %x, want %x", got, want)
			}
		})
	}
}

func TestIdentityTranscriptHashValidatesShape(t *testing.T) {
	ek := make([]byte, XWingEKBytes)
	ct := make([]byte, XWingCTBytes)
	id := make([]byte, SessionIDBytes)
	nonce := make([]byte, identityNonceBytes)
	for _, tc := range []struct {
		name                     string
		ek, ct, sessionID, nonce []byte
		leaf, ca                 []byte
		wantErr                  string
	}{
		{name: "ek", ek: make([]byte, 1), ct: ct, sessionID: id, nonce: nonce, leaf: []byte{1}, ca: []byte{2}, wantErr: "identity transcript X-Wing key must be 1216 bytes, got 1"},
		{name: "ct", ek: ek, ct: make([]byte, 1), sessionID: id, nonce: nonce, leaf: []byte{1}, ca: []byte{2}, wantErr: "identity transcript X-Wing ciphertext must be 1120 bytes, got 1"},
		{name: "session id", ek: ek, ct: ct, sessionID: make([]byte, 1), nonce: nonce, leaf: []byte{1}, ca: []byte{2}, wantErr: "identity transcript session id must be 16 bytes, got 1"},
		{name: "nonce", ek: ek, ct: ct, sessionID: id, nonce: make([]byte, 16), leaf: []byte{1}, ca: []byte{2}, wantErr: "identity transcript nonce must be 32 bytes, got 16"},
		{name: "leaf", ek: ek, ct: ct, sessionID: id, nonce: nonce, ca: []byte{2}, wantErr: "identity transcript requires leaf and CA certificates"},
		{name: "ca", ek: ek, ct: ct, sessionID: id, nonce: nonce, leaf: []byte{1}, wantErr: "identity transcript requires leaf and CA certificates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := IdentityTranscriptHash(tc.ek, tc.ct, tc.sessionID, tc.nonce, tc.leaf, tc.ca)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
