package overenc

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityTranscriptHashBindsEveryField(t *testing.T) {
	pub := PublicKey{
		X25519:   bytes.Repeat([]byte{0x11}, X25519PubBytes),
		MLKEM768: bytes.Repeat([]byte{0x22}, MLKEM768EKBytes),
	}
	nonce := bytes.Repeat([]byte{0x33}, identityNonceBytes)
	leaf := []byte("leaf-der")
	ca := []byte("ca-der")

	base, err := IdentityTranscriptHash(pub, nonce, leaf, ca)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != sha512.Size384 {
		t.Fatalf("transcript hash length = %d, want %d", len(base), sha512.Size384)
	}
	const vector = "0f1adeacacf9a6586aa102432616634e0307bdeb982aa295c0c8862e449b74c8bec6fda53529e58b84f1ad2cc15e481d"
	if hex.EncodeToString(base) != vector {
		t.Fatalf("cross-language transcript vector = %x, want %s", base, vector)
	}

	tests := []struct {
		name  string
		pub   PublicKey
		nonce []byte
		leaf  []byte
		ca    []byte
	}{
		{name: "x25519", pub: PublicKey{X25519: bytes.Repeat([]byte{0x44}, X25519PubBytes), MLKEM768: pub.MLKEM768}, nonce: nonce, leaf: leaf, ca: ca},
		{name: "mlkem", pub: PublicKey{X25519: pub.X25519, MLKEM768: bytes.Repeat([]byte{0x55}, MLKEM768EKBytes)}, nonce: nonce, leaf: leaf, ca: ca},
		{name: "nonce", pub: pub, nonce: bytes.Repeat([]byte{0x66}, identityNonceBytes), leaf: leaf, ca: ca},
		{name: "leaf", pub: pub, nonce: nonce, leaf: []byte("other-leaf"), ca: ca},
		{name: "ca", pub: pub, nonce: nonce, leaf: leaf, ca: []byte("other-ca")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IdentityTranscriptHash(tt.pub, tt.nonce, tt.leaf, tt.ca)
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
	}{
		{name: "nonce short", nonce: make([]byte, 16), serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}},
		{name: "nonce long", nonce: make([]byte, 33), serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}},
		{name: "serving leaf empty", nonce: nonce, leaf: []byte{2}, ca: []byte{3}},
		{name: "mesh leaf empty", nonce: nonce, serving: []byte{1}, ca: []byte{3}},
		{name: "ca empty", nonce: nonce, serving: []byte{1}, leaf: []byte{2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LBTranscriptHash(tc.nonce, tc.serving, tc.leaf, tc.ca); err == nil {
				t.Fatal("invalid transcript input accepted")
			}
		})
	}
}

// TestLBTranscriptGoldenVectors pins the attest-lb transcript encoding against
// the shared cross-repo vectors (copied verbatim into c8s-verify-js and
// TEErminator), so the three parsers cannot drift.
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
	valid := PublicKey{X25519: make([]byte, X25519PubBytes), MLKEM768: make([]byte, MLKEM768EKBytes)}
	for _, tc := range []struct {
		name  string
		pub   PublicKey
		nonce []byte
		leaf  []byte
		ca    []byte
	}{
		{name: "x25519", pub: PublicKey{X25519: make([]byte, 1), MLKEM768: valid.MLKEM768}, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}, ca: []byte{2}},
		{name: "mlkem", pub: PublicKey{X25519: valid.X25519, MLKEM768: make([]byte, 1)}, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}, ca: []byte{2}},
		{name: "nonce", pub: valid, nonce: make([]byte, 16), leaf: []byte{1}, ca: []byte{2}},
		{name: "leaf", pub: valid, nonce: make([]byte, identityNonceBytes), ca: []byte{2}},
		{name: "ca", pub: valid, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := IdentityTranscriptHash(tc.pub, tc.nonce, tc.leaf, tc.ca); err == nil {
				t.Fatal("invalid transcript input accepted")
			}
		})
	}
}
