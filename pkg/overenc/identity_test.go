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

func TestIdentityTranscriptHashBindsEveryField(t *testing.T) {
	pub := PublicKey{
		X25519:   bytes.Repeat([]byte{0x11}, X25519PubBytes),
		MLKEM768: bytes.Repeat([]byte{0x22}, MLKEM768EKBytes),
	}
	nonce := bytes.Repeat([]byte{0x33}, identityNonceBytes)
	leaf := []byte("leaf-der")
	ca := []byte("ca-der")
	upstream := UpstreamIdentity{
		URL:        "https://backend.other.svc:8443",
		ServerName: "backend.other.svc",
		CAHash:     bytes.Repeat([]byte{0x44}, 32),
	}

	base, err := IdentityTranscriptHash(pub, nonce, leaf, ca, upstream)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != sha512.Size384 {
		t.Fatalf("transcript hash length = %d, want %d", len(base), sha512.Size384)
	}
	const vector = "c2c2828fe4c59ffadb6e4ffc4142f5573a807ec15c58383378622a32743d84ed1ae019e2457c38db5e2caf50aab665f0"
	if hex.EncodeToString(base) != vector {
		t.Fatalf("cross-language transcript vector = %x, want %s", base, vector)
	}

	tests := []struct {
		name     string
		pub      PublicKey
		nonce    []byte
		leaf     []byte
		ca       []byte
		upstream UpstreamIdentity
	}{
		{name: "x25519", pub: PublicKey{X25519: bytes.Repeat([]byte{0x44}, X25519PubBytes), MLKEM768: pub.MLKEM768}, nonce: nonce, leaf: leaf, ca: ca, upstream: upstream},
		{name: "mlkem", pub: PublicKey{X25519: pub.X25519, MLKEM768: bytes.Repeat([]byte{0x55}, MLKEM768EKBytes)}, nonce: nonce, leaf: leaf, ca: ca, upstream: upstream},
		{name: "nonce", pub: pub, nonce: bytes.Repeat([]byte{0x66}, identityNonceBytes), leaf: leaf, ca: ca, upstream: upstream},
		{name: "leaf", pub: pub, nonce: nonce, leaf: []byte("other-leaf"), ca: ca, upstream: upstream},
		{name: "ca", pub: pub, nonce: nonce, leaf: leaf, ca: []byte("other-ca"), upstream: upstream},
		{name: "upstream", pub: pub, nonce: nonce, leaf: leaf, ca: ca, upstream: UpstreamIdentity{URL: "http://attacker.svc:8000", ServerName: upstream.ServerName, CAHash: upstream.CAHash}},
		{name: "upstream server name", pub: pub, nonce: nonce, leaf: leaf, ca: ca, upstream: UpstreamIdentity{URL: upstream.URL, ServerName: "attacker.svc", CAHash: upstream.CAHash}},
		{name: "upstream ca", pub: pub, nonce: nonce, leaf: leaf, ca: ca, upstream: UpstreamIdentity{URL: upstream.URL, ServerName: upstream.ServerName, CAHash: bytes.Repeat([]byte{0x77}, 32)}},
		{name: "upstream emptied", pub: pub, nonce: nonce, leaf: leaf, ca: ca, upstream: UpstreamIdentity{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IdentityTranscriptHash(tt.pub, tt.nonce, tt.leaf, tt.ca, tt.upstream)
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
	upstream := UpstreamIdentity{
		URL:        "https://backend.other.svc:8443",
		ServerName: "backend.other.svc",
		CAHash:     bytes.Repeat([]byte{0x44}, 32),
	}

	base, err := LBTranscriptHash(nonce, serving, leaf, ca, upstream)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != sha512.Size384 {
		t.Fatalf("transcript hash length = %d, want %d", len(base), sha512.Size384)
	}

	tests := []struct {
		name                     string
		nonce, serving, leaf, ca []byte
		upstream                 UpstreamIdentity
	}{
		{name: "nonce", nonce: bytes.Repeat([]byte{0x66}, identityNonceBytes), serving: serving, leaf: leaf, ca: ca, upstream: upstream},
		{name: "serving leaf", nonce: nonce, serving: []byte("other-serving"), leaf: leaf, ca: ca, upstream: upstream},
		{name: "mesh leaf", nonce: nonce, serving: serving, leaf: []byte("other-leaf"), ca: ca, upstream: upstream},
		{name: "ca", nonce: nonce, serving: serving, leaf: leaf, ca: []byte("other-ca"), upstream: upstream},
		{name: "upstream", nonce: nonce, serving: serving, leaf: leaf, ca: ca, upstream: UpstreamIdentity{URL: "http://attacker-svc.attacker.svc.cluster.local:8000"}},
		{name: "upstream server name", nonce: nonce, serving: serving, leaf: leaf, ca: ca, upstream: UpstreamIdentity{URL: upstream.URL, ServerName: "attacker.svc", CAHash: upstream.CAHash}},
		{name: "upstream ca", nonce: nonce, serving: serving, leaf: leaf, ca: ca, upstream: UpstreamIdentity{URL: upstream.URL, ServerName: upstream.ServerName, CAHash: bytes.Repeat([]byte{0x77}, 32)}},
		// Swapping the serving and mesh leaves must change the hash: the
		// per-field positions are load-bearing, not just the field set.
		{name: "serving/mesh swap", nonce: nonce, serving: leaf, leaf: serving, ca: ca, upstream: upstream},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LBTranscriptHash(tt.nonce, tt.serving, tt.leaf, tt.ca, tt.upstream)
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
	upstream := UpstreamIdentity{URL: "http://upstream:8000"}
	for _, tc := range []struct {
		name                     string
		nonce, serving, leaf, ca []byte
		upstream                 UpstreamIdentity
		wantErr                  string
	}{
		{name: "nonce short", nonce: make([]byte, 16), serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}, upstream: upstream, wantErr: "lb transcript nonce must be 32 bytes, got 16"},
		{name: "nonce long", nonce: make([]byte, 33), serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}, upstream: upstream, wantErr: "lb transcript nonce must be 32 bytes, got 33"},
		{name: "serving leaf empty", nonce: nonce, leaf: []byte{2}, ca: []byte{3}, upstream: upstream, wantErr: "lb transcript requires serving leaf, mesh leaf, and CA certificates"},
		{name: "mesh leaf empty", nonce: nonce, serving: []byte{1}, ca: []byte{3}, upstream: upstream, wantErr: "lb transcript requires serving leaf, mesh leaf, and CA certificates"},
		{name: "ca empty", nonce: nonce, serving: []byte{1}, leaf: []byte{2}, upstream: upstream, wantErr: "lb transcript requires serving leaf, mesh leaf, and CA certificates"},
		{name: "upstream ca hash not a SHA-256", nonce: nonce, serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}, upstream: UpstreamIdentity{CAHash: []byte{1, 2, 3}}, wantErr: "upstream CA hash must be 32 bytes, got 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LBTranscriptHash(tc.nonce, tc.serving, tc.leaf, tc.ca, tc.upstream)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
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
		Upstream       string `json:"upstream"`
		UpstreamSNI    string `json:"upstream_server_name"`
		UpstreamCAB64  string `json:"upstream_ca_sha256_b64"`
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
			upstream := UpstreamIdentity{URL: v.Upstream, ServerName: v.UpstreamSNI, CAHash: decode(v.UpstreamCAB64)}
			got, err := LBTranscriptHash(decode(v.NonceB64), decode(v.ServingLeafB64), decode(v.MeshLeafB64), decode(v.MeshCAB64), upstream)
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
	upstream := UpstreamIdentity{URL: "http://upstream:8000"}
	for _, tc := range []struct {
		name     string
		pub      PublicKey
		nonce    []byte
		leaf     []byte
		ca       []byte
		upstream UpstreamIdentity
		wantErr  string
	}{
		{name: "x25519", pub: PublicKey{X25519: make([]byte, 1), MLKEM768: valid.MLKEM768}, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}, ca: []byte{2}, upstream: upstream, wantErr: "identity transcript X25519 key must be 32 bytes, got 1"},
		{name: "mlkem", pub: PublicKey{X25519: valid.X25519, MLKEM768: make([]byte, 1)}, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}, ca: []byte{2}, upstream: upstream, wantErr: "identity transcript ML-KEM key must be 1184 bytes, got 1"},
		{name: "nonce", pub: valid, nonce: make([]byte, 16), leaf: []byte{1}, ca: []byte{2}, upstream: upstream, wantErr: "identity transcript nonce must be 32 bytes, got 16"},
		{name: "leaf", pub: valid, nonce: make([]byte, identityNonceBytes), ca: []byte{2}, upstream: upstream, wantErr: "identity transcript requires leaf and CA certificates"},
		{name: "ca", pub: valid, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}, upstream: upstream, wantErr: "identity transcript requires leaf and CA certificates"},
		{name: "upstream ca hash not a SHA-256", pub: valid, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}, ca: []byte{2}, upstream: UpstreamIdentity{CAHash: []byte{1, 2, 3}}, wantErr: "upstream CA hash must be 32 bytes, got 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := IdentityTranscriptHash(tc.pub, tc.nonce, tc.leaf, tc.ca, tc.upstream)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// UpstreamCABundleHash commits only CERTIFICATE blocks, in file order; a
// bundle without one is "no CA bundle".
func TestUpstreamCABundleHash(t *testing.T) {
	if got := UpstreamCABundleHash([]byte("no pem here")); got != nil {
		t.Fatalf("hash of a certificate-less bundle = %x, want nil", got)
	}
	one := "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----\n"
	two := "-----BEGIN CERTIFICATE-----\nY2EtZGVy\n-----END CERTIFICATE-----\n"
	junk := "-----BEGIN PRIVATE KEY-----\na2V5\n-----END PRIVATE KEY-----\n"
	single := UpstreamCABundleHash([]byte(one))
	chained := UpstreamCABundleHash([]byte(one + junk + two))
	if single == nil || chained == nil {
		t.Fatal("a bundle with CERTIFICATE blocks must hash non-nil")
	}
	if bytes.Equal(single, chained) {
		t.Fatal("appending a second certificate did not change the bundle hash")
	}
	if reordered := UpstreamCABundleHash([]byte(two + one)); bytes.Equal(reordered, chained) {
		t.Fatal("block order must be load-bearing")
	}
	if withJunk := UpstreamCABundleHash([]byte(junk + one)); !bytes.Equal(withJunk, single) {
		t.Fatal("non-CERTIFICATE blocks must not feed the hash")
	}
}
