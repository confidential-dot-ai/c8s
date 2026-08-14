package initdata

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The spike vector: this exact byte sequence was delivered to a live SEV-SNP
// guest and its sha256 read back out of the AMD-signed report's HOST_DATA
// (docs/kata-image-policy.md — "Allowlist sourcing"). Any change to Render
// that breaks it breaks the binding on hardware.
const (
	spikeRaw = "version = \"0.1.0\"\n" +
		"algorithm = \"sha256\"\n" +
		"\n" +
		"[data]\n" +
		"\"spike.txt\" = \"c8s-initdata-spike-2026-08-03\"\n"

	spikeDigestHex = "474758eb7ec59a416dbc52b954e7bcbdc2efb0665fbf42dc390ab2a607effc2b"
)

func TestRenderMatchesHardwareConfirmedVector(t *testing.T) {
	built, err := New(map[string]string{"spike.txt": "c8s-initdata-spike-2026-08-03"}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if string(built.Raw) != spikeRaw {
		t.Errorf("Raw =\n%q\nwant\n%q", built.Raw, spikeRaw)
	}
	if got := hex.EncodeToString(built.Digest[:]); got != spikeDigestHex {
		t.Errorf("Digest = %s, want %s", got, spikeDigestHex)
	}
}

func TestDigestIsOverRawBytes(t *testing.T) {
	if got := hex.EncodeToString(digestHex(Digest([]byte(spikeRaw)))); got != spikeDigestHex {
		t.Errorf("Digest(spikeRaw) = %s, want %s", got, spikeDigestHex)
	}
}

func digestHex(d [DigestSize]byte) []byte { return d[:] }

func TestAnnotationRoundTrip(t *testing.T) {
	doc := New(map[string]string{
		KeyRole:                   RoleCDS,
		KeyCDSAllowlistSeedSHA256: strings.Repeat("ab", 32),
		KeyCDSOperatorKeysSHA256:  strings.Repeat("cd", 32),
	})
	built, err := doc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	decoded, err := Decode(built.Annotation)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(decoded) != string(built.Raw) {
		t.Fatalf("Decode(Annotation) =\n%q\nwant\n%q", decoded, built.Raw)
	}
	if Digest(decoded) != built.Digest {
		t.Error("digest of decoded annotation differs from Built.Digest")
	}

	parsed, err := Parse(built.Raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Version != Version || parsed.Algorithm != AlgorithmSHA256 {
		t.Errorf("Parse header = %q/%q", parsed.Version, parsed.Algorithm)
	}
	for k, want := range doc.Data {
		if got := parsed.Data[k]; got != want {
			t.Errorf("Parse Data[%q] = %q, want %q", k, got, want)
		}
	}
	if len(parsed.Data) != len(doc.Data) {
		t.Errorf("Parse Data has %d entries, want %d", len(parsed.Data), len(doc.Data))
	}
}

func TestRenderIsDeterministicAndSorted(t *testing.T) {
	data := map[string]string{"zz": "1", "aa": "2", "mm": "3"}
	first, err := New(data).Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for range 20 {
		again, err := New(data).Render()
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if string(again) != string(first) {
			t.Fatalf("Render is not deterministic:\n%q\n%q", first, again)
		}
	}
	want := "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"aa\" = \"2\"\n\"mm\" = \"3\"\n\"zz\" = \"1\"\n"
	if string(first) != want {
		t.Errorf("Render =\n%q\nwant\n%q", first, want)
	}
}

func TestValidateAlgorithmRejectsShimPanicValues(t *testing.T) {
	// kata's shim switches on the algorithm with no default arm and then hashes
	// unconditionally, so anything unrecognised panics the shim.
	for _, alg := range []string{"", "sha384", "sha512", "SHA256", "sha-256", "md5"} {
		if err := ValidateAlgorithm(alg); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("ValidateAlgorithm(%q) = %v, want ErrUnsupportedAlgorithm", alg, err)
		}
	}
	if err := ValidateAlgorithm(AlgorithmSHA256); err != nil {
		t.Errorf("ValidateAlgorithm(sha256) = %v", err)
	}
}

func TestBuildRejectsBadDocuments(t *testing.T) {
	tests := []struct {
		name string
		doc  Document
		want error
	}{
		{"wrong version", Document{Version: "0.2.0", Algorithm: AlgorithmSHA256, Data: map[string]string{"a": "b"}}, ErrUnsupportedVersion},
		{"empty version", Document{Algorithm: AlgorithmSHA256, Data: map[string]string{"a": "b"}}, ErrUnsupportedVersion},
		{"bad algorithm", Document{Version: Version, Algorithm: "sha384", Data: map[string]string{"a": "b"}}, ErrUnsupportedAlgorithm},
		{"empty data", Document{Version: Version, Algorithm: AlgorithmSHA256}, ErrMalformed},
		{"quote in value", New(map[string]string{"a": `b"c`}), ErrUnrepresentable},
		{"backslash in value", New(map[string]string{"a": `b\c`}), ErrUnrepresentable},
		{"newline in value", New(map[string]string{"a": "b\nc"}), ErrUnrepresentable},
		{"empty value", New(map[string]string{"a": ""}), ErrUnrepresentable},
		{"space in key", New(map[string]string{"a b": "c"}), ErrUnrepresentable},
		{"equals in key", New(map[string]string{"a=b": "c"}), ErrUnrepresentable},
		{"quote in key", New(map[string]string{`a"b`: "c"}), ErrUnrepresentable},
		{"empty key", New(map[string]string{"": "c"}), ErrUnrepresentable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.doc.Build(); !errors.Is(err, tt.want) {
				t.Errorf("Build() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseRejectsAnythingOutsideTheRenderedSubset(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"no trailing newline", strings.TrimSuffix(spikeRaw, "\n"), ErrMalformed},
		{"invalid utf8", "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"a\" = \"\xff\"\n", ErrMalformed},
		{"no data section", "version = \"0.1.0\"\nalgorithm = \"sha256\"\n", ErrMalformed},
		{"empty data section", "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n", ErrMalformed},
		{"duplicate data section", "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"a\" = \"b\"\n[data]\n", ErrMalformed},
		{"duplicate key", "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"a\" = \"b\"\n\"a\" = \"c\"\n", ErrMalformed},
		{"duplicate version", "version = \"0.1.0\"\nversion = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"a\" = \"b\"\n", ErrMalformed},
		{"unknown header key", "version = \"0.1.0\"\nalgorithm = \"sha256\"\nextra = \"x\"\n\n[data]\n\"a\" = \"b\"\n", ErrMalformed},
		{"unquoted data key", "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\na = \"b\"\n", ErrMalformed},
		{"unquoted value", "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"a\" = b\n", ErrMalformed},
		{"loose spacing", "version=\"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"a\" = \"b\"\n", ErrMalformed},
		{"bad version", "version = \"9.9.9\"\nalgorithm = \"sha256\"\n\n[data]\n\"a\" = \"b\"\n", ErrUnsupportedVersion},
		{"bad algorithm", "version = \"0.1.0\"\nalgorithm = \"sha512\"\n\n[data]\n\"a\" = \"b\"\n", ErrUnsupportedAlgorithm},
		{"other toml table", "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"a\" = \"b\"\n[other]\n", ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.raw)); !errors.Is(err, tt.want) {
				t.Errorf("Parse() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, tt := range []struct{ name, in string }{
		{"not base64", "!!!!"},
		{"not gzip", "aGVsbG8="},
		{"empty", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(tt.in); !errors.Is(err, ErrMalformed) {
				t.Errorf("Decode(%q) = %v, want ErrMalformed", tt.in, err)
			}
		})
	}
}

func TestDecodeRejectsOversizedDocument(t *testing.T) {
	built, err := New(map[string]string{"a": strings.Repeat("x", maxDecodedSize+1)}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := Decode(built.Annotation); !errors.Is(err, ErrMalformed) {
		t.Errorf("Decode(oversized) = %v, want ErrMalformed", err)
	}
}

func TestParseAcceptsEveryDocumentBuildEmits(t *testing.T) {
	docs := []Document{
		New(map[string]string{KeyRole: RoleWorkload, KeyCDSMeasurements: strings.Repeat("ab", 48)}),
		New(map[string]string{KeyRole: RoleCDS}),
		New(map[string]string{"spike.txt": "c8s-initdata-spike-2026-08-03"}),
		New(map[string]string{"a/b_c-d.e": "value with spaces, commas and = signs"}),
	}
	for _, doc := range docs {
		built, err := doc.Build()
		if err != nil {
			t.Fatalf("Build(%v): %v", doc.Data, err)
		}
		parsed, err := Parse(built.Raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", built.Raw, err)
		}
		for k, want := range doc.Data {
			if parsed.Data[k] != want {
				t.Errorf("round trip Data[%q] = %q, want %q", k, parsed.Data[k], want)
			}
		}
	}
}
