package types

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWhitelistListResponseJSONRoundtrip(t *testing.T) {
	raw := `{"version":"3","digests":{"sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2":"docker.io/nginx:latest"}}`

	var resp WhitelistListResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Version != "3" {
		t.Fatalf("version: got %q, want %q", resp.Version, "3")
	}

	d, err := ParseDigest("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}

	img, ok := resp.Digests[d]
	if !ok {
		t.Fatal("digest key not found")
	}
	if img != "docker.io/nginx:latest" {
		t.Fatalf("image: got %q, want %q", img, "docker.io/nginx:latest")
	}

	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// Verify roundtrip by unmarshalling both and comparing
	var original, roundtripped map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &original); err != nil {
		t.Fatalf("unmarshal original: %v", err)
	}
	if err := json.Unmarshal(out, &roundtripped); err != nil {
		t.Fatalf("unmarshal roundtripped: %v", err)
	}

	origBytes, _ := json.Marshal(original)
	rtBytes, _ := json.Marshal(roundtripped)
	if string(origBytes) != string(rtBytes) {
		t.Fatalf("roundtrip mismatch:\n  got:  %s\n  want: %s", rtBytes, origBytes)
	}
}

func TestWhitelistAddRequestJSONRoundtrip(t *testing.T) {
	d, err := ParseDigest("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}

	req := WhitelistAddRequest{
		Digest: d,
		Image:  "docker.io/nginx:latest",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded WhitelistAddRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Digest.String() != d.String() {
		t.Fatalf("digest: got %q, want %q", decoded.Digest.String(), d.String())
	}
	if decoded.Image != "docker.io/nginx:latest" {
		t.Fatalf("image: got %q, want %q", decoded.Image, "docker.io/nginx:latest")
	}
}

func TestWhitelistDeleteRequestJSONRoundtrip(t *testing.T) {
	d, err := ParseDigest("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}

	req := WhitelistDeleteRequest{Digests: []Digest{d}}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded WhitelistDeleteRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(decoded.Digests) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(decoded.Digests))
	}
	if decoded.Digests[0].String() != d.String() {
		t.Fatalf("digest: got %q, want %q", decoded.Digests[0].String(), d.String())
	}
}

func TestWhitelistAddRequestRejectsUnknownFields(t *testing.T) {
	raw := `{"digest":"sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","image":"nginx","extra":"field"}`

	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()

	var req WhitelistAddRequest
	if err := dec.Decode(&req); err == nil {
		t.Fatal("expected error for unknown field")
	}
}
