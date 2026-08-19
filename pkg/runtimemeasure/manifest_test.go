package runtimemeasure

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	mrtdHex  = strings.Repeat("1a", Size)
	rtmr1Hex = strings.Repeat("2b", Size)
	rtmr2Hex = strings.Repeat("3c", Size)
)

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadImageManifestValid(t *testing.T) {
	// Extra unknown fields are allowed: build manifests carry other data, and
	// only the three register keys must be unambiguous — a repeated unknown
	// key (and a nested object naming "mrtd") is none of this loader's
	// business.
	p := writeManifest(t, `{
		"schema": 3, "schema": 4,
		"artifacts": {"kernel": "deadbeef", "mrtd": "ignored", "mrtd": "ignored"},
		"mrtd": "`+mrtdHex+`",
		"rtmr1": "`+rtmr1Hex+`",
		"rtmr2": "`+rtmr2Hex+`"
	}`)
	pins, err := LoadImageManifest(p)
	if err != nil {
		t.Fatalf("LoadImageManifest: %v", err)
	}
	for _, reg := range []struct {
		name string
		got  [Size]byte
		want string
	}{
		{"mrtd", pins.MRTD, mrtdHex},
		{"rtmr1", pins.RTMR1, rtmr1Hex},
		{"rtmr2", pins.RTMR2, rtmr2Hex},
	} {
		if hex.EncodeToString(reg.got[:]) != reg.want {
			t.Errorf("%s = %x, want %s", reg.name, reg.got, reg.want)
		}
	}
}

func TestLoadImageManifestRejects(t *testing.T) {
	for _, tc := range []struct{ name, content, wantErr string }{
		{"not json", "not json at all", "not a JSON object"},
		{"json array", `[1,2,3]`, "not a JSON object"},
		{"missing mrtd",
			`{"rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`missing "mrtd"`},
		{"missing rtmr1",
			`{"mrtd":"` + mrtdHex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`missing "rtmr1"`},
		{"missing rtmr2",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `"}`,
			`missing "rtmr2"`},
		{"generic artifact-hash manifest",
			`{"files":{"disk.img":"sha256:abc"}}`,
			"a generic artifact-hash manifest.json is not it"},
		{"bad hex",
			`{"mrtd":"` + strings.Repeat("zz", Size) + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			"lowercase hex"},
		{"uppercase hex",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + strings.ToUpper(rtmr1Hex) + `","rtmr2":"` + rtmr2Hex + `"}`,
			"lowercase hex"},
		{"wrong length",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"aabb"}`,
			"want 96"},
		{"wrong json type", `{"mrtd":7,"rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			"not a JSON object"},
		// encoding/json keeps the LAST value for a repeated key, so a
		// duplicate lets the manifest load as a value other than the one it
		// reads as. Each register must be named exactly once.
		{"duplicate mrtd",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `","mrtd":"` + strings.Repeat("ff", Size) + `"}`,
			`duplicate "mrtd"`},
		{"duplicate rtmr1",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`duplicate "rtmr1"`},
		{"duplicate rtmr2",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`duplicate "rtmr2"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadImageManifest(writeManifest(t, tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// One malformed field must fail the whole load: a partial pin (say MRTD
// without RTMR[2]) would silently verify only part of the image.
func TestLoadImageManifestIsAtomic(t *testing.T) {
	p := writeManifest(t, `{"mrtd":"`+mrtdHex+`","rtmr1":"`+rtmr1Hex+`","rtmr2":"bad"}`)
	pins, err := LoadImageManifest(p)
	if err == nil {
		t.Fatal("want error")
	}
	if pins != (ImagePins{}) {
		t.Error("a failed load must not return partial pins")
	}
}

func TestLoadImageManifestMissingFile(t *testing.T) {
	_, err := LoadImageManifest(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "read image manifest") {
		t.Errorf("error = %v, want a read error", err)
	}
}

// Values from the published rke2-snp-dev manifest for build 9ce1642, whose
// smp2 and smp4 digests were confirmed byte-identical to the MEASUREMENT in
// hardware attestation reports from VMs launched at those vCPU counts.
const (
	snpSMP2Digest = "e9dd4de2ddc59700fa8842fff7e9d80605d433d8d32e8b4112afd761b96506e4e67d97139df5cad76dfa5881c7b11ff5"
	snpSMP4Digest = "a0185a3b93d8a10438fc2c2445edf9908c6de694350a3eaf2f55277d5287fd3532a02994c1e2932809da4147d8b58c97"
)

func snpManifest(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSNPImageManifestValid(t *testing.T) {
	p := snpManifest(t, `{"version":3,"snp_variants":[
	  {"smp":2,"measurement":{"snp_launch_digest":"`+snpSMP2Digest+`","algorithm":"sha384"}},
	  {"smp":4,"measurement":{"snp_launch_digest":"`+snpSMP4Digest+`","algorithm":"sha384"}}]}`)
	pins, err := LoadSNPImageManifest(p)
	if err != nil {
		t.Fatalf("LoadSNPImageManifest: %v", err)
	}
	if len(pins.BySMP) != 2 {
		t.Fatalf("got %d variants, want 2", len(pins.BySMP))
	}
	want2, _ := hex.DecodeString(snpSMP2Digest)
	if got := pins.BySMP[2]; !bytes.Equal(got[:], want2) {
		t.Errorf("smp2 digest = %x, want %s", got, snpSMP2Digest)
	}
	// Both variants are accepted: one image, two legitimate vCPU shapes.
	var d2, d4 [Size]byte
	copy(d2[:], want2)
	w4, _ := hex.DecodeString(snpSMP4Digest)
	copy(d4[:], w4)
	if !pins.Has(d2) || !pins.Has(d4) {
		t.Error("Has must accept every pinned variant")
	}
	var other [Size]byte
	if pins.Has(other) {
		t.Error("Has must reject a digest outside the set")
	}
	// Digests are ordered by SMP so operator-facing output is stable.
	if got := pins.Digests(); len(got) != 2 || !bytes.Equal(got[0][:], want2) {
		t.Errorf("Digests() not in ascending SMP order: %x", got)
	}
}

func TestLoadSNPImageManifestRejects(t *testing.T) {
	cases := map[string]string{
		"no snp_variants (TDX tuple)": `{"mrtd":"` + strings.Repeat("a", 96) + `"}`,
		"empty variant list":          `{"snp_variants":[]}`,
		"zero smp":                    `{"snp_variants":[{"smp":0,"measurement":{"snp_launch_digest":"` + snpSMP2Digest + `","algorithm":"sha384"}}]}`,
		"duplicate smp":               `{"snp_variants":[{"smp":2,"measurement":{"snp_launch_digest":"` + snpSMP2Digest + `","algorithm":"sha384"}},{"smp":2,"measurement":{"snp_launch_digest":"` + snpSMP4Digest + `","algorithm":"sha384"}}]}`,
		"wrong algorithm":             `{"snp_variants":[{"smp":2,"measurement":{"snp_launch_digest":"` + snpSMP2Digest + `","algorithm":"sha256"}}]}`,
		"missing digest":              `{"snp_variants":[{"smp":2,"measurement":{"algorithm":"sha384"}}]}`,
		"missing algorithm":           `{"snp_variants":[{"smp":2,"measurement":{"snp_launch_digest":"` + snpSMP2Digest + `"}}]}`,
		"short digest":                `{"snp_variants":[{"smp":2,"measurement":{"snp_launch_digest":"abcd","algorithm":"sha384"}}]}`,
		"uppercase digest":            `{"snp_variants":[{"smp":2,"measurement":{"snp_launch_digest":"` + strings.ToUpper(snpSMP2Digest) + `","algorithm":"sha384"}}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadSNPImageManifest(snpManifest(t, body)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// The loaders must read a real confos build manifest, not just a hand-written
// pin. These fixtures are verbatim gate artifacts (confos manifest schema
// version 3): the TDX tuple nests under "tdx", the SNP set under
// "snp_variants", and both carry build/inputs/outputs the loaders ignore.
func TestLoadImageManifestReadsConfosBuild(t *testing.T) {
	pins, err := LoadImageManifest("testdata/confos-tdx-manifest.json")
	if err != nil {
		t.Fatalf("LoadImageManifest on a real confos manifest: %v", err)
	}
	const wantMRTD = "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1"
	if got := hex.EncodeToString(pins.MRTD[:]); got != wantMRTD {
		t.Errorf("mrtd = %s, want %s", got, wantMRTD)
	}
	var zero [Size]byte
	if pins.RTMR1 == zero || pins.RTMR2 == zero {
		t.Error("rtmr1/rtmr2 must be read from the nested tdx object")
	}
}

func TestLoadSNPImageManifestReadsConfosBuild(t *testing.T) {
	pins, err := LoadSNPImageManifest("testdata/confos-snp-manifest.json")
	if err != nil {
		t.Fatalf("LoadSNPImageManifest on a real confos manifest: %v", err)
	}
	// The build ships one IGVM per supported vCPU count.
	for _, smp := range []int{2, 4, 8, 16} {
		if _, ok := pins.BySMP[smp]; !ok {
			t.Errorf("no pinned variant for smp %d", smp)
		}
	}
	const wantSMP2 = "e7df3a8f1dbe619607154ce994c1f4d7299c539b120b5560e137f7787e4ece304f270c1444b47c863fde54bc863291d7"
	if got := pins.BySMP[2]; hex.EncodeToString(got[:]) != wantSMP2 {
		t.Errorf("smp2 digest = %x, want %s", got, wantSMP2)
	}
}

// A TDX manifest carries no snp_variants and an SNP manifest no tdx tuple, so
// each loader must reject the other platform's real manifest. This is what
// get-kubeconfig's platform inference rests on.
func TestLoadersRejectTheOtherPlatformsConfosBuild(t *testing.T) {
	if _, err := LoadSNPImageManifest("testdata/confos-tdx-manifest.json"); err == nil {
		t.Error("SNP loader accepted a real TDX manifest")
	}
	if _, err := LoadImageManifest("testdata/confos-snp-manifest.json"); err == nil {
		t.Error("TDX loader accepted a real SNP manifest")
	}
}

// The duplicate-key guard must follow the tuple into the nested object, or a
// nested manifest could name a register twice and load the last value.
func TestLoadImageManifestRejectsDuplicateNestedRegister(t *testing.T) {
	p := writeManifest(t, `{"tdx":{"mrtd":"`+mrtdHex+`","mrtd":"`+strings.Repeat("9f", Size)+`","rtmr1":"`+rtmr1Hex+`","rtmr2":"`+rtmr2Hex+`"}}`)
	if _, err := LoadImageManifest(p); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v, want a duplicate-key rejection", err)
	}
}
