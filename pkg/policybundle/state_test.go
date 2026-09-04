package policybundle

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadDir(t *testing.T) {
	doc := []byte(`{"schema":"c8s.allowlist/v1","digests":{},"workloads":{}}`)
	bundle := mustBundle(t, map[string][]byte{MemberStaticAllowlist: doc})
	sum := bundle.IndexDigest()
	digest := hex.EncodeToString(sum[:])
	static := func(extra map[string][]byte) map[string][]byte {
		files := map[string][]byte{ModeFile: []byte("static\n"), DigestFile: []byte(digest), MemberStaticAllowlist: doc}
		for name, data := range extra {
			files[name] = data
		}
		return files
	}
	for _, tc := range []struct {
		name     string
		files    map[string][]byte
		wantMode string
		wantErr  string
	}{
		{"dynamic", map[string][]byte{ModeFile: []byte("dynamic\n")}, DynamicMode, ""},
		{"dynamic without newline", map[string][]byte{ModeFile: []byte("dynamic")}, DynamicMode, ""},
		{"static", static(nil), StaticMode, ""},
		{"static with a newline after the digest", static(map[string][]byte{DigestFile: []byte(digest + "\n")}), StaticMode, ""},
		{"mode missing", map[string][]byte{}, "", "did c8s-policy-measure.service run"},
		{"mode unknown", map[string][]byte{ModeFile: []byte("sealed\n")}, "", `holds "sealed"`},
		{"mode empty", map[string][]byte{ModeFile: []byte("")}, "", `holds ""`},
		{"static without members", map[string][]byte{ModeFile: []byte("static\n"), DigestFile: []byte(digest)}, "", "no static-allowlist.json member"},
		{"static without digest", map[string][]byte{ModeFile: []byte("static\n"), MemberStaticAllowlist: doc}, "", "policy digest"},
		{"digest rewritten", static(map[string][]byte{DigestFile: []byte(strings.Repeat("0", 64))}), "", "members index to"},
		{"member rewritten after measurement", static(map[string][]byte{MemberStaticAllowlist: append(doc, ' ')}), "", "members index to"},
		{"unknown member added", static(map[string][]byte{"extra.json": []byte("{}")}), "", `member "extra.json" is unknown`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, data := range tc.files {
				writeFile(t, filepath.Join(dir, name), data)
			}
			state, err := ReadDir(dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ReadDir(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadDir(%s) = %v, want nil", tc.name, err)
			}
			if state.Mode != tc.wantMode {
				t.Errorf("ReadDir(%s).Mode = %q, want %q", tc.name, state.Mode, tc.wantMode)
			}
			if tc.wantMode == DynamicMode {
				if state.Bundle.Members != nil {
					t.Errorf("ReadDir(%s) = %+v, want no bundle on a dynamic boot", tc.name, state)
				}
				return
			}
			if state.Bundle.IndexDigest() != sum || state.Bundle.RTMR3() != bundle.RTMR3() {
				t.Errorf("ReadDir(%s) = digest %x, RTMR3 %x; want %s and the measured bundle's register", tc.name, state.Bundle.IndexDigest(), state.Bundle.RTMR3(), digest)
			}
		})
	}
	t.Run("non-regular entry", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, ModeFile), []byte("static\n"))
		if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadDir(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("ReadDir(subdir) = %v, want not-a-regular-file error", err)
		}
	})
	t.Run("oversized member", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, ModeFile), []byte("static\n"))
		writeFile(t, filepath.Join(dir, MemberStaticAllowlist), make([]byte, MaxMemberSize+1))
		if _, err := ReadDir(dir); err == nil || !strings.Contains(err.Error(), "over") {
			t.Fatalf("ReadDir(oversized) = %v, want a size error", err)
		}
	})
}
