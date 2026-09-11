package launchdata

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLaunchData builds a launchdata dir from name → content.
func writeLaunchData(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var launchDataGoldenFiles = map[string]string{
	"cds-url":           "x\n",
	"measurements.json": "hello\n",
}

const launchDataGoldenManifest = "confai-launchdata v1\n" +
	"73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac  cds-url\n" +
	"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  measurements.json\n"

// Golden vectors pin the launchdata v1 commitment, shared with the host-side
// commitment script and the guest's binding. Treat a failure here as a
// breaking change to the attestation contract, not a test to update.
func TestLaunchDataGoldenVectors(t *testing.T) {
	manifest, err := LaunchDataManifest(writeLaunchData(t, launchDataGoldenFiles))
	if err != nil {
		t.Fatal(err)
	}
	if string(manifest) != launchDataGoldenManifest {
		t.Fatalf("manifest = %q, want %q", manifest, launchDataGoldenManifest)
	}
	hostData := LaunchDataHostData(manifest)
	if got, want := base64.StdEncoding.EncodeToString(hostData[:]),
		"l9mAn9EWM0JXp+PBxyie7HDgHKEVh97xoga3y2ERkVM="; got != want {
		t.Errorf("hostdata = %s, want %s", got, want)
	}
	id := LaunchDataMRConfigID(manifest)
	if got, want := hex.EncodeToString(id[:]),
		"ef38ad0a367d8e2d01518ff18120de70366ea5a721d10e4e8f424078c7cbff621e996650f9973c31396e633d3a48e67d"; got != want {
		t.Errorf("MRCONFIGID = %s, want %s", got, want)
	}
}

func TestLaunchDataManifestSkipsDotfiles(t *testing.T) {
	files := map[string]string{".hidden": "sneaky\n"}
	for name, content := range launchDataGoldenFiles {
		files[name] = content
	}
	manifest, err := LaunchDataManifest(writeLaunchData(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if string(manifest) != launchDataGoldenManifest {
		t.Errorf("manifest = %q, want the dotfile-free golden manifest", manifest)
	}
}

func TestLaunchDataManifestSortsByFilenameByteOrder(t *testing.T) {
	dir := t.TempDir()
	// Created in the reverse of C order; "Z" < "a" bytewise.
	for _, name := range []string{"tls-san", "cds-url", "Z-upper"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := LaunchDataManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(manifest), "\n"), "\n")
	want := []string{"Z-upper", "cds-url", "tls-san"}
	if len(lines) != 1+len(want) {
		t.Fatalf("manifest has %d lines, want %d: %q", len(lines), 1+len(want), manifest)
	}
	for i, name := range want {
		if got := lines[1+i]; !strings.HasSuffix(got, "  "+name) {
			t.Errorf("line %d = %q, want it to name %q", 1+i, got, name)
		}
	}
}

func TestLaunchDataManifestRejects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr string
	}{
		{"empty dir",
			func(t *testing.T) string { return t.TempDir() },
			"no files to commit"},
		{"only dotfiles",
			func(t *testing.T) string {
				return writeLaunchData(t, map[string]string{".hidden": "x\n"})
			},
			"no files to commit"},
		{"subdirectory",
			func(t *testing.T) string {
				dir := writeLaunchData(t, launchDataGoldenFiles)
				if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			`"subdir" is not a regular file`},
		{"symlink",
			func(t *testing.T) string {
				dir := writeLaunchData(t, launchDataGoldenFiles)
				if err := os.Symlink("cds-url", filepath.Join(dir, "link")); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			`"link" is not a regular file`},
		{"missing dir",
			func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") },
			"read launchdata dir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LaunchDataManifest(tc.setup(t))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestLaunchDataManifestRejectsHostileName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a b"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LaunchDataManifest(dir); err == nil || !strings.Contains(err.Error(), "characters outside") {
		t.Fatalf("err = %v, want charset rejection", err)
	}
}

func TestLoadLaunchData(t *testing.T) {
	files := map[string]string{"operator-pubkey": "hello\n"}
	for name, data := range launchDataGoldenFiles {
		files[name] = data
	}
	manifest, pub, err := LoadLaunchData(writeLaunchData(t, files))
	if err != nil {
		t.Fatal(err)
	}
	want := launchDataGoldenManifest + "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  operator-pubkey\n"
	if string(manifest) != want || string(pub) != "hello\n" {
		t.Fatalf("manifest = %q, pub = %q; want the committed key bytes and golden manifest", manifest, pub)
	}
}

func TestLoadLaunchDataRequiresOperatorKey(t *testing.T) {
	for _, empty := range []bool{false, true} {
		files := map[string]string{"measurements.json": "{}"}
		if empty {
			files["operator-pubkey"] = ""
		}
		manifest, pub, err := LoadLaunchData(writeLaunchData(t, files))
		if err == nil || !strings.Contains(err.Error(), "operator-pubkey") || manifest != nil || pub != nil {
			t.Fatalf("empty=%v: manifest=%q, pub=%q, err=%v; want missing/empty key refusal", empty, manifest, pub, err)
		}
	}
}
