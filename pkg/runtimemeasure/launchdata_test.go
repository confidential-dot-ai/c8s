package runtimemeasure

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
	reg := Extend(Zero, LaunchDataRTMR3Digest(manifest))
	if got, want := hex.EncodeToString(reg[:]),
		"eb31a30767c2ab305b93ae9846e07059c24aae96995b2b2c28193d451378a0ff3bc45636447932e792a6e767f6508280"; got != want {
		t.Errorf("RTMR[3] = %s, want %s", got, want)
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
