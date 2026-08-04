package volume

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCreateDryRun drives the command through cobra so flag validation and the
// build run exactly as they do for an operator, minus the CDS call.
func runCreateDryRun(t *testing.T, dir string, extra ...string) (string, error) {
	t.Helper()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	o := &options{}
	cmd := newCreateCmd(o)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	args := append([]string{
		"--name=weights",
		"--source=" + src,
		"--out=" + filepath.Join(dir, "vol.img"),
		"--path=/tenant-a/volumes/weights",
		"--escrow-out=" + filepath.Join(dir, "escrow.json"),
		"--dry-run",
	}, extra...)
	cmd.SetArgs(args)

	// Build shells out to mkfs.erofs and veritysetup; neither is needed to
	// exercise validation, so a build failure is reported as-is.
	err := cmd.Execute()
	return out.String(), err
}

func TestCreateRejectsOverlongName(t *testing.T) {
	dir := t.TempDir()
	_, err := runCreateDryRun(t, dir, "--name=thirteenchars")
	if err == nil || !strings.Contains(err.Error(), "device serial holds") {
		t.Fatalf("got %v, want a name-length error naming the serial bound", err)
	}
}

func TestCreateRejectsMalformedName(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Weights", "-weights", "weights-", "we/ights"} {
		if _, err := runCreateDryRun(t, dir, "--name="+name); err == nil {
			t.Errorf("name %q: accepted", name)
		}
	}
}

func TestCreateRequiresEscrowOut(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	o := &options{}
	cmd := newCreateCmd(o)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--name=weights", "--source=" + src,
		"--out=" + filepath.Join(dir, "vol.img"),
		"--path=/tenant-a/volumes/weights", "--dry-run",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "escrow-out") {
		t.Fatalf("got %v, want an --escrow-out error", err)
	}
}

func TestCreateRejectsNonCanonicalPath(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"tenant-a/volumes/weights", "/tenant-a/../weights", "/tenant-a/volumes/"} {
		if _, err := runCreateDryRun(t, dir, "--path="+p); err == nil {
			t.Errorf("path %q: accepted", p)
		}
	}
}

// Validation must reject before anything is generated or written: a rejected
// invocation should leave no image and no escrow file behind.
func TestCreateValidationLeavesNoArtifacts(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCreateDryRun(t, dir, "--name=thirteenchars"); err == nil {
		t.Fatal("expected rejection")
	}
	for _, f := range []string{"vol.img", "escrow.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("%s exists after a rejected invocation", f)
		}
	}
}

func TestWriteEscrowRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "escrow.json")
	if err := os.WriteFile(dest, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	blob, err := NewBlob(testKey(), validVerity())
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	if err := writeEscrow(dest, blob); err == nil {
		t.Fatal("overwrote an existing escrow file")
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "existing" {
		t.Fatal("existing escrow file was modified")
	}
}

func TestWriteEscrowIsOwnerOnlyAndReloadable(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "escrow.json")
	blob, err := NewBlob(testKey(), validVerity())
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	if err := writeEscrow(dest, blob); err != nil {
		t.Fatalf("write escrow: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("escrow mode is %o, want 600", perm)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The escrow file is the recovery path, so it has to decode as a blob.
	if _, err := DecodeBlob(raw); err != nil {
		t.Fatalf("escrow file does not decode as a key blob: %v", err)
	}
}

func TestPrintResultNamesSerialAnnotationAndExactGrant(t *testing.T) {
	var out bytes.Buffer
	printResult(&out, createConfig{
		name: "weights", out: "/tmp/vol.img", escrowOut: "/tmp/escrow.json", node: "node-1",
	}, "/tenant-a/volumes/weights", Verity{DataBlocks: 4})
	got := out.String()
	for _, want := range []string{
		"c8s-vol-weights",
		`confidential.ai/c8s-volumes: "weights=/tenant-a/volumes/weights"`,
		"kubernetes.io/hostname: node-1",
		`"read": ["/tenant-a/volumes/weights"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	// A subtree grant would hand over every volume beneath the base.
	if strings.Contains(got, "/**") {
		t.Errorf("output offers a subtree grant:\n%s", got)
	}
}

func TestNewCmdRegistersCreate(t *testing.T) {
	cmd := newCmd(nil)
	var names []string
	for _, c := range cmd.Commands() {
		names = append(names, c.Name())
	}
	if !containsStr(names, "create") {
		t.Fatalf("subcommands = %v, want create", names)
	}
}

func containsStr(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func TestWriteEscrowReportsAnUnwritableDestination(t *testing.T) {
	blob, err := NewBlob(testKey(), validVerity())
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	if err := writeEscrow(filepath.Join(t.TempDir(), "missing-dir", "escrow.json"), blob); err == nil {
		t.Fatal("accepted a path whose directory does not exist")
	}
}
