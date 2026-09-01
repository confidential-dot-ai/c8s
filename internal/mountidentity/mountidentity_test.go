//go:build linux

package mountidentity

import (
	"os"
	"testing"
)

func TestObserveRequiresAnExactCanonicalMountPoint(t *testing.T) {
	evidence, err := Observe("/proc")
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Canonical || !evidence.Mountpoint || evidence.Filesystem == 0 {
		t.Fatalf("/proc evidence = %+v", evidence)
	}
	dir := t.TempDir()
	evidence, err = Observe(dir)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Mountpoint {
		t.Fatalf("ordinary directory was reported as a mount point: %+v", evidence)
	}
	link := dir + "-link"
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	evidence, err = Observe(link)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Canonical {
		t.Fatalf("symlink source was reported as canonical: %+v", evidence)
	}
}

func TestUnescapeMountInfo(t *testing.T) {
	if got, want := unescapeMountInfo(`/a\040b\011c\134d`), "/a b\tc\\d"; got != want {
		t.Fatalf("unescapeMountInfo = %q, want %q", got, want)
	}
}
