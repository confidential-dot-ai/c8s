package tdxrtmr

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// fakeSysfs points SysfsRoot at a temp dir for the test and returns it.
func fakeSysfs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := SysfsRoot
	SysfsRoot = dir
	t.Cleanup(func() { SysfsRoot = orig })
	return dir
}

func TestPath(t *testing.T) {
	dir := fakeSysfs(t)
	if got, want := Path(3), filepath.Join(dir, "rtmr3:sha384"); got != want {
		t.Errorf("Path(3) = %q, want %q", got, want)
	}
}

func TestRead(t *testing.T) {
	value := runtimemeasure.Event("sha256:" + strings.Repeat("ab", 32))
	for _, tc := range []struct {
		name  string
		index int
		node  []byte // nil: no node written
		want  string // "" = must succeed with value
	}{
		{"rtmr3", 3, value[:], ""},
		{"rtmr0", 0, value[:], ""},
		{"short node", 3, value[:47], "got 47 bytes, want 48"},
		{"long node", 3, append(value[:], 0), "got 49 bytes, want 48"},
		{"missing node", 3, nil, "is this a TDX guest"},
		{"index too high", 4, value[:], "does not exist"},
		{"negative index", -1, value[:], "does not exist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := fakeSysfs(t)
			if tc.node != nil {
				name := "rtmr3:sha384"
				if tc.index >= 0 && tc.index <= 3 {
					name = filepath.Base(Path(tc.index))
				}
				if err := os.WriteFile(filepath.Join(dir, name), tc.node, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Read(tc.index)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Read(%d) error = %v, want it to contain %q", tc.index, err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("Read(%d): %v", tc.index, err)
			}
			if got != value {
				t.Errorf("Read(%d) = %x, want %x", tc.index, got, value)
			}
		})
	}
}

func TestExtend(t *testing.T) {
	event := runtimemeasure.ModeDynamic
	for _, tc := range []struct {
		name  string
		index int
		node  bool // create the node first
		want  string
	}{
		{"rtmr3", 3, true, ""},
		{"rtmr2", 2, true, ""},
		{"rtmr1 is firmware-owned", 1, true, "not guest-extendable"},
		{"rtmr0 is firmware-owned", 0, true, "not guest-extendable"},
		{"index too high", 4, true, "not guest-extendable"},
		{"missing node under an existing root", 3, false, "extend "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := fakeSysfs(t)
			if tc.node {
				if err := os.WriteFile(filepath.Join(dir, filepath.Base(Path(tc.index))), make([]byte, runtimemeasure.Size), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := Extend(tc.index, event)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Extend(%d) error = %v, want it to contain %q", tc.index, err, tc.want)
				}
				// A failed extend must leave no file behind: a created node
				// would read back as a register on the next call.
				if !tc.node {
					if _, statErr := os.Stat(Path(tc.index)); !os.IsNotExist(statErr) {
						t.Errorf("os.Stat(%s) after a failed Extend = %v, want not-exist", Path(tc.index), statErr)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Extend(%d): %v", tc.index, err)
			}
			// The fake node records the last event written; the real TSM node
			// folds it. Either way the bytes that reached the node are the event.
			got, err := os.ReadFile(Path(tc.index))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, event[:]) {
				t.Errorf("node after Extend(%d) = %x, want %x", tc.index, got, event)
			}
		})
	}
}
