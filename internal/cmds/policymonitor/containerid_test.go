//go:build linux

package policymonitor

import (
	"path/filepath"
	"testing"
)

func TestPathLooksLikeContainer(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	for _, tc := range []struct {
		path string
		want bool
	}{
		{filepath.Join(watchDir, testCID("child")), true},
		{filepath.Join(watchDir, "aa_1.b"), false},                            // not a 64-hex id
		{filepath.Join(watchDir, "init"), false},                              // a systemd unit cgroup name
		{filepath.Join(watchDir, "shared"), false},                            // kata's own dir, never a container
		{filepath.Join(watchDir, "deep", "nested", testCID("nested")), false}, // not a direct child
		{filepath.Join(watchDir, ""), false},                                  // empty
		{watchDir, false},                                                     // the watch dir itself
	} {
		got := m.pathLooksLikeContainer(tc.path)
		if got != tc.want {
			t.Errorf("pathLooksLikeContainer(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
