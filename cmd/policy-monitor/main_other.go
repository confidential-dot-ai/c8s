//go:build !linux

// Command policy-monitor requires Linux; this stub keeps cross-platform
// `go build ./cmd/...` working on non-Linux dev machines (otherwise the
// package has no buildable files and the build errors). It fails closed at
// runtime — the daemon depends on inotify and cgroup-based process control,
// neither of which exists off Linux.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "policy-monitor requires Linux (inotify, cgroup process control)")
	os.Exit(1)
}
