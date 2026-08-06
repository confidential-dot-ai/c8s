//go:build !linux

// Command volumed requires Linux; this stub keeps cross-platform
// `go build ./cmd/...` working on non-Linux dev machines (otherwise the
// package has no buildable files and the build errors). It fails closed at
// runtime — the daemon depends on device-mapper and mount(2), neither of which
// exists off Linux.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "volumed requires Linux (device-mapper, mount(2))")
	os.Exit(1)
}
