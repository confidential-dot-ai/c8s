//go:build !linux

package main

import (
	"fmt"
	"net"
)

// defaultOrigDstFunc is a stub for non-Linux platforms. SO_ORIGINAL_DST is
// Linux-only. In tests, override Proxy.origDstFunc with a custom function.
func defaultOrigDstFunc(_ net.Conn) (string, error) {
	return "", fmt.Errorf("origdst: SO_ORIGINAL_DST not available on this platform")
}
