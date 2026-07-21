//go:build !linux

package workloadclaims

import "net"

// peerPID has no portable implementation off Linux: SO_PEERCRED is Linux-only.
// The broker never runs on non-Linux, but the package (and the c8s CLI that
// imports it, e.g. `c8s verify`) must still build on macOS/Windows for
// operators. Returning 0 is the "no peer credentials" sentinel the node-CVM
// resolver already rejects, so a broker mistakenly built for another OS fails
// closed rather than mis-binding a caller.
func peerPID(net.Conn) int { return 0 }
