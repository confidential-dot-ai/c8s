//go:build !linux

package workloadclaims

import "net"

// Peer is the non-Linux stub: SO_PEERCRED/SO_PEERPIDFD are Linux-only. The
// inventory never runs off Linux, but the package (and the c8s CLI that imports
// it, e.g. `c8s verify`) must still build on macOS/Windows for operators. A
// zero-PID Peer is the "no peer credentials" sentinel the node-CVM resolver
// rejects, so an inventory mistakenly built for another OS fails closed rather
// than mis-binding a caller.
type Peer struct{ pid int }

func peerFrom(net.Conn) Peer { return Peer{} }

// PID returns the peer's PID (always 0 off Linux).
func (p Peer) PID() int { return p.pid }

// IsAlive is a no-op true off Linux; PID 0 is rejected upstream regardless, and
// the inventory never runs on a non-Linux host.
func (Peer) IsAlive() bool { return true }

// Close is a no-op off Linux.
func (Peer) Close() {}

// PeerForPID builds a Peer from an out-of-band PID (tests). See the Linux
// implementation for the production path.
func PeerForPID(pid int) Peer { return Peer{pid: pid} }
