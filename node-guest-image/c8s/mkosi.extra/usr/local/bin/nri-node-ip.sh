#!/bin/sh
# Write this node's address where nri-image-policy looks for it.
#
# The plugin's admission inventory advertises an address CDS dials back on
# (workload_claims.advertise_host). On a Kubernetes-hosted install the chart's
# installer DaemonSet writes it from its own status.hostIP. A node-as-CVM has
# no such installer — the plugin is a containerd child on the host — so with
# the value unset it resolves to 127.0.0.1 and the plugin refuses to start:
#
#   workloadclaims: inventory host "127.0.0.1" is not a routable unicast address
#
# The address is a dial target, not a trust input. CDS still requires whatever
# answers to pass mutually-attested RA-TLS on a privileged port, so naming the
# wrong one fails closed rather than opening anything.
set -eu

DIR=/var/run/nri-image-policy
# The plugin creates this at startup, but this unit is ordered before rke2
# brings containerd up, so it does not exist yet.
mkdir -p "$DIR"

# The source address of the default route: the one interface a CDS elsewhere in
# the cluster can reach. `ip route get` resolves it without assuming an
# interface name, which differs across launch shapes.
ADDR=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)

if [ -z "$ADDR" ]; then
    # No default route yet. Leave the file absent rather than writing a
    # loopback address: the plugin's own check rejects that with a message
    # naming the cause, which beats advertising an address nothing can reach.
    echo "nri-node-ip: no IPv4 default route; leaving $DIR/node-ip unwritten" >&2
    exit 0
fi

printf '%s\n' "$ADDR" > "$DIR/node-ip"
echo "nri-node-ip: advertised $ADDR"
