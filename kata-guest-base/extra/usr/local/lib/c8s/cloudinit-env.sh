#!/bin/sh
# Materialise /run/c8s/ratls-mesh.env from cloud-init's user-data.
#
# Invoked by c8s-cloudinit-env.service after cloud-init.service has
# finished writing /etc/c8s/cloudinit.env from the pod's NoCloud
# user-data.
#
# The two-file dance:
#   cloud-init's write_files                 (per pod, host-injected)
#     -> /etc/c8s/cloudinit.env              (on the verity/overlay)
#       -> this script
#         -> /run/c8s/ratls-mesh.env         (on tmpfs)
#           -> EnvironmentFile= in ratls-mesh.service
#
# We pass the cloud-init values through verbatim — no parsing or
# validation. The C8S_* surface is a contract with S4 (the binary that
# reads it); validation lives there.

set -eu

SRC="/etc/c8s/cloudinit.env"
DST_DIR="/run/c8s"
DST="${DST_DIR}/ratls-mesh.env"

mkdir -p "${DST_DIR}"

if [ ! -f "${SRC}" ]; then
    echo "c8s-cloudinit-env: ${SRC} missing" >&2
    echo "c8s-cloudinit-env: did the pod's cloud-init user-data set write_files?" >&2
    # Emit an empty env file so ratls-mesh.service still loads (and
    # immediately fails its readiness-check because C8S_CDS_URL is
    # unset). Failing here would leave dependent units in a confusing
    # state — ratls-mesh would never get the chance to surface the
    # actual error.
    : > "${DST}"
    exit 0
fi

# Copy verbatim. Mode 0644: world-readable is fine — the file contains
# URLs and workload IDs, not secrets (secrets are minted in-guest via
# RA-TLS and never appear in cloud-init payloads, which the host can
# see).
install -m 0644 "${SRC}" "${DST}"
echo "c8s-cloudinit-env: wrote ${DST} from ${SRC}"
