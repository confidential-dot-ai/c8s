#!/bin/sh
set -e

readonly CONTAINERD_CONFIG="${CONTAINERD_CONFIG:-/etc/containerd/config.toml}"
readonly NRI_SOCKET="/var/run/nri/nri.sock"
readonly LOG_PREFIX="[nri-enabler]"
readonly MAX_WAIT=30
readonly WAIT_INTERVAL=2

log()  { echo "${LOG_PREFIX} $*"; }
err()  { echo "${LOG_PREFIX} ERROR: $*" >&2; }

# Run a command on the host via nsenter
host() {
    nsenter --target 1 --mount -- "$@"
}

# Run a command on the host with PID namespace access
host_pid() {
    nsenter --target 1 --mount --pid -- "$@"
}

# Wait for a condition to become true, polling up to MAX_WAIT times
# Usage: wait_for "description" command [args...]
wait_for() {
    _desc="$1"; shift
    _i=0
    while [ "$_i" -lt "$MAX_WAIT" ]; do
        _i=$((_i + 1))
        if "$@" 2>/dev/null; then
            log "${_desc} is ready"
            return 0
        fi
        log "Waiting for ${_desc}... (${_i}/${MAX_WAIT})"
        sleep "$WAIT_INTERVAL"
    done
    err "${_desc} did not become ready within timeout"
    return 1
}

log "Checking NRI status on node $(hostname)"

if host test -S "${NRI_SOCKET}"; then
    log "NRI socket exists, NRI is already enabled"
    exit 0
fi

log "NRI socket not found, enabling NRI in containerd config"
host mkdir -p /var/run/nri /etc/nri/conf.d /opt/nri/plugins

if ! host test -f "${CONTAINERD_CONFIG}"; then
    err "containerd config not found at ${CONTAINERD_CONFIG}"
    exit 1
fi

# Back up containerd config before modifying
host cp "${CONTAINERD_CONFIG}" "${CONTAINERD_CONFIG}.bak"

if host grep -q 'io.containerd.nri.v1.nri' "${CONTAINERD_CONFIG}"; then
    log "NRI config block found, ensuring it is enabled"
    # Only modify the disable flag within the NRI plugin block, not other plugins
    host sed -i '/io.containerd.nri.v1.nri/,/^\[/ s/disable = true/disable = false/' "${CONTAINERD_CONFIG}"
else
    log "Adding NRI config block to containerd"
    host tee -a "${CONTAINERD_CONFIG}" > /dev/null << 'NRIEOF'

[plugins."io.containerd.nri.v1.nri"]
  disable = false
  disable_connections = false
  plugin_config_path = "/etc/nri/conf.d"
  plugin_path = "/opt/nri/plugins"
  socket_path = "/var/run/nri/nri.sock"
NRIEOF
fi

log "Reloading containerd to apply NRI config"
if host_pid systemctl reload containerd 2>/dev/null; then
    log "containerd reload succeeded"
else
    log "Reload not supported, restarting containerd"
    host_pid systemctl restart containerd
fi

wait_for "containerd" host_pid systemctl is-active containerd
wait_for "NRI socket" host test -S "${NRI_SOCKET}"
