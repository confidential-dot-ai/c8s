#!/bin/bash
# Role dispatch, run by rke2-role.service before any role-gated unit.
# Reads an optional `joindata` disk and stages the RKE2 role, tokens, and
# node addresses. No disk => server (the single-node default).
#
# joindata is host-controlled: worst case is DoS (residual surface: the
# kernel's iso9660 parser; the mount pins the type, ro,nodev,nosuid,noexec).
# Disk text is never sourced or evaluated; a malformed disk fails this unit
# and every role-gated unit stays down.
#
# joindata contract (v0), all files a single <=256-byte ASCII line (edge
# whitespace tolerated and trimmed; interior whitespace rejected):
#   role              server|agent            (both roles)
#   node-ip           routable IPv4           (both roles)
#   node-external-ip  routable IPv4, optional (both roles)
#   server            IPv4, no scheme/port    (agent only; forbidden on server)
#   server-token      64 lowercase hex        (server only; forbidden on agent)
#   agent-token       64 lowercase hex        (both roles)
set -euo pipefail

RUN=/run/confos
DEV=/dev/disk/by-label/joindata
MNT=$RUN/joindata
FRAG=/etc/rancher/rke2/config.yaml.d/50-role.yaml

# Re-dispatch starts clean: a stale verdict or fragment from an earlier run
# this boot must never let both role conditions pass or mix roles.
rm -f "$RUN/role-server" "$RUN/role-agent" \
      "$RUN/rke2-server-token" "$RUN/rke2-agent-token" "$FRAG" \
      "$RUN"/.rke2-*-token.* "${FRAG%/*}/.${FRAG##*/}".*

fail() { echo "rke2-role: $1" >&2; exit 1; }

# read_field FILE — echo the single validated line of MNT/FILE.
read_field() {
    local path="$MNT/$1" line size
    [[ -f "$path" && ! -L "$path" ]] || fail "$1: missing or not a regular file"
    size=$(stat -c%s "$path")
    # Bound before slurping: a huge host file must not fill RAM.
    (( size <= 257 )) || fail "$1: larger than one 256-byte line"
    # tr, not grep: a NUL can't be a grep pattern argument.
    (( $(tr -d '\0' < "$path" | wc -c) == size )) || fail "$1: contains NUL"
    # One line plus an optional trailing newline = at most one newline total.
    (( $(tr -cd '\n' < "$path" | wc -c) <= 1 )) || fail "$1: more than one line"
    IFS= read -r line < "$path" || true
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    (( ${#line} <= 256 )) || fail "$1: line exceeds 256 bytes"
    [[ "$line" == *[[:space:]]* ]] && fail "$1: interior whitespace"
    printf '%s' "$line"
}

is_hex_token() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }

is_ipv4() {
    local ip="$1" o IFS=.
    # No leading zeros: bash arithmetic reads them as octal and rke2's
    # Go-side net.ParseIP rejects them.
    [[ "$ip" =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]] || return 1
    for o in $ip; do (( o <= 255 )) || return 1; done
}

# allow_only NAME... — reject any disk entry outside this role's list.
allow_only() {
    local f name a allowed
    for f in "$MNT"/* "$MNT"/.[!.]* "$MNT"/..?*; do
        # Unmatched globs stay literal; -L keeps dangling symlinks rejectable.
        [[ -e "$f" || -L "$f" ]] || continue
        name=${f##*/}
        allowed=no
        for a in "$@"; do
            if [[ "$name" == "$a" ]]; then allowed=yes; break; fi
        done
        # fixed message: the name is host text
        if [[ "$allowed" != yes ]]; then fail "unexpected file for this role"; fi
    done
}

# write_atomic PATH MODE < content
write_atomic() {
    local dest="$1" mode="$2" tmp
    tmp=$(mktemp "${dest%/*}/.${dest##*/}.XXXXXX")
    cat > "$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$dest"
}

# Common address fields, validated the same way for both roles.
stage_addresses() {
    local node_ip node_ext
    node_ip=$(read_field node-ip)
    is_ipv4 "$node_ip" || fail "node-ip: not IPv4"
    NODE_IP="$node_ip"
    NODE_EXT=""
    # -L: a dangling symlink must be rejected in read_field, not read as absent.
    if [[ -e "$MNT/node-external-ip" || -L "$MNT/node-external-ip" ]]; then
        node_ext=$(read_field node-external-ip)
        is_ipv4 "$node_ext" || fail "node-external-ip: not IPv4"
        NODE_EXT="$node_ext"
    fi
}

# Infallible: runs inside the fragment pipe, where a failure would stage a
# truncated fragment. Everything fallible (stage_addresses) runs before it.
emit_node_addr_lines() {
    printf 'node-ip: %s\n' "$NODE_IP"
    # `if`, not `&&`: a bare `[[…]] && printf` as last statement returns 1
    # when NODE_EXT is empty, aborting the pipe under set -e for every node
    # without an external IP.
    if [[ -n "$NODE_EXT" ]]; then
        printf 'node-external-ip: %s\n' "$NODE_EXT"
    fi
}

set_server_role() {
    local server_token agent_token
    allow_only role node-ip node-external-ip server-token agent-token
    server_token=$(read_field server-token)
    agent_token=$(read_field agent-token)
    is_hex_token "$server_token" || fail "server-token: not 64 lowercase hex"
    is_hex_token "$agent_token" || fail "agent-token: not 64 lowercase hex"
    [[ "$server_token" != "$agent_token" ]] || fail "server-token equals agent-token"
    stage_addresses

    printf '%s' "$server_token" | write_atomic "$RUN/rke2-server-token" 0600
    printf '%s' "$agent_token" | write_atomic "$RUN/rke2-agent-token" 0600
    # No agent-token-file here: rke2-server.service.d/20-role.conf wires it via
    # RKE2_AGENT_TOKEN_FILE for every server boot, disk or legacy alike.
    {
        printf 'token-file: %s\n' "$RUN/rke2-server-token"
        emit_node_addr_lines
    } | write_atomic "$FRAG" 0600
    : > "$RUN/role-server"
}

set_agent_role() {
    local server_addr agent_token
    allow_only role node-ip node-external-ip server agent-token
    server_addr=$(read_field server)
    agent_token=$(read_field agent-token)
    is_ipv4 "$server_addr" || fail "server: not IPv4"
    is_hex_token "$agent_token" || fail "agent-token: not 64 lowercase hex"
    stage_addresses

    printf '%s' "$agent_token" | write_atomic "$RUN/rke2-agent-token" 0600
    {
        printf 'token-file: %s\n' "$RUN/rke2-agent-token"
        printf 'server: https://%s:9345\n' "$server_addr"
        emit_node_addr_lines
    } | write_atomic "$FRAG" 0600
    : > "$RUN/role-agent"
}

# No-disk fallback: legacy single-node server. Generate a boot-local agent
# token so RKE2 doesn't alias agent-token to the privileged server token;
# 20-role.conf wires it via RKE2_AGENT_TOKEN_FILE, same as the disk path.
set_legacy_server_role() {
    local token
    token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n') || fail "token generation failed"
    is_hex_token "$token" || fail "generated agent token malformed"
    printf '%s' "$token" | write_atomic "$RUN/rke2-agent-token" 0600
    : > "$RUN/role-server"
}

# Drain the udev queue so a late disk can't default an agent boot to server.
# A settle timeout fails the unit (possible on a busy diskless boot); recover
# with `systemctl restart rke2-role rke2-server` — failed units aren't retried.
[[ -e "$DEV" ]] || udevadm settle --timeout=10

if [[ ! -e "$DEV" ]]; then
    set_legacy_server_role
    echo "rke2-role: no joindata disk, defaulting to server"
    exit 0
fi

mkdir -p "$MNT"
# Host-controlled device: pin the fs parser, bound a wedged mount.
timeout 10 mount -t iso9660 -o ro,nodev,nosuid,noexec "$DEV" "$MNT"
trap 'umount "$MNT" 2>/dev/null || true' EXIT

role=$(read_field role)
case "$role" in
server) set_server_role ;;
agent)  set_agent_role ;;
*)      fail "invalid role" ;;  # fixed message: the value is host text
esac
echo "rke2-role: role=${role}"
