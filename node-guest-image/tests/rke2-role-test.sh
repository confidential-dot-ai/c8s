#!/bin/bash
# Runs the byte-exact production rke2-role.sh (its own `set -euo pipefail`,
# never a weakened copy) against real ISO9660 loop devices: happy paths, the
# full rejection matrix, re-dispatch, injection, write-boundary fault shims,
# token-leak greps. Unit gating lives in rke2-role-systemd-test.sh.
#
# Needs root and genisoimage; mutates /run/confos and /etc/rancher/rke2 —
# run `make test-node-guest-image-role` on a disposable machine, or in a
# privileged debian:12 container (+ e2fsprogs udev).
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${RKE2_ROLE_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/rke2-role.sh"}
WORK=/tmp/rke2-role-test-work
SHIMDIR=/tmp/rke2-role-test-shims
FAULTDIR=/tmp/rke2-role-test-fault

[[ $EUID -eq 0 ]] || { echo "must run as root (mount/losetup)"; exit 2; }
command -v genisoimage >/dev/null || { echo "genisoimage required"; exit 2; }
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

no_tokens_in() { ! grep -qE '[0-9a-f]{64}' "$1"; }

# reset_artifacts — clear staging + fault state, keep any attached disk.
reset_artifacts() {
    rm -rf "$RUN" "$FRAGDIR"
    # tmpfiles.d/confos-rke2.conf parity: both dirs exist before the unit runs.
    mkdir -p "$RUN" "$FRAGDIR" "$BYLABEL"
    rm -rf "$FAULTDIR"; mkdir -p "$FAULTDIR"
}
reset_state() {
    release_disk
    reset_artifacts
    rm -f /tmp/pwned-*
}

# write_stub FILE BODY — tiny executable /bin/sh stub for PATH shimming.
write_stub() {
    mkdir -p "${1%/*}"
    printf '#!/bin/sh\n%s\n' "$2" > "$1"
    chmod +x "$1"
}

RC=0; OUT=$WORK/out.txt
run_script() {
    local prefix="${1:-}"
    if [[ -n "$prefix" ]]; then
        PATH="$prefix:/usr/sbin:/usr/bin:/sbin:/bin" "$SCRIPT" >"$OUT" 2>&1
    else
        "$SCRIPT" >"$OUT" 2>&1
    fi
    RC=$?
}

assert_rejected() {
    ok "exits nonzero" test "$RC" -ne 0
    ok "no role-server verdict" test ! -e "$RUN/role-server"
    ok "no role-agent verdict" test ! -e "$RUN/role-agent"
    ok "no server token staged" test ! -e "$RUN/rke2-server-token"
    ok "no agent token staged" test ! -e "$RUN/rke2-agent-token"
    ok "no fragment written" test ! -e "$FRAG"
}

# ---------------------------------------------------------------- sanity
mkdir -p "$WORK"
CASE=sanity
reset_state
d=$WORK/sanity; mkdir -p "$d" "$MNT"; echo hi > "$d/x"
if ! make_iso "$d" || ! timeout 10 mount -t iso9660 -o ro "$DEVLINK" "$MNT"; then
    note "SANITY: cannot loop-mount ISO9660 here; aborting"
    exit 2
fi
umount "$MNT"
# Prefer the real settle where udevd runs (CI runners); shim only where not.
if ! udevadm settle --timeout=2; then
    note "SANITY: udevadm settle fails here (no udevd); no-disk cases will shim it"
    UDEV_SHIM=1
else
    UDEV_SHIM=0
fi
write_stub "$SHIMDIR-udev/udevadm" 'exit 0'

# ---------------------------------------------------------------- happy: server
CASE="server-disk"
reset_state; server_dir "$WORK/d"; make_iso "$WORK/d"; run_script
ok "exit 0" test "$RC" -eq 0
ok "role-server verdict" test -f "$RUN/role-server"
ok "no role-agent verdict" test ! -e "$RUN/role-agent"
ok "server token file 0600" test "$(file_mode "$RUN/rke2-server-token")" = 600
ok "agent token file 0600" test "$(file_mode "$RUN/rke2-agent-token")" = 600
ok "server token exact" test "$(cat "$RUN/rke2-server-token")" = "$STOK"
ok "agent token exact" test "$(cat "$RUN/rke2-agent-token")" = "$ATOK"
ok "fragment 0600" test "$(file_mode "$FRAG")" = 600
ok "fragment exact (token paths only)" \
   test "$(cat "$FRAG")" = "token-file: $RUN/rke2-server-token
node-ip: 192.168.7.10"
ok "no token value in fragment" no_tokens_in "$FRAG"
ok "no token value in output" no_tokens_in "$OUT"

CASE="server-disk+external-ip"
reset_state; server_dir "$WORK/d" with_ext; make_iso "$WORK/d"; run_script
ok "exit 0" test "$RC" -eq 0
ok "fragment has external ip" grep -qx 'node-external-ip: 203.0.113.10' "$FRAG"
ok "role-server verdict" test -f "$RUN/role-server"

# KubeVirt renders secret disks with kubelet AtomicWriter transport entries
# at the ISO root; dispatch must skip them, not reject the disk.
CASE="server-disk+kubevirt-transport-dirs"
reset_state; server_dir "$WORK/d"
mkdir -p "$WORK/d/..2026_01_01_00_00_00.111" "$WORK/d/..data"
cp "$WORK/d/role" "$WORK/d/..data/role"
cp "$WORK/d/role" "$WORK/d/..2026_01_01_00_00_00.111/role"
make_iso "$WORK/d"; run_script
ok "exit 0" test "$RC" -eq 0
ok "role-server verdict" test -f "$RUN/role-server"

# ---------------------------------------------------------------- happy: agent
CASE="agent-disk"
reset_state; agent_dir "$WORK/d"; make_iso "$WORK/d"; run_script
ok "exit 0" test "$RC" -eq 0
ok "role-agent verdict" test -f "$RUN/role-agent"
ok "no role-server verdict" test ! -e "$RUN/role-server"
ok "agent token 0600" test "$(file_mode "$RUN/rke2-agent-token")" = 600
ok "agent token exact" test "$(cat "$RUN/rke2-agent-token")" = "$ATOK"
ok "server token NOT staged" test ! -e "$RUN/rke2-server-token"
ok "fragment exact (url + addrs)" \
   test "$(cat "$FRAG")" = "token-file: $RUN/rke2-agent-token
server: https://192.168.7.10:$JOIN_PORT
node-ip: 192.168.7.11"
ok "no token value in fragment" no_tokens_in "$FRAG"
ok "no token value in output" no_tokens_in "$OUT"

CASE="agent-disk+external-ip"
reset_state; agent_dir "$WORK/d" with_ext; make_iso "$WORK/d"; run_script
ok "exit 0" test "$RC" -eq 0
ok "fragment has external ip" grep -qx 'node-external-ip: 203.0.113.11' "$FRAG"

# 0.0.0.0 is the autodetect sentinel: the fragment must omit node-ip so
# rke2 resolves the address itself (a literal 0.0.0.0 registers as the
# node's InternalIP and breaks apiserver->kubelet traffic). The agent
# role shares stage_addresses, so this covers both roles.
CASE="server-disk+autodetect-ip"
reset_state; server_dir "$WORK/d"; write_f "$WORK/d" node-ip 0.0.0.0
make_iso "$WORK/d"; run_script
ok "exit 0" test "$RC" -eq 0
ok "fragment omits node-ip" bash -c '! grep -q "^node-ip:" "'"$FRAG"'"'
ok "role-server verdict" test -f "$RUN/role-server"

# No autodetect for external addresses: the sentinel there is a config
# error and must reject, not pass through as ExternalIP 0.0.0.0.
CASE="server-disk+zero-external-ip"
reset_state; server_dir "$WORK/d" with_ext; write_f "$WORK/d" node-external-ip 0.0.0.0
make_iso "$WORK/d"; run_script
assert_rejected

# ---------------------------------------------------------------- happy: no disk
CASE="no-disk-legacy-server"
reset_state
if [[ "$UDEV_SHIM" == 1 ]]; then run_script "$SHIMDIR-udev"; else run_script; fi
ok "exit 0" test "$RC" -eq 0
ok "role-server verdict" test -f "$RUN/role-server"
ok "no role-agent verdict" test ! -e "$RUN/role-agent"
ok "generated agent token 0600" test "$(file_mode "$RUN/rke2-agent-token")" = 600
ok "generated token is 64 lowercase hex" \
   grep -qxE '[0-9a-f]{64}' "$RUN/rke2-agent-token"
ok "no server token file" test ! -e "$RUN/rke2-server-token"
ok "no fragment (legacy defaults untouched)" test ! -e "$FRAG"
ok "says defaulting to server" grep -q 'no joindata disk, defaulting to server' "$OUT"
ok "generated token not logged" no_tokens_in "$OUT"

# ---------------------------------------------------------------- re-dispatch
# Same-boot re-runs must not leak the previous run's staging.
CASE="redispatch-server-then-agent"
reset_state; server_dir "$WORK/d"; make_iso "$WORK/d"; run_script
ok "first run (server) exit 0" test "$RC" -eq 0
release_disk
agent_dir "$WORK/d"; make_iso "$WORK/d"; run_script
ok "second run (agent) exit 0" test "$RC" -eq 0
ok "role-agent verdict" test -f "$RUN/role-agent"
ok "stale role-server verdict removed" test ! -e "$RUN/role-server"
ok "stale server token removed" test ! -e "$RUN/rke2-server-token"
ok "fragment is agent-shaped" grep -qx "server: https://192.168.7.10:$JOIN_PORT" "$FRAG"

CASE="redispatch-success-then-broken"
reset_state; server_dir "$WORK/d"; make_iso "$WORK/d"; run_script
ok "first run (server) exit 0" test "$RC" -eq 0
release_disk
server_dir "$WORK/d"; write_f "$WORK/d" server-token not-a-token; make_iso "$WORK/d"; run_script
assert_rejected

# ---------------------------------------------------------------- rejections
reject_case() {
    CASE="$1"
    reset_state
    "$2" "$WORK/d"
    make_iso "$WORK/d"
    run_script
    assert_rejected
}

m_wrong_role()        { server_dir "$1"; write_f "$1" role bogus; }
m_role_missing()      { server_dir "$1"; rm "$1/role"; }
m_forbid_server()     { server_dir "$1"; write_f "$1" server 192.168.7.9; }
m_forbid_stok()       { agent_dir "$1";  write_f "$1" server-token "$STOK"; }
m_extra_file_server() { server_dir "$1"; write_f "$1" foo bar; }
m_extra_file_agent()  { agent_dir "$1";  write_f "$1" foo bar; }
m_equal_tokens()      { server_dir "$1"; write_f "$1" server-token "$ATOK"; }
m_tok_63()            { server_dir "$1"; write_f "$1" server-token "${STOK:0:63}"; }
m_tok_upper()         { server_dir "$1"; write_f "$1" server-token "$(tr a A <<<"$STOK" | tr -d '\n')"; }
m_tok_nonhex()        { agent_dir "$1";  write_f "$1" agent-token "${ATOK:0:63}g"; }
m_ip_range()          { server_dir "$1"; write_f "$1" node-ip 999.1.1.1; }
m_ip_short()          { server_dir "$1"; write_f "$1" node-ip 1.2.3; }
m_ip_leading_zero()   { server_dir "$1"; write_f "$1" node-ip 010.2.3.4; }
m_ip_octet_08()       { server_dir "$1"; write_f "$1" node-ip 1.2.3.08; }
m_srv_scheme()        { agent_dir "$1";  write_f "$1" server https://192.168.7.10; }
m_srv_port()          { agent_dir "$1";  write_f "$1" server "192.168.7.10:$JOIN_PORT"; }
m_interior_ws()       { server_dir "$1"; write_f "$1" node-ip '1.2.3.4 x'; }
m_multiline()         { server_dir "$1"; printf 'server\nagent\n' > "$1/role"; }
m_oversize_file()     { server_dir "$1"; head -c 300 /dev/zero | tr '\0' a > "$1/role"; }
m_oversize_line()     { server_dir "$1"; { head -c 257 /dev/zero | tr '\0' a; } > "$1/role"; }
m_nul_byte()          { server_dir "$1"; printf 'ser\0ver' > "$1/role"; }
m_symlink()           { server_dir "$1"; rm "$1/role"; ln -s /etc/hostname "$1/role"; }
m_dangling_ext_ip()   { server_dir "$1"; ln -s /nonexistent-target "$1/node-external-ip"; }
m_nonregular_dir()    { server_dir "$1"; rm "$1/role"; mkdir "$1/role"; }
m_empty_ext_ip()      { server_dir "$1"; write_f "$1" node-external-ip ''; }
m_agent_no_server()   { agent_dir "$1"; rm "$1/server"; }
m_server_no_atok()    { server_dir "$1"; rm "$1/agent-token"; }

for c in wrong_role role_missing forbid_server forbid_stok extra_file_server \
         extra_file_agent equal_tokens tok_63 tok_upper tok_nonhex ip_range \
         ip_short ip_leading_zero ip_octet_08 srv_scheme srv_port interior_ws \
         multiline oversize_file oversize_line nul_byte symlink \
         dangling_ext_ip nonregular_dir empty_ext_ip agent_no_server \
         server_no_atok; do
    reject_case "reject-$c" "m_$c"
done

# The regex, not bash arithmetic (invalid octal), must catch leading zeros.
CASE="reject-ip-octet-08-clean"
reset_state; m_ip_octet_08 "$WORK/d"; make_iso "$WORK/d"; run_script
ok "no bash arithmetic noise" bash -c '! grep -q "value too great" "'"$OUT"'"'

# ---------------------------------------------------------------- injection
CASE="injection-not-evaluated"
reset_state
d=$WORK/d; server_dir "$d"
write_f "$d" role '$(touch$IFS/tmp/pwned-role)'
write_f "$d" node-ip '`touch$IFS/tmp/pwned-ip`'
write_f "$d" server-token ';touch$IFS/tmp/pwned-tok;'
make_iso "$d"; run_script
assert_rejected
ok "no command from role field ran" test ! -e /tmp/pwned-role
ok "no command from ip field ran" test ! -e /tmp/pwned-ip
ok "no command from token field ran" test ! -e /tmp/pwned-tok

# Host-supplied role text (terminal escapes included) must not reach logs.
CASE="invalid-role-not-echoed"
reset_state; server_dir "$WORK/d"; write_f "$WORK/d" role 'EVILMARKER123'; make_iso "$WORK/d"; run_script
assert_rejected
ok "supplied role text absent from output" bash -c '! grep -q EVILMARKER123 "'"$OUT"'"'

# ---------------------------------------------------------------- non-ISO fs
CASE="reject-non-iso"
reset_state
img=$WORK/ext4.img; rm -f "$img"
dd if=/dev/zero of="$img" bs=1M count=4 status=none
mke2fs -q -t ext4 -L joindata "$img"
attach_disk "$img"
run_script
assert_rejected

# ---------------------------------------------------------------- mount timeout (simulated)
CASE="reject-mount-timeout"
reset_state; server_dir "$WORK/d"; make_iso "$WORK/d"
# exec: otherwise timeout's kill orphans the sleep for the remaining 50s.
write_stub "$SHIMDIR-hang/mount" 'exec sleep 60'
run_script "$SHIMDIR-hang"
assert_rejected
ok "timeout fired (rc 124 path, <60s)" test "$RC" -eq 124

# ---------------------------------------------------------------- fault injection
# Fail the Nth invocation of one staging command; the canonical artifacts must
# each be absent-or-complete and the verdict must be absent.
make_shims() { # make_shims CMD N
    local cmd="$1" n="$2" real
    rm -rf "$SHIMDIR"; mkdir -p "$SHIMDIR"
    real=$(command -v "$cmd")
    # Builtins only: a shimmed `cat` calling cat would recurse via PATH.
    cat > "$SHIMDIR/$cmd" <<EOF
#!/bin/bash
c=0
[[ -f $FAULTDIR/count ]] && read -r c < $FAULTDIR/count
c=\$((c+1)); printf '%s\n' "\$c" > $FAULTDIR/count
if [[ \$c -eq $n ]]; then echo "fault: $cmd call \$c" >&2; exit 1; fi
exec $real "\$@"
EOF
    chmod +x "$SHIMDIR/$cmd"
}

assert_no_partial() {
    local f
    ok "no role-server verdict" test ! -e "$RUN/role-server"
    ok "no role-agent verdict" test ! -e "$RUN/role-agent"
    for f in "$RUN/rke2-server-token:$STOK" "$RUN/rke2-agent-token:$ATOK"; do
        local path="${f%%:*}" want="${f#*:}"
        if [[ -e "$path" ]]; then
            ok "${path##*/} complete if visible" test "$(cat "$path")" = "$want"
        fi
    done
    if [[ -e "$FRAG" ]]; then
        ok "fragment complete if visible" grep -q '^token-file: ' "$FRAG"
        ok "fragment has no token value" no_tokens_in "$FRAG"
    fi
}

# Only the shim varies, so each role's ISO is built once (server stages 3
# write_atomic calls, agent 2).
for spec in server:3 agent:2; do
    kind=${spec%:*}; writes=${spec#*:}
    reset_state; "${kind}_dir" "$WORK/d"; make_iso "$WORK/d"
    for cmd in mv cat chmod mktemp; do
        for (( n=1; n<=writes; n++ )); do
            CASE="fault-$kind-$cmd-$n"
            reset_artifacts
            make_shims "$cmd" "$n"
            run_script "$SHIMDIR"
            if grep -q "fault: $cmd call $n" "$OUT"; then
                ok "script fails on injected fault" test "$RC" -ne 0
                assert_no_partial
            else
                ok "fault $n beyond $cmd call count (script succeeded untouched)" test "$RC" -eq 0
            fi
        done
    done
done
# Legacy path: od failure must fail closed.
CASE="fault-legacy-od"
reset_state
make_shims od 1
[[ "$UDEV_SHIM" == 1 ]] && write_stub "$SHIMDIR/udevadm" 'exit 0'
run_script "$SHIMDIR"
ok "od failure fails the unit" test "$RC" -ne 0
ok "no verdict on od failure" test ! -e "$RUN/role-server"

# ---------------------------------------------------------------- summary
release_disk
summarize "rke2-role script-level summary"
