# Shared fixtures for the rke2-role harnesses. Unlike test/e2e/lib.sh's
# fail-fast fail(), ok() counts and keeps going; the "FAIL:" prefix stays
# aligned with that lib (CI greps it).

RUN=/run/confos
MNT=$RUN/joindata
FRAGDIR=/etc/rancher/rke2/config.yaml.d
FRAG=$FRAGDIR/50-role.yaml
BYLABEL=/dev/disk/by-label
DEVLINK=$BYLABEL/joindata

STOK=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11111111
ATOK=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb22222222
JOIN_PORT=9345  # rke2 supervisor port the staged fragment must name

PASS=0; FAIL=0
declare -a FAILURES

note() { printf '%s\n' "$*"; }

# ok DESC cmd... — count an assertion, attributed to $CASE.
ok() {
    local desc="$1"; shift
    if "$@"; then PASS=$((PASS+1)); else
        FAIL=$((FAIL+1)); FAILURES+=("$CASE: $desc"); note "  FAIL: $CASE: $desc"
    fi
}

# summarize TITLE — print totals; exit 1 if anything failed.
summarize() {
    note ""
    note "==== $1 ===="
    note "PASS: $PASS  FAIL: $FAIL"
    if (( FAIL > 0 )); then
        note "-- failures:"
        local f; for f in "${FAILURES[@]}"; do note "   $f"; done
        exit 1
    fi
}

file_mode() { stat -c %a "$1" 2>/dev/null || echo MISSING; }

# Joindata disk fixtures. write_f DIR NAME CONTENT (printf %s, no newline).
write_f() { printf '%s' "$3" > "$1/$2"; }

server_dir() { # server_dir DIR [with_ext]
    local d="$1"
    rm -rf "$d"; mkdir -p "$d"
    write_f "$d" role server
    write_f "$d" node-ip 192.168.7.10
    write_f "$d" server-token "$STOK"
    write_f "$d" agent-token "$ATOK"
    [[ "${2:-}" == with_ext ]] && write_f "$d" node-external-ip 203.0.113.10
    return 0
}
agent_dir() { # agent_dir DIR [with_ext]
    local d="$1"
    rm -rf "$d"; mkdir -p "$d"
    write_f "$d" role agent
    write_f "$d" server 192.168.7.10
    write_f "$d" node-ip 192.168.7.11
    write_f "$d" agent-token "$ATOK"
    [[ "${2:-}" == with_ext ]] && write_f "$d" node-external-ip 203.0.113.11
    return 0
}

# make_iso DIR — build an ISO (Rock Ridge, so symlinks/dirs survive), attach
# to a loop device, link it at /dev/disk/by-label/joindata. Uses $WORK.
declare -a OUR_LOOPS=()
make_iso() {
    local dir="$1" img loop
    img=$WORK/disk.iso
    rm -f "$img"
    genisoimage -quiet -R -o "$img" "$dir" 2>/dev/null || { note "genisoimage failed"; return 1; }
    attach_disk "$img"
}

# attach_disk IMG — loop-attach IMG and expose it at the joindata label path.
attach_disk() {
    local loop
    loop=$(losetup --find --show "$1") || return 1
    OUR_LOOPS+=("$loop")
    mkdir -p "$BYLABEL"
    ln -sf "$loop" "$DEVLINK"
}

release_disk() {
    umount "$MNT" 2>/dev/null || true
    local d
    for d in "${OUR_LOOPS[@]:-}"; do [[ -n "$d" ]] && losetup -d "$d" 2>/dev/null || true; done
    OUR_LOOPS=()
    rm -f "$DEVLINK"
}
