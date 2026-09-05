#!/bin/bash
# Root-free tests of the production AppArmor boot gate. Only absolute system
# paths are rebased; parser, aa-exec and systemctl behavior comes from fixtures.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/apparmor-enforce.sh
[[ -f "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export PROBE_ROOT=$WORK PROBE_CASE=good
mkdir -p "$WORK/bin" "$WORK/sys/kernel/security/apparmor" \
    "$WORK/sys/module/apparmor/parameters" "$WORK/proc/self/attr"
export PATH="$WORK/bin:$PATH"

cat >"$WORK/bin/apparmor_parser" <<'EOF'
#!/bin/sh
cat > "$PROBE_ROOT/policy"
printf '%s\n' "$*" >> "$PROBE_ROOT/parser-calls"
case "$1" in
    --replace)
        [ "$PROBE_CASE" != load-fails ] || exit 1
        mode=enforce
        [ "$PROBE_CASE" != complain ] || mode=complain
        printf 'c8s-apparmor-boot-probe (%s)\n' "$mode" > "$PROBE_ROOT/sys/kernel/security/apparmor/profiles"
        touch "$PROBE_ROOT/loaded"
        ;;
    --remove)
        [ "$PROBE_CASE" != cleanup-fails ] || exit 1
        rm -f "$PROBE_ROOT/loaded"
        ;;
    *) exit 1 ;;
esac
EOF
cat >"$WORK/bin/aa-exec" <<'EOF'
#!/bin/sh
[ "$1" = -p ] && [ "$2" = c8s-apparmor-boot-probe ] && [ "$3" = -- ] || exit 2
shift 3
[ "$1" = /bin/cat ] || exit 2
case "$2" in
    "$PROBE_ROOT/proc/self/attr/current")
        case "$PROBE_CASE" in
            bad-label) echo unconfined ;;
            empty-label) : ;;
            enter-fails) exit 1 ;;
            *) echo 'c8s-apparmor-boot-probe (enforce)' ;;
        esac
        ;;
    "$PROBE_ROOT/proc/version")
        case "$PROBE_CASE" in
            denial-ignored) exit 0 ;;
            wrong-error) echo 'cat: unexpected failure' >&2; exit 1 ;;
            wrong-status) echo 'cat: Permission denied' >&2; exit 127 ;;
            *) echo 'cat: Permission denied' >&2; exit 1 ;;
        esac
        ;;
    *) exit 2 ;;
esac
EOF
cat >"$WORK/bin/systemctl" <<'EOF'
#!/bin/sh
[ "$2" = apparmor.service ] || exit 2
case "$1:$PROBE_CASE" in
    is-enabled:service-enabled) echo enabled ;;
    is-enabled:service-unknown) echo not-found; exit 4 ;;
    is-enabled:*) echo disabled; exit 1 ;;
    is-active:service-active) echo active ;;
    is-active:service-state-unknown) echo unknown; exit 4 ;;
    is-active:*) echo inactive; exit 3 ;;
    *) exit 2 ;;
esac
EOF

reset_probe() {
    PROBE_CASE=good
    chmod +x "$WORK/bin/apparmor_parser" "$WORK/bin/aa-exec" "$WORK/bin/systemctl"
    printf '%s\n' 'lockdown,yama,apparmor,bpf' > "$WORK/sys/kernel/security/lsm"
    printf 'Y\n' > "$WORK/sys/module/apparmor/parameters/enabled"
    printf 'Linux test kernel\n' > "$WORK/proc/version"
    : > "$WORK/sys/kernel/security/apparmor/profiles"
    : > "$WORK/parser-calls"
    rm -f "$WORK/loaded"
}

run_enforce() {
    sed -e "s|/sys/|$WORK/sys/|g" \
        -e "s|/proc/|$WORK/proc/|g" \
        -e "s|/sbin/apparmor_parser|$WORK/bin/apparmor_parser|g" \
        -e "s|/usr/bin/aa-exec|$WORK/bin/aa-exec|g" \
        "$SCRIPT" | sh >"$WORK/stdout" 2>"$WORK/stderr"
}

CASE="working enforcement"
reset_probe
ok "passes" run_enforce
ok "loads uncached profile" grep -qx -- '--replace --skip-cache' "$WORK/parser-calls"
ok "removes uncached profile" grep -qx -- '--remove --skip-cache' "$WORK/parser-calls"
ok "probe profile removed" test ! -e "$WORK/loaded"

for missing in absent substring; do
    CASE="$missing AppArmor LSM"
    reset_probe
    if [[ $missing == absent ]]; then
        rm "$WORK/sys/kernel/security/lsm"
    else
        printf 'lockdown,notapparmor,yama\n' > "$WORK/sys/kernel/security/lsm"
    fi
    ok "fails closed" not run_enforce
    ok "names LSM cause" stderr_has 'active LSM list'
done

CASE="disabled AppArmor module"
reset_probe
printf 'N\n' > "$WORK/sys/module/apparmor/parameters/enabled"
ok "fails closed" not run_enforce
ok "names disabled module" stderr_has 'AppArmor is disabled'

for binary in apparmor_parser aa-exec; do
    CASE="missing $binary"
    reset_probe
    chmod -x "$WORK/bin/$binary"
    ok "fails closed" not run_enforce
    ok "names missing binary" stderr_has "$binary is missing"
done

for state in service-enabled service-active service-unknown service-state-unknown; do
    CASE="$state"
    reset_probe
    PROBE_CASE=$state
    ok "fails closed" not run_enforce
    ok "names stock service" stderr_has 'apparmor.service must be'
    ok "does not load a profile" test ! -s "$WORK/parser-calls"
done

CASE="parser load failure"
reset_probe
PROBE_CASE=load-fails
ok "fails closed" not run_enforce
ok "names load failure" stderr_has 'cannot load'

for scenario in complain bad-label empty-label enter-fails denial-ignored wrong-error wrong-status; do
    CASE="$scenario"
    reset_probe
    PROBE_CASE=$scenario
    ok "fails closed" not run_enforce
    ok "failure removes profile" test ! -e "$WORK/loaded"
    ok "cleanup invoked" grep -qx -- '--remove --skip-cache' "$WORK/parser-calls"
done

CASE="unconfined control read failure"
reset_probe
rm "$WORK/proc/version"
ok "fails closed" not run_enforce
ok "names control read" stderr_has 'unconfined control read failed'
ok "failure removes profile" test ! -e "$WORK/loaded"

CASE="cleanup failure"
reset_probe
PROBE_CASE=cleanup-fails
ok "fails closed" not run_enforce
ok "names cleanup failure" stderr_has 'cannot remove'
ok "does not report success" not grep -q 'verified' "$WORK/stdout"

summarize "apparmor-enforce"
