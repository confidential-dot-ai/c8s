#!/bin/bash
# Boots real systemd in a privileged container with the production units,
# drop-ins, preset, tmpfiles config, and rke2-role.sh (fake sleep-infinity
# rke2 payloads), and asserts the gating:
# only the selected role's unit runs, a failed dispatch fails both visibly,
# preset applies, restart/role-switch behavior is pinned down.
#
# Driver mode (default) needs only docker; --inside runs the assertions.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [[ "${1:-}" != "--inside" ]]; then
    command -v docker >/dev/null 2>&1 || { echo "docker required"; exit 2; }
    IMG=rke2-role-systemd-test
    CTR=rke2-role-systemd-$$
    docker build -q -t "$IMG" - <<'EOF' >/dev/null || { echo "image build failed"; exit 2; }
FROM debian:12
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv udev genisoimage && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
EOF
    trap 'docker rm -f "$CTR" >/dev/null 2>&1' EXIT
    docker run -d --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        --name "$CTR" "$IMG" >/dev/null || { echo "container start failed"; exit 2; }
    # Poll rather than a single `--wait`: right after `docker run`, exec can
    # land before systemd has its D-Bus socket and returns nothing.
    state=""
    for _ in $(seq 1 30); do
        state=$(docker exec "$CTR" systemctl is-system-running 2>/dev/null || true)
        # degraded is normal: no getty/network units in a container
        case "$state" in running|degraded) break ;; esac
        sleep 1
    done
    case "$state" in
    running|degraded) ;;
    *) echo "systemd failed to reach a settled state: '$state'"; exit 2 ;;
    esac
    docker cp "$TESTS_DIR/.." "$CTR":/ngi >/dev/null
    docker exec "$CTR" bash /ngi/tests/rke2-role-systemd-test.sh --inside
    exit $?
fi

# ---- inside: real systemd is PID 1 ----
. "$TESTS_DIR/lib.sh"

EXTRA=$TESTS_DIR/../c8s/mkosi.extra
WORK=/tmp/systemd-test-work
# rke2 tarball unit dir; mkosi.sync stages the units there (the lint job
# tripwires on that staying true).
UNITDIR=/usr/local/lib/systemd/system
mkdir -p "$WORK"

# Production pieces, installed exactly where the image puts them.
for p in etc/systemd/system/rke2-role.service \
         etc/systemd/system/apparmor-enforce.service \
         etc/systemd/system/rke2-server.service.d/20-role.conf \
         etc/systemd/system/rke2-agent.service.d/20-role.conf \
         etc/systemd/system/rke2-agent.service.d/no-modprobe.conf \
         etc/tmpfiles.d/confos-rke2.conf \
         usr/lib/systemd/system-preset/50-rke2.preset; do
    install -D -m644 "$EXTRA/$p" "/$p"
done
install -D -m755 "$EXTRA/usr/local/bin/rke2-role.sh" /usr/local/bin/rke2-role.sh

# Exercise the production dependency/preset wiring without changing the
# test host's AppArmor policy or letting FailureAction power it off. The
# root-free apparmor-enforce-test.sh separately executes the exact probe.
install -D -m644 /dev/stdin /etc/systemd/system/apparmor-enforce.service.d/test.conf <<'EOF'
[Unit]
FailureAction=none
[Service]
ExecStart=
ExecStart=/bin/test ! -e /run/apparmor-enforce-test-fail
EOF
install -D -m644 /dev/stdin "$UNITDIR/apparmor.service" <<'EOF'
[Unit]
Description=fake stock AppArmor loader
[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

# Fake rke2 payloads in the tarball's unit dir: gating, not rke2, is under
# test.
for u in rke2-server rke2-agent; do
    install -D -m644 /dev/stdin "$UNITDIR/$u.service" <<EOF
[Unit]
Description=fake $u payload
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
EOF
done

systemctl daemon-reload

active()       { systemctl is-active --quiet "$1"; }
not_active()   { ! systemctl is-active --quiet "$1"; }
cond_skipped() { [[ "$(systemctl show -p ConditionResult --value "$1")" == no ]]; }
unit_failed()  { systemctl is-failed --quiet "$1"; }

# Boot simulation: start both role-gated units, as the preset would at boot;
# Requires= pulls in rke2-role first, conditions evaluate after it.
boot_roles() { systemctl start rke2-server.service rke2-agent.service; }

# assert_role_won ROLE — dispatch done, ROLE's unit runs, the other skipped.
assert_role_won() {
    local win=$1 lose=rke2-agent
    if [[ $win == rke2-agent ]]; then lose=rke2-server; fi
    ok "dispatch active" active rke2-role
    ok "AppArmor gate active" active apparmor-enforce
    ok "$win active" active "$win"
    ok "$lose not active" not_active "$lose"
    ok "$lose was condition-skipped" cond_skipped "$lose"
    ok "verdict role-${win#rke2-}" test -f "$RUN/role-${win#rke2-}"
}

scenario_reset() {
    systemctl stop rke2-agent rke2-server rke2-role apparmor-enforce >/dev/null 2>&1 || true
    systemctl reset-failed >/dev/null 2>&1 || true
    rm -f /run/apparmor-enforce-test-fail
    release_disk
    rm -rf "$RUN" "$FRAGDIR"
    systemd-tmpfiles --create /etc/tmpfiles.d/confos-rke2.conf >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------- bake parity
CASE="preset"
systemctl enable apparmor.service >/dev/null 2>&1
ok "preset applies to roles and AppArmor services" \
   systemctl preset rke2-role.service rke2-server.service rke2-agent.service apparmor-enforce.service apparmor.service
for u in rke2-role rke2-server rke2-agent apparmor-enforce; do
    ok "$u enabled by preset" systemctl is-enabled --quiet "$u.service"
done
ok "preset disables the stock AppArmor loader" \
   test "$(systemctl is-enabled apparmor.service 2>/dev/null || true)" = disabled
for role in server agent; do
    ok "AppArmor is required by rke2-$role" \
       test -L "/etc/systemd/system/rke2-$role.service.requires/apparmor-enforce.service"
done
CASE="tmpfiles"
systemd-tmpfiles --create /etc/tmpfiles.d/confos-rke2.conf >/dev/null 2>&1 || true
ok "tmpfiles created $RUN" test -d "$RUN"
ok "tmpfiles created $FRAGDIR" test -d "$FRAGDIR"

# ---------------------------------------------------------------- boot: no disk
CASE="boot-no-disk"
scenario_reset
ok "boot start succeeds" boot_roles
assert_role_won rke2-server
ok "generated agent token 0600" test "$(file_mode "$RUN/rke2-agent-token")" = 600

# ---------------------------------------------------------------- boot: server disk
CASE="boot-server-disk"
scenario_reset
server_dir "$WORK/d"; make_iso "$WORK/d"
ok "boot start succeeds" boot_roles
assert_role_won rke2-server
ok "server token staged 0600" test "$(file_mode "$RUN/rke2-server-token")" = 600
ok "fragment staged" test -f "$FRAG"

# ---------------------------------------------------------------- boot: agent disk
CASE="boot-agent-disk"
scenario_reset
agent_dir "$WORK/d"; make_iso "$WORK/d"
ok "boot start succeeds" boot_roles
assert_role_won rke2-agent
ok "fragment names the join URL" grep -qx "server: https://192.168.7.10:$JOIN_PORT" "$FRAG"

# ---------------------------------------------------------------- boot: broken disk
CASE="boot-broken-disk"
scenario_reset
server_dir "$WORK/d"; write_f "$WORK/d" server-token not-a-token
make_iso "$WORK/d"
ok "boot start FAILS (Requires= propagates)" bash -c '! systemctl start rke2-server.service rke2-agent.service 2>/dev/null'
ok "dispatch unit failed (visible)" unit_failed rke2-role
ok "server not active" not_active rke2-server
ok "agent not active" not_active rke2-agent
ok "no verdict staged" bash -c "test ! -e $RUN/role-server && test ! -e $RUN/role-agent"

# ---------------------------------------------------------------- boot: AppArmor failure
for role in server agent; do
    CASE="boot-$role-AppArmor-failure"
    scenario_reset
    "${role}_dir" "$WORK/d"; make_iso "$WORK/d"
    touch /run/apparmor-enforce-test-fail
    ok "failed AppArmor gate blocks boot" not boot_roles
    ok "AppArmor failure visible" unit_failed apparmor-enforce
    ok "server not active" not_active rke2-server
    ok "agent not active" not_active rke2-agent
done

# ---------------------------------------------------------------- restart, same disk
CASE="restart-same-disk"
scenario_reset
server_dir "$WORK/d"; make_iso "$WORK/d"
boot_roles
ok "server active before restart" active rke2-server
systemctl restart rke2-role.service
srv_after=$(systemctl is-active rke2-server.service 2>/dev/null || true)
note "  observed: rke2-server is '$srv_after' after rke2-role restart (Requires= propagation)"
ok "dispatch re-ran clean" active rke2-role
ok "verdict still role-server" test -f "$RUN/role-server"
ok "never both roles active" \
   bash -c '! (systemctl is-active --quiet rke2-server && systemctl is-active --quiet rke2-agent)'
# The documented remedy must restore service regardless of propagation.
ok "remedy restores the server" bash -c 'systemctl start rke2-server.service && systemctl is-active --quiet rke2-server'

# ---------------------------------------------------------------- restart, swapped disk
# Unsupported operation (role changes ride a reboot); recorded, not asserted.
CASE="restart-swapped-disk"
release_disk
agent_dir "$WORK/d"; make_iso "$WORK/d"
systemctl restart rke2-role.service
ok "verdict followed the disk" test -f "$RUN/role-agent"
ok "stale verdict removed" test ! -e "$RUN/role-server"
srv=$(systemctl is-active rke2-server.service 2>/dev/null || true)
agt=$(systemctl is-active rke2-agent.service 2>/dev/null || true)
note "  observed after swap+restart: rke2-server='$srv' rke2-agent='$agt' (design doc: role changes require a reboot)"

# ---------------------------------------------------------------- summary
scenario_reset
summarize "rke2-role systemd-level summary"
