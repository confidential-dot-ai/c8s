#!/bin/bash
# Boot real systemd with production launch/core units and role conditions.
# The test replaces service payloads and device/verifier I/O only; dependency
# ordering, Requires= failures, role selection and presets remain production.
# Driver mode needs Docker; --inside runs only in its disposable container.
set -euo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ "${1:-}" != --inside ]]; then
    command -v docker >/dev/null || { echo "docker required" >&2; exit 2; }
    IMG=c8s-launch-systemd-test
    CTR=c8s-launch-systemd-$$
    docker build -q -t "$IMG" - <<'EOF' >/dev/null
FROM debian:12
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv && apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
EOF
    trap 'docker rm -f "$CTR" >/dev/null 2>&1 || true' EXIT
    docker run -d --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        --name "$CTR" "$IMG" >/dev/null
    state=""
    for _ in $(seq 1 30); do
        state=$(docker exec "$CTR" systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) break ;; esac
        sleep 1
    done
    case "$state" in running|degraded) ;; *) echo "systemd failed to settle: $state" >&2; exit 2 ;; esac
    docker cp "$TESTS_DIR/.." "$CTR":/ngi >/dev/null
    docker exec "$CTR" bash /ngi/tests/rke2-role-systemd-test.sh --inside
    exit $?
fi
[[ $EUID == 0 && $(cat /proc/1/comm) == systemd ]] || { echo "--inside requires disposable root systemd" >&2; exit 2; }
. "$TESTS_DIR/lib.sh"
. "$TESTS_DIR/launch-fixtures.sh"
EXTRA=$TESTS_DIR/../c8s/mkosi.extra
SOURCE_UNITS=$EXTRA/etc/systemd/system
UNITDIR=/usr/local/lib/systemd/system
mkdir -p "$UNITDIR" /dev/disk/by-label

for p in etc/systemd/system/rke2-role.service \
         etc/systemd/system/c8s-join.service \
         etc/systemd/system/apparmor-enforce.service \
         etc/systemd/system/rke2-server.service.d/no-modprobe.conf \
         etc/systemd/system/rke2-agent.service.d/no-modprobe.conf \
         etc/systemd/system/rke2-server.service.d/20-role.conf \
         etc/systemd/system/rke2-agent.service.d/20-role.conf \
         etc/tmpfiles.d/confos-rke2.conf \
         usr/lib/systemd/system-preset/50-rke2.preset; do
    install -D -m644 "$EXTRA/$p" "/$p"
done
install -D -m755 "$EXTRA/usr/local/bin/rke2-role.sh" /usr/local/bin/rke2-role.sh
install_launch_stubs /usr/local/bin
install -D -m644 /dev/stdin /etc/systemd/system/rke2-role.service.d/90-test.conf <<EOF
[Service]
Environment=CRED_PLATFORM=tdx
Environment=C8S_ROLE_FIXTURE=$C8S_ROLE_FIXTURE
EOF

install -D -m644 /dev/stdin /etc/systemd/system/c8s-join.service.d/90-test.conf <<EOF
[Service]
Environment=C8S_ROLE_FIXTURE=$C8S_ROLE_FIXTURE
EOF

# Exercise the production dependency/preset wiring without changing the
# test host's AppArmor policy or letting FailureAction power it off. The
# isolated apparmor-enforce-test.sh separately executes the unchanged probe.
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

# RKE2's tarball units and the external attester are the only units not
# available in this repository. Their test payloads wait indefinitely.
for u in rke2-server rke2-agent attestation-api; do
    install -D -m644 /dev/stdin "$UNITDIR/$u.service" <<EOF
[Unit]
Description=test $u payload
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
EOF
done

# A real follower payload must never execute before enrollment writes its token.
install -D -m644 /dev/stdin "$UNITDIR/rke2-agent.service.d/90-test-payload.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/bin/sh -c 'test -s /run/confos/rke2-agent-token && touch /run/confos/test-agent-started && exec /bin/sleep infinity'
EOF

# Locate units by their concrete service entrypoints, so renaming a unit is
# harmless but dropping a core service or bypassing its wrapper is detected.
core_units=()
for command in cds mesh mesh-sync get-cert cds-attest allowlist-proxy attest-proxy join-release; do
    mapfile -t files < <(grep -lE "^ExecStart=.*node-services run $command$" "$SOURCE_UNITS"/*.service)
    [[ ${#files[@]} == 1 ]] || { echo "expected one production unit for $command" >&2; exit 2; }
    core_units+=("${files[0]##*/}")
done
mapfile -t nginx_units < <(grep -lE '^ExecStart=.*/nginx ' "$SOURCE_UNITS"/*.service)
[[ ${#nginx_units[@]} == 1 ]] || { echo "expected one production nginx unit" >&2; exit 2; }
core_units+=("${nginx_units[0]##*/}" cred-release.service nri-node-ip.service)

for unit in "${core_units[@]}"; do
    install -D -m644 "$SOURCE_UNITS/$unit" "/etc/systemd/system/$unit"
    install -D -m644 /dev/stdin "/etc/systemd/system/$unit.d/90-test-payload.conf" <<'EOF'
[Service]
Type=simple
ExecStartPre=
ExecStart=
ExecStart=/bin/sleep infinity
ExecStartPost=
ExecStop=
EOF
done

systemctl daemon-reload
payload_units=(rke2-server.service rke2-agent.service c8s-join.service "${core_units[@]}")
active() { systemctl is-active --quiet "$1"; }
not_active() { ! active "$1"; }
cond_skipped() { [[ $(systemctl show -p ConditionResult --value "$1") == no ]]; }
boot_roles() { systemctl start "${payload_units[@]}"; }
scenario_reset() {
    systemctl stop "${payload_units[@]}" rke2-role.service attestation-api.service apparmor-enforce.service >/dev/null 2>&1 || true
    systemctl reset-failed >/dev/null 2>&1 || true
    reset_launch_fixture
    rm -f /dev/disk/by-label/opkeydata /run/apparmor-enforce-test-fail
    systemd-tmpfiles --create /etc/tmpfiles.d/confos-rke2.conf
    # Paths mounted read-only by production hardening normally exist after
    # RKE2 initializes. Payload stubs need empty equivalents for its sandbox.
    mkdir -p /etc/confai /etc/rancher/rke2 /run/c8s-tls /run/ratls-mesh \
        /var/lib/rancher/rke2/server/tls /var/lib/rancher/rke2/agent /var/log/nginx /var/lib/nginx
}

CASE=presets
systemctl enable apparmor.service >/dev/null 2>&1
ok "production preset applies" systemctl preset rke2-role.service apparmor-enforce.service apparmor.service "${payload_units[@]}"
for unit in rke2-role.service apparmor-enforce.service "${payload_units[@]}"; do
    ok "$unit enabled" systemctl is-enabled --quiet "$unit"
done

ok "preset disables the stock AppArmor loader" \
    test "$(systemctl is-enabled apparmor.service 2>/dev/null || true)" = disabled
for role in server agent; do
    ok "AppArmor is required by rke2-$role" \
        test -L "/etc/systemd/system/rke2-$role.service.requires/apparmor-enforce.service"
done

for role in leader follower; do
    CASE="boot-$role"
    scenario_reset
    launch_media "$role"
    : > /dev/disk/by-label/opkeydata
    ok "selected role boots" boot_roles
    ok "launch verification is active" active rke2-role.service
    ok "AppArmor gate is active" active apparmor-enforce.service
    selected=rke2-server.service; skipped=rke2-agent.service
    if [[ $role == follower ]]; then selected=rke2-agent.service; skipped=rke2-server.service; fi
    ok "$selected active" active "$selected"
    ok "$skipped inactive" not_active "$skipped"
    ok "$skipped condition skipped" cond_skipped "$skipped"
    if [[ $role == follower ]]; then
        ok "enrollment is complete" active c8s-join.service
        ok "agent ran after enrollment" test -f /run/confos/test-agent-started
        ok "credential is private" test "$(stat -c %a /run/confos/rke2-agent-token)" = 600
    else
        ok "leader skips follower enrollment" cond_skipped c8s-join.service
        ok "leader never fetched a credential" test ! -e /run/confos/test-join-attempts
    fi
    for unit in "${core_units[@]}"; do
        if [[ $role == follower ]] && grep -qF 'ConditionPathExists=/run/confos/role-server' "$SOURCE_UNITS/$unit"; then
            ok "$unit inactive on follower" not_active "$unit"
            ok "$unit condition skipped on follower" cond_skipped "$unit"
        else
            ok "$unit active on $role" active "$unit"
        fi
    done
done

CASE=leader-without-followers
scenario_reset
launch_media leader
: > "$C8S_ROLE_FIXTURE/no-followers"
ok "leader without followers boots" boot_roles
ok "release is skipped without follower policy" cond_skipped c8s-join-release.service
ok "leader control plane remains active" active rke2-server.service

CASE=enrollment-failure
scenario_reset
launch_media follower
: > "$C8S_ROLE_FIXTURE/join-fails"
systemctl start --no-block "${payload_units[@]}"
for _ in $(seq 1 80); do
    [[ -f /run/confos/test-join-attempts ]] && [[ $(cat /run/confos/test-join-attempts) -ge 2 ]] && break
    sleep 0.1
done
ok "failed enrollment retries automatically" test "$(cat /run/confos/test-join-attempts)" -ge 2
ok "enrollment never satisfies the agent gate" not_active c8s-join.service
ok "failed enrollment cannot start agent" not_active rke2-agent.service
ok "agent payload never executed" test ! -e /run/confos/test-agent-started
ok "no credential was staged" test ! -e /run/confos/rke2-agent-token
ok "stop cancels pending enrollment" systemctl stop c8s-join.service
attempts=$(cat /run/confos/test-join-attempts)
sleep 0.2
ok "stopped enrollment stays inactive" not_active c8s-join.service
ok "stop leaves no running process" test "$(systemctl show -p MainPID --value c8s-join.service)" = 0
ok "stop prevents additional attempts" test "$(cat /run/confos/test-join-attempts)" = "$attempts"

CASE=enrollment-retry
scenario_reset
launch_media follower
: > "$C8S_ROLE_FIXTURE/join-fails-once"
ok "retry completes original boot job" boot_roles
ok "enrollment retried automatically" test "$(cat /run/confos/test-join-attempts)" -ge 2
ok "recovered enrollment starts agent" active rke2-agent.service
ok "recovered agent has its credential" test -f /run/confos/test-agent-started

for scenario in missing-launch invalid-signature prepare-failure; do
    CASE="boot-$scenario"
    scenario_reset
    if [[ $scenario != missing-launch ]]; then
        launch_media leader
        : > /dev/disk/by-label/opkeydata
    fi
    case "$scenario" in
        invalid-signature) printf '%s\n' invalid > "$C8S_ROLE_FIXTURE/media/launch.yaml.sig" ;;
        prepare-failure) : > "$C8S_ROLE_FIXTURE/prepare-fails" ;;
    esac
    ok "startup fails visibly" not boot_roles
    ok "launch unit failed" systemctl is-failed --quiet rke2-role.service
    ok "no role authorized" no_launch_markers
    for unit in "${payload_units[@]}"; do ok "$unit stayed down" not_active "$unit"; done
done

for role in leader follower; do
    CASE="boot-$role-AppArmor-failure"
    scenario_reset
    launch_media "$role"
    : > /dev/disk/by-label/opkeydata
    : > /run/apparmor-enforce-test-fail
    ok "failed AppArmor gate blocks boot" not boot_roles
    ok "AppArmor failure is visible" systemctl is-failed --quiet apparmor-enforce.service
    ok "server stays down" not_active rke2-server.service
    ok "agent stays down" not_active rke2-agent.service
done

scenario_reset
summarize "authenticated launch systemd dependencies"
