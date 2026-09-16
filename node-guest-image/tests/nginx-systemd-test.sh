#!/bin/bash
# Exercise the rendered node-image nginx configuration and production unit in
# real Linux systemd. Only the two required prerequisite services are faked.
set -euo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ "${1:-}" != --inside ]]; then
    for tool in docker go helm; do
        command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 2; }
    done
    REPO=$(cd "$TESTS_DIR/../.." && pwd)
    WORK=$(mktemp -d)
    IMG=c8s-nginx-systemd-test
    CTR=c8s-nginx-systemd-$$
    # shellcheck disable=SC2317,SC2329 # Invoked indirectly by the EXIT trap.
    cleanup() {
        local result=$?
        if (( result != 0 )); then
            docker exec "$CTR" journalctl -u c8s-nginx.service --no-pager -n 100 || true
        fi
        docker rm -f "$CTR" >/dev/null 2>&1 || true
        rm -rf "$WORK"
        return "$result"
    }
    trap cleanup EXIT
    trap 'exit 1' HUP INT TERM
    (
        cd "$REPO"
        CGO_ENABLED=0 go build -o "$WORK/c8s" ./cmd/c8s
    )
    rke2=$(sed -n 's/^RKE2_VERSION="\(.*\)"$/\1/p' "$TESTS_DIR/../c8s/mkosi.sync")
    [[ -n "$rke2" ]] || { echo "RKE2 version pin missing" >&2; exit 2; }
    "$WORK/c8s" node-image render --hardware-platform tdx \
        --kube-version "${rke2%%+*}" \
        --image-digest "sha256:$(printf '%064d' 0)" --output-dir "$WORK/rendered"
    docker build -q -t "$IMG" --build-arg "CONFOS_RELEASE=${CONFOS_RELEASE:-26.04}" - <<'EOF' >/dev/null
ARG CONFOS_RELEASE=26.04
FROM ubuntu:${CONFOS_RELEASE}
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv nginx openssl curl util-linux procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
EOF
    docker run -d --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock --name "$CTR" "$IMG" >/dev/null
    state=""
    for _ in $(seq 1 30); do
        state=$(docker exec "$CTR" systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) break ;; esac
        sleep 1
    done
    case "$state" in running|degraded) ;; *) echo "systemd failed to settle: $state" >&2; exit 2 ;; esac
    docker cp "$TESTS_DIR/.." "$CTR":/ngi >/dev/null
    docker cp "$WORK/rendered/nginx.conf.in" "$CTR":/nginx.conf >/dev/null
    docker exec "$CTR" bash /ngi/tests/nginx-systemd-test.sh --inside
    exit $?
fi

[[ $EUID == 0 && $(cat /proc/1/comm) == systemd ]] || { echo "--inside requires disposable root systemd" >&2; exit 2; }
# shellcheck source=lib.sh
. "$TESTS_DIR/lib.sh"
WORK=/run/nginx-systemd-test
mkdir -p "$WORK" /run/confos/launch /run/c8s-tls /var/lib/nginx /var/log/nginx
systemctl disable --now nginx.service >/dev/null 2>&1
install -m644 "$TESTS_DIR/../c8s/mkosi.extra/etc/systemd/system/c8s-nginx.service" \
    /etc/systemd/system/c8s-nginx.service
install -m644 /nginx.conf /run/confos/launch/nginx.conf
: > /run/confos/role-server
for unit in rke2-role c8s-get-cert; do
    cat > "/etc/systemd/system/$unit.service" <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF
done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=c8s-node.invalid \
    -keyout /run/c8s-tls/key.pem -out /run/c8s-tls/cert.pem >/dev/null 2>&1
cp /run/c8s-tls/cert.pem /run/c8s-tls/ca.pem
chmod 600 /run/c8s-tls/key.pem
printf '{}\n' > /run/c8s-tls/discovery.json
for log in access error; do
    printf 'legacy %s log\n' "$log" > "/var/log/nginx/$log.log"
    chown www-data:adm "/var/log/nginx/$log.log"
    chmod 0640 "/var/log/nginx/$log.log"
done
legacy_state() {
    stat -c '%n %u:%g %a %s %i' /var/log/nginx/{access,error}.log
    sha256sum /var/log/nginx/{access,error}.log
}
legacy_state > "$WORK/legacy-before"
systemctl daemon-reload

wait_until() {
    local attempt
    for ((attempt = 0; attempt < 50; attempt++)); do
        if "$@"; then return 0; fi
        sleep 0.2
    done
    return 1
}
ready() { curl --insecure --silent --fail --max-time 1 https://127.0.0.1/healthz >/dev/null; }
main_pid() { systemctl show -p MainPID --value c8s-nginx.service; }
workers() { pgrep -P "$(main_pid)" | sort -n; }
workers_replaced() {
    local old
    [[ -n "$(workers)" ]] || return 1
    for old in $old_workers; do
        if kill -0 "$old" 2>/dev/null; then return 1; fi
    done
}
access_logged() {
    journalctl -t c8s-nginx --no-pager -o cat > "$WORK/access-journal"
    grep -Fq "\"GET /$1 HTTP/" "$WORK/access-journal"
}
request_logged() {
    local status marker="nginx-journal-$CASE"
    status=$(curl --insecure --silent --show-error --max-time 3 --output /dev/null \
        --write-out '%{http_code}' "https://127.0.0.1/$marker") || return 1
    [[ "$status" == 404 ]] || return 1
    wait_until access_logged "$marker"
}
legacy_unchanged() {
    legacy_state > "$WORK/legacy-after"
    cmp "$WORK/legacy-before" "$WORK/legacy-after"
}
capabilities_unchanged() {
    local pid
    pid=$(main_pid)
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    # CHOWN, KILL, SETGID, SETUID, NET_BIND_SERVICE; no DAC override or read/search.
    awk '/^Cap(Eff|Bnd):/ { if ($2 != "00000000000004e1") exit 1; n++ } END { if (n != 2) exit 1 }' "/proc/$pid/status"
}
check_running() {
    ok "HTTPS health is ready" wait_until ready
    ok "requests reach the journal" request_logged
    ok "production capabilities are unchanged" capabilities_unchanged
    ok "legacy log metadata and content are unchanged" legacy_unchanged
    ok "nginx has not crashed and restarted" test "$(systemctl show -p NRestarts --value c8s-nginx.service)" = 0
}

CASE=start
ok "legacy files cannot be written without DAC capabilities" \
    setpriv --bounding-set=-dac_override,-dac_read_search /bin/sh -c \
    'test ! -w /var/log/nginx/access.log && test ! -w /var/log/nginx/error.log'
ok "production unit starts" systemctl start c8s-nginx.service
check_running
journalctl -u c8s-nginx.service --no-pager -o cat > "$WORK/error-journal"
ok "configuration-test stderr reaches the journal" grep -Fq 'syntax is ok' "$WORK/error-journal"
ok "request errors reach stderr in the journal" grep -Eq 'open\(\).*nginx-journal-start.*failed' "$WORK/error-journal"
if (( FAIL > 0 )); then summarize "nginx systemd lifecycle"; fi

CASE=HUP
pid=$(main_pid)
old_workers=$(workers)
ok "HUP reload succeeds" systemctl reload c8s-nginx.service
ok "HUP replaces the workers" wait_until workers_replaced
ok "HUP keeps the master" test "$(main_pid)" = "$pid"
check_running

CASE=USR1
ok "USR1 reopen succeeds" systemctl kill --kill-whom=main --signal=USR1 c8s-nginx.service
ok "USR1 keeps the master" test "$(main_pid)" = "$pid"
check_running

CASE=restart
ok "restart succeeds" systemctl restart c8s-nginx.service
ok "restart replaces the master" not test "$(main_pid)" = "$pid"
check_running
summarize "nginx systemd lifecycle"
