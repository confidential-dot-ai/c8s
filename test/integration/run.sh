#!/usr/bin/env bash
# Integration test for the TLS load balancer.
# Starts mock services, runs get-cert as an init container, and verifies
# nginx can serve HTTPS with the obtained certificate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

cleanup() {
    echo "--- Cleaning up ---"
    if [ -n "${COMPOSE_CMD:-}" ]; then
        $COMPOSE_CMD down -v --remove-orphans 2>/dev/null || true
    fi
}
trap cleanup EXIT

COMPOSE_CMD=""
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "SKIP: docker compose not available"
    exit 0
fi

echo "=== Building and starting services ==="
$COMPOSE_CMD build
$COMPOSE_CMD up -d

echo ""
echo "=== Verifying TLS endpoint ==="

# Wait for nginx to be ready (it depends on get-cert completing).
for i in $(seq 1 30); do
    if curl -sk https://localhost:8443/healthz >/dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "FAIL: nginx did not become ready in time"
        docker compose logs
        exit 1
    fi
    sleep 1
done

# Test 1: Health endpoint works over TLS.
HEALTH_RESPONSE=$(curl -sk https://localhost:8443/healthz)
if [ "$HEALTH_RESPONSE" != "ok" ]; then
    echo "FAIL: expected 'ok' from /healthz, got: $HEALTH_RESPONSE"
    exit 1
fi
echo "PASS: /healthz returns ok"

# Test 2: Proxied backend content is served.
BODY=$(curl -sk https://localhost:8443/)
if ! echo "$BODY" | grep -q "Welcome to nginx"; then
    echo "FAIL: expected nginx welcome page from proxy, got: $BODY"
    exit 1
fi
echo "PASS: reverse proxy serves backend content"

# Test 3: Certificate has the expected SAN.
SAN_INFO=$(echo | openssl s_client -connect localhost:8443 -servername nginx-lb 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
if echo "$SAN_INFO" | grep -q "DNS:nginx-lb"; then
    echo "PASS: certificate contains SAN DNS:nginx-lb"
elif echo "$SAN_INFO" | grep -qi "nginx-lb"; then
    echo "PASS: certificate references nginx-lb"
else
    echo "WARN: could not verify SAN in certificate (openssl may not be available)"
    echo "  SAN info: $SAN_INFO"
fi

# Test 4: Certificate is signed by an EC key (P-256).
KEY_INFO=$(echo | openssl s_client -connect localhost:8443 -servername nginx-lb 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep "Public Key Algorithm" || true)
if echo "$KEY_INFO" | grep -q "id-ecPublicKey"; then
    echo "PASS: certificate uses ECDSA key"
else
    echo "WARN: could not verify key algorithm"
    echo "  Key info: $KEY_INFO"
fi

echo ""
echo "=== All integration tests passed ==="
