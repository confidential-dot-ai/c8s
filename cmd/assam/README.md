# assam

The main key broker service binary. Assam verifies TEE attestation evidence via an external attestation service and issues signed X.509 certificates via cert-issuer.

## Usage

```bash
assam \
  --attestation-service-url http://attestation-service:8400 \
  --cert-issuer-url http://cert-issuer:8090 \
  --whitelist-db /data/whitelist.db \
  --whitelist-admin-password secret
```

For Kubernetes deployments, sensitive values can be provided via
`C8S_ATTESTATION_SERVICE_API_KEY` and
`C8S_ASSAM_WHITELIST_ADMIN_PASSWORD` instead of command-line arguments.

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host` | | `0.0.0.0` | Host address to bind to |
| `--port` | `-p` | `8080` | Port to listen on |
| `--attestation-service-url` | | *(required)* | URL of the attestation service |
| `--attestation-service-api-key` | | `$C8S_ATTESTATION_SERVICE_API_KEY` | API key for the attestation service |
| `--cert-issuer-url` | | *(required)* | URL of the cert-issuer service |
| `--ear-issuer` | | `assam` | Issuer name for EAR tokens |
| `--cert-ttl` | | `24h` | TTL for issued certificates |
| `--challenge-ttl` | | `1m` | Challenge validity period |
| `--readiness-interval` | | `10s` | Interval between readiness health checks |
| `--whitelist-db` | | *(required)* | Path to the whitelist SQLite database file |
| `--whitelist-admin-password` | | `$C8S_ASSAM_WHITELIST_ADMIN_PASSWORD` | Admin password for whitelist mutation endpoints |
| `--token-signer-rotation-interval` | | `720h` | How often to rotate the EAR signing key (0 = disable) |
| `--token-signer-overlap` | | `25h` | How long a retired key stays in JWKS after rotation |
| `--token-signer-rotation-jitter` | | `0.1` | Fraction of rotation interval to jitter the first tick |

## Graceful shutdown

The server handles SIGINT (Ctrl+C) and SIGTERM signals for graceful shutdown.
