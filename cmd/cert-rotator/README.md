# cert-rotator

Rotates mesh CA keypairs for the cert-issuer. Generates new certificates, updates Kubernetes Secrets and ConfigMaps with CA bundles, and verifies cert-issuer hot-reload via metrics polling. Token-signer rotation is handled by assam in-process (see `pkg/earsigner`).

Deployed as a Kubernetes CronJob via the `trustee_kbs` Ansible role.

## Build

```bash
make build-cert-rotator
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--namespace` | `tee-attestation` | Namespace holding the kbs-mesh-ca Secret and mesh-ca-cert ConfigMap |
| `--components` | `mesh-ca` | Comma-separated components to rotate |
| `--mesh-ca-validity-days` | `365` | Mesh CA certificate validity (days) |
| `--cert-issuer-url` | *(empty)* | cert-issuer metrics URL for hot-reload verification |
| `--verify-timeout` | `120s` | Timeout for reload verification polling |
| `--verify-poll-interval` | `5s` | Polling interval for cert-issuer reload verification |
| `--http-timeout` | `30s` | HTTP client timeout for KBS and cert-issuer requests |
| `--max-ttl` | `4h` | Max leaf cert TTL for CA bundle trimming cutoff |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--kbs-url` | *(empty)* | KBS base URL (enables attested rotation via cert-issuer /v1/rotate-ca) |
| `--attest-cmd` | `/attest-sev-snp` | Path to attestation binary |
| `--cert-issuer-rotate-url` | *(empty)* | cert-issuer /v1/rotate-ca endpoint URL |

## Rotation Flow

1. Capture baseline cert-issuer metrics (if `--cert-issuer-url` set)
2. For each component in `--components`:
   - **mesh-ca**: Generate P-384 keypair, create self-signed CA certificate, update `kbs-mesh-ca` Secret, build CA bundle (new cert + trimmed old certs), update `mesh-ca-cert` ConfigMap. In KBS mode (`--kbs-url`), attests to KBS and triggers rotation via cert-issuer `/v1/rotate-ca` instead.
3. Verify cert-issuer hot-reload via metrics polling (5s interval until reload counter increments AND CA fingerprint matches)

## CA Bundle Trimming

Old certificates in the CA bundle are removed when they expired more than `2 × --max-ttl` ago. This grace period ensures that leaf certificates signed by the old CA (which can live up to `--max-ttl`) remain verifiable during their lifetime. Unparseable PEM blocks are preserved.

## Rollback Behavior

If the ConfigMap update fails after a Secret update, the Secret is reverted to its original data. If rollback itself fails, a critical error is logged but the process does not abort — manual intervention is required.

## Audit Trail

Each rotation logs SHA-256 fingerprints for old and new certificates:

```json
{
  "level": "info",
  "msg": "mesh CA rotated",
  "old_fingerprint": "sha256:abc...",
  "new_fingerprint": "sha256:def...",
  "not_after": "2027-03-01T00:00:00Z"
}
```

KBS-mode rotations log the new fingerprint returned by cert-issuer.

## Deployment

Deployed as a Kubernetes CronJob via the `trustee_kbs` Ansible role in [`lunal-dev/deployment-scripts`](https://github.com/lunal-dev/deployment-scripts). See the role's README for CronJob configuration, RBAC, and Ansible variables.

## Testing

```bash
go test -race -count=1 -timeout=60s -v ./cmd/cert-rotator/...
```

## Security

- [Threat Model](../../docs/SECURITY/THREAT_MODEL.md) — Threats [T16](../../docs/SECURITY/THREAT_MODEL.md#t16-cert-rotator-secret-access), [T18](../../docs/SECURITY/THREAT_MODEL.md#t18-ca-bundle-trimming-removes-valid-cas)
- [Certificate Lifecycle](../../docs/SECURITY/CERT_LIFECYCLE.md) — Rotation flow, bundle trimming, configuration matrix
