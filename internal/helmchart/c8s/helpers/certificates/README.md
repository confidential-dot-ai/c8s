# Certificate helpers

Source: [templates/_certificates.tpl](../../templates/_certificates.tpl).
[All helpers](../README.md).

`c8s.getCertContainers` renders the `c8s-cert` native sidecar and the
`c8s-cert-wait` init container for chart-owned components. The sidecar obtains
and renews a CDS-issued mesh certificate over RA-TLS. Its long-lived process
anchors the shared PID namespace under Kata, allowing nginx reload by SIGHUP.
`--key-out` loads an existing key across container restarts.

The wait container gates workload startup on the certificate file using
`/c8s probe-file`. This uses the guest's allowed container-creation path;
locked guests deny the exec RPC an exec startup probe would require. Keep the
`/c8s` command aligned with the binary location in `cmd/c8s/Dockerfile`.

The helper takes a dict with these fields:

| Field | Purpose |
| --- | --- |
| `root` | Chart root for image and endpoint helpers |
| `san` | Certificate workload identity or Service DNS name |
| `certOut`, `keyOut` | Certificate and private-key output paths |
| `caOut` | Optional output path for the mesh CA bundle trailing the leaf |
| `volume`, `mountPath` | Writable certificate volume and its mount directory |
| `renewInterval` | Go duration, such as `6h` or `30m` |
| `runAsUser`, `runAsGroup`, `runAsNonRoot` | Consumer-compatible security context |
| `reloadNginx` | Enable nginx SIGHUP on renewal; defaults to `false` |
| `extraArgs` | Optional list of additional get-cert arguments |
| `extraMounts` | Optional rendered volumeMount YAML |

`c8s.getCertSecurityContext` uses the supplied UID/GID, drops all capabilities,
requires a read-only root filesystem, and selects the RuntimeDefault seccomp
profile. Both containers share it so they can access the consumer's cert volume.

`c8s.cdsDnsSanPattern` matches `<service>.<namespace>.svc` across namespaces.
CDS full-matches the regex. `cds.dnsSanPatterns` adds further allowed patterns,
including public hostnames, alongside this in-cluster pattern.
