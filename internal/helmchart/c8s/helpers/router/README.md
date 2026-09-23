# Router helpers

Source: [templates/router-helpers.tpl](../../templates/router-helpers.tpl).
[All helpers](../README.md).

## The built-in CDS allowlist route

`router.renderAllowlistRoute` is the single predicate behind the built-in
control-plane route: the nginx locations, the `allowlist-proxy` sidecar and the
Service traffic policy all flip on it. It is true when `router.allowlist.enabled`
is a real boolean `true` and no legacy typed route already owns `/allowlist`
(`router.hasExplicitAllowlistRoute`).

`router.allowlistLocation` renders one of those locations. Args: `root`, `exact`
(bool), `regex` (bool), `path`, `proxyPort`, `writeBurst`, `writeTotalBurst`,
`readBurst`, and optionally `read`. The configmap prologue validates the numeric
args before passing them.

Two invariants the template exists to hold:

- **`proxy_pass` carries `$request_uri` verbatim.** Operator authorization signs
  the method, the exact path and the body, so nginx must not normalize the path
  before CDS verifies the token.
- **nginx never dials CDS directly.** Stock nginx cannot verify the RA-TLS
  attestation extension, so every location forwards to the loopback
  `allowlist-proxy`, which does.

## Which paths render

[router-configmap.yaml](../../templates/router-configmap.yaml) emits an exact
`/allowlist` location and a `/allowlist/` prefix location, so a lookalike path
such as `/allowlisted` never reaches the proxy. Alongside them it emits the read
surface of the publication protocol as one regex location:

```
~ ^/\.well-known/c8s/(objects/|allowlist/latest$|state$|state/challenge$)
```

A regex takes precedence over the `/.well-known/c8s/` prefix location that
serves the in-pod attestation sidecar, and naming the four paths exactly is what
keeps everything else on that prefix going to the sidecar. The participant
writes under `/.well-known/c8s/participants/` are deliberately absent: the proxy
refuses them too, so no boot can enroll or acknowledge through the public front
door. See
[allowlist-and-capabilities.md](../../../../../docs/allowlist-and-capabilities.md).

## Rate limiting

Metering runs before nginx collapses every caller onto the loopback proxy's
source address. Each zone's map key is empty for the methods it does not cover,
and `limit_req` does not account an empty key:

| Zone | Key | Covers |
| --- | --- | --- |
| `allowlist_write_per_client` | `$allowlist_write_rate_key` | Mutations, per client. |
| `allowlist_write_total` | `$allowlist_write_total_key` | Mutations in aggregate, guarding the shared per-pod-IP CDS bucket. |
| `allowlist_read_per_client` | `$allowlist_read_rate_key` | `GET`, `HEAD` and `POST`, per client. |

The read key covers `POST` because the state challenge is a read that has to be
one: it carries the verifier's nonce. The publication location passes `read=true`
and so applies this zone alone, which is what stops a few browser verifiers
exhausting the operator's write budget. On the `/allowlist` locations `POST` is
not a method CDS serves, so counting it in both the read and the write zones
costs nothing.
