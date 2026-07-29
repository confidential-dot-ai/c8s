# Secret release

How a workload is authorized to read a secret, and what the allowlist and the
admission inventory contribute to that decision.

> **Status.** This document describes the parts that have landed: the
> entry-level `secrets` grant, and the inventory reporting that release will be
> evaluated against. The CDS secrets store and its release endpoint are not
> implemented yet, so **no grant releases anything today**.

## The grant

A secret grant belongs to a **workload entry**, not a container:

```json
"vllm-llama": {
  "containers": [ { "digest": "sha256:…", "command": {…}, "args": {…} } ],
  "secrets": { "policy": "allow", "read": ["/tenant-a/**"], "write": ["/tenant-a/session"] }
}
```

The subject is the entry because the value is delivered on a volume every
container in the pod can read — a per-container grant would not describe what is
actually released.

- `policy` is `allow` or `deny`. There is deliberately **no `any`**: an unbounded
  secret grant is never what an operator means.
- Paths are absolute, clean, and the only wildcard is a trailing `/**`, which
  matches strictly beneath its base — `/a/**` does not grant `/a`.
- `write` requires `read`. The only client creates with `POST`, then re-reads;
  a write-only grant would strand every replica that loses the create race.
- A grant that releases nothing is **omitted** from the canonical document, so an
  entry without one serializes exactly as it did before the field existed.

`paths`, the per-container filesystem field this replaces, never had an enforcer
and is gone. The in-pod destination of a secret is **not** an authorization
boundary — the workload owns its own filesystem once the value is inside it — so
only the store path is policy.

### Upgrading

CDS parses its seed with unknown fields rejected and fails closed, so a values
file still carrying per-container `paths` would stop CDS booting. The chart
rejects it at `helm upgrade` (`VALIDATION_ERROR kind=allowlist_container_paths`).
Move the grant up to the entry; a `deny` grant is simply dropped.

Serving the field is safe ahead of the consumers: `secrets` appears only once an
operator writes a real grant, and the pull path
(`allowlist.ParseServedJSON`) ignores fields it does not know. Strict parsing is
kept for operator-authored input, where an unknown field is a typo.

## What the inventory reports

`GET /digests/{sandboxID}` answers with two views of the same sandbox:

| field | shape | used by |
|---|---|---|
| `digests` | deduplicated digest set | cert issuance (membership) |
| `containers` | `[{digest, argv}]`, **not** deduplicated | secret release |

`argv` is the effective OCI `process.args` that admission evaluated, so release
can hold a sandbox to the same `(digest, argv)` pair the allowlist matched rather
than to a digest set that says nothing about what those images were told to run.
Without it, two entries differing only in argv are indistinguishable, and the
argv admission enforces is a **union across every entry listing the digest** — so
an entry that pins `command: exact` gives no guarantee at release time if another
entry widens the same digest.

`containers` is absent on an inventory older than the field. A consumer that
needs it must treat that as "cannot answer" rather than "no containers"
(`RequireContainers`).

### The report is a high-water mark

Both views describe every container **ever admitted** in the sandbox, not those
running now. The inventory is otherwise "created and not yet removed", and
kubelet removes and recreates a container across a `CrashLoopBackOff` — so a live
snapshot lets a pod arrange for a container to be absent at the moment it is
asked and present a set it does not have. A pod could then declare a victim
entry's containers plus one extra image that exits immediately, be handed the
secret during a backoff window, and read it when the extra container restarts.

Admission is monotone, so membership here is too. A container that stops leaves
caller resolution — a stopped container must not bind a caller — but stays in the
sandbox's record until the sandbox itself is torn down.

The cost is that a pod which ever ran an image outside its entry never receives a
secret, even after that image is gone. That is the correct direction for a
release decision.
