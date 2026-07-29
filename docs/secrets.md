# Secret release

How a workload is authorized to read a secret, and what the allowlist and the
admission inventory contribute to that decision.

> **Status.** Delivery works end to end. Still missing: an operator diagnostic
> for a denied release (`c8s secrets explain`) and the lint checks that catch an
> ambiguous or under-declared entry.

## When it is served

Release is gated on an allowlist entry carrying a grant, which is operator-signed
and changeable without a restart. An entry without one releases nothing, so
writing a grant is what turns release on.

Serving the endpoint at all needs what sandbox identity already requires —
`--ratls-platform`, `--measurements`, and `--sandbox-inventory-cidr`. Miss any
and CDS logs a warning naming the one it is missing, and does not serve
`/secrets`.

It also does not serve `/secrets` when **handoff** is configured
(`--handoff-peer-url` / `--handoff-measurements`). A handoff roll puts two CDS
pods behind the Service at once, and the surge replica serves an empty store: a
workload landing on it mints a value diverging from the one its siblings already
hold, with no error anywhere. Refusing to serve is better than that divergence.

Sizing: `--secrets-max-paths`, `--secrets-max-value-bytes`,
`--sandbox-ledger-max-entries`. CDS is a single in-memory process holding the
mesh CA, so a workload able to grow either map without limit could OOM it and
take every certificate in the cluster with it.

**kata is out of scope.** `--cvm-mode=pod` refuses `--measurements`, so the
measurement requirement above is unmeetable there. Two other reasons stand
independently: the kata sandbox ID comes from a host-written CRI annotation, and
argv enforcement in the guest is watch-and-kill rather than synchronous.

## Asking for a secret

Annotate the pod alongside `confidential.ai/cw`:

| Annotation | |
|---|---|
| `confidential.ai/c8s-secrets` | comma-separated `NAME=/store/path`; `NAME` is the file each value is written to |
| `confidential.ai/c8s-secret-dir` | where the files land; default `/run/c8s/secrets` |

```yaml
annotations:
  confidential.ai/cw: api
  confidential.ai/c8s-secrets: "DB=/tenant-a/db,HF=/tenant-a/hf-token"
```

The webhook injects a `c8s-secret` sidecar and a memory-backed volume. Every
container in the pod mounts that volume **read-only**; only the fetcher may
write it. The volume and the container name are reserved — a pod declaring
either is rejected, since a `hostPath` there would write a released secret to
host-visible storage, and an ephemeral container mounting it would read one out
of a running pod.

### The file appears after your container starts

This is the part to design around. CDS releases only once **every** main
container is running, because that is when the sandbox matches a whole workload
entry. The fetcher therefore starts alongside the workload, is refused while the
set is incomplete, and writes when it completes. A consumer must wait for its
file rather than read it at startup:

```sh
until [ -f /run/c8s/secrets/DB ]; do sleep 1; done
```

Nothing can remove this. An init container would be asking before its siblings
exist and would deadlock the pod it gates. The consequence is that a terminal
fetch failure leaves a `Running` pod with no secret and an
`Init:CrashLoopBackOff` sub-status — there is no fail-closed delivery gate to be
had under combination gating.

A workload that finds its path empty creates it, so the first pod of a workload
to ask defines the value.

## The API

The injected fetcher speaks this; a workload does not have to. Every request
needs a single-use challenge and a fresh sandbox token, so a release is bound to
one caller and cannot be replayed.

```
POST /secrets                      → {"challenge": "<base64>"}
GET  /secrets/<store path>         → 200 {"value": "<base64>"} | 404 | 403
POST /secrets/<store path>         → 201 {"value": "<base64>"} | 409 | 403
```

`POST /secrets` is the challenge route; the wildcard can never match it, so no
store path is shadowed by it — a secret at `/challenge` still resolves.

A request carries:

| | |
|---|---|
| client certificate | the pod's mesh leaf, mTLS. Its CDS-stamped sandbox ID is the identity |
| `X-C8s-Challenge` | base64 of the challenge, consumed before anything else happens |
| `Authorization: SandboxToken <base64>` | the inventory-signed token, in a header so it is bounded and never logged |

The token is obtained from the node's admission inventory at `POST /sandbox`,
bound to the leaf's key and that challenge — the same route and the same
envelope `get-cert` uses at issuance.

**`POST` never carries a value.** CDS generates it, so no caller chooses what
another caller will later read. On a path that already exists it answers `409`
with **no body**: returning the value would make a write grant a read grant. A
caller holding `read` recovers with `GET`, which is how the replica that loses
a create race gets the value.

A path that is not granted is `404`, indistinguishable from one that does not
exist — otherwise the API enumerates the store. Denials are opaque to the
client; the reason goes to the CDS log.

Paths must arrive already canonical: absolute, clean, no trailing slash, and no
percent-encoding. They are rejected rather than repaired, so the bytes matched
against a grant and the bytes used as a store key are the bytes the client
sent.

## What CDS checks

1. The client certificate chains to the mesh CA — verified by crypto/tls, not
   by the handler. The RA-TLS path is not accepted here: it would admit a
   self-signed peer whose sandbox-ID extension is whatever it chose.
2. The sandbox ID comes from that verified leaf.
3. The sandbox token verifies against the inventory **bound to that sandbox**,
   carries this request's challenge, and names the same sandbox as the leaf.
4. That inventory reports what the sandbox has run.
5. The reported set, minus injected containers, matches exactly one workload
   entry.
6. That entry's grant covers the requested path.

Any failure refuses. So does an unreachable inventory, an unknown sandbox, an
empty container set, an ambiguous match, or an entry with no grant.

### Which inventory is asked

The binding is CDS's, not the requester's. At issuance — where the token has
already been verified — CDS records `sandbox ID → inventory host`,
**first-write-wins**, and the secrets path dials *that* host. The token must
name the same one.

This matters because a token is signable by anything that can answer on the
inventory port inside the configured CIDRs. Taking the host from the request
would let such a thing sign a token for someone else's sandbox, be believed
about what that sandbox runs, and have the answer used to release its secrets.

A conflicting binding does **not** refuse a certificate. `get-cert` has no
token-less retry, so denying at issuance would let one pre-claim wedge a pod for
a whole certificate lifetime — worse than what it prevents. The sandbox is
instead unusable for secrets, which costs one workload rather than every pod on
the node.

### The injected drop set

c8s injects its own containers into every confidential pod. They are not part of
a workload's declared set, so they are removed before matching — an entry never
has to enumerate c8s's own sidecars.

A container is dropped when its digest is an allowlist **floor** entry *and* its
entrypoint is one c8s injects (`get-cert`, `get-secret`, `/c8s`). Both halves
are load-bearing. Floor membership alone would let a pod add busybox running a
shell — also a floor entry — and have it ignored.

The floor is the source. It already carries the injected image, since it could
not run otherwise, and it is **additive**: a digest once served is never
dropped. So an image bump leaves the previous digest in place alongside the new
one, and pods still running the old image keep matching while they recycle.

What this rests on: no floor image other than c8s's has an executable at one of
those entrypoints. Floor contents are operator-controlled and auditable, but
that is a property of the deployment rather than something enforced here.

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
  entry without one carries no `secrets` key and a consumer that does not know
  the field never sees it.

The in-pod destination of a secret is **not** an authorization boundary — the
workload owns its own filesystem once the value is inside it — so only the store
path is policy.

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

## Restarts

**A CDS restart destroys every secret, and requires rolling every workload that
holds one.**

The store is process memory and there is no persistence. Worse than losing it:
a pod recreated after the restart calls `POST`, finds the path empty, and is
given a **new** value — while its siblings still hold the old one. Nothing
reports this. A partially-rolled Deployment ends up with two different values
for one path.

So after a CDS restart, restart every secret-consuming workload rather than
letting them recover piecemeal — a rolling restart of each Deployment. Treat a released value as ephemeral for the
lifetime of the CDS process; nothing durable may be keyed on one.

The sandbox ledger is process memory too, so a leaf that outlives a restart has
no binding until its next renewal and is refused meanwhile.
