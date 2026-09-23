# Allowlist and capabilities

How c8s decides which container images may run, which commands they may run
with, and — for future key-management integration — which secret paths they may
read and write. This document complements [`ratls.md`](ratls.md) (how the allowlist is bound
into attestation).

> **Trust model.** The host, hypervisor, and Kubernetes control plane are
> untrusted; the trust boundary is the TEE. The image *reference* a pod presents
> (`docker.io/vllm/vllm-openai:v0.6.3`) is chosen by the untrusted host and is
> not bound to the bytes that run. The image *digest* is. So every trust decision
> in this design keys on the digest — the reference is a label for humans, never
> a lookup key.

## The model

The allowlist is a map of named **workload entries**. Each entry pins an
init/main container set. Every container binds a **digest** to the process
policy (`command`, `args`) permitted for those bytes, optionally to the
environment values it may launch with (`env`), and the entry as a whole may
carry a secret-store grant (`secrets`).
The entry name is operator-chosen; the entry `label` and per-container `image`
are informational. Policy is always resolved by container digest.

An image that may run **however it is invoked** — the standalone and injected
c8s components (cds, get-cert, the operator, ratls-mesh, nri-image-policy, the
router, the containerd-prep helper), whose argv is per-pod — is an entry whose
container `command` and `args` are both `any`. Nothing distinguishes such an
entry from any other: it is matched, stamped and diffed like the rest, and the
same digest may also appear elsewhere under a narrower policy — see [union
semantics](#a-digest-may-run-many-ways).

### Document shape

```json
{
  "schema": "c8s.allowlist/v1",
  "workloads": {
    "cds-3f2a9c8b1e2f": {
      "label": "ghcr.io/confidential-dot-ai/cds@sha256:<cds>",
      "initContainers": [],
      "containers": [
        {
          "digest":  "sha256:<cds>",
          "image":   "ghcr.io/confidential-dot-ai/cds@sha256:<cds>",
          "command": { "policy": "any" },
          "args":    { "policy": "any" }
        }
      ]
    },
    "vllm-llama": {
      "label": "docker.io/vllm/vllm-openai:v0.6.3",
      "initContainers": [],
      "containers": [
        {
          "digest": "sha256:<vllm>",
          "image":  "docker.io/vllm/vllm-openai:v0.6.3",
          "command": { "policy": "exact", "argv": ["python3"] },
          "args":    { "policy": "exact", "argv": ["-m", "vllm.entrypoints.openai.api_server", "--model", "/models/llama-3.1-8b"] }
        }
      ]
    }
  }
}
```

`schema` is the format identity. It is the first field of the canonical
serialization (`allowlist.Canonical`), so any holder of an equivalent document
reproduces the same bytes and pins the exact format. It also makes a malformed
or foreign body fail loud instead of parsing as an empty (and therefore deny-all
or, worse, allow-nothing-changed) allowlist.

#### Entry names

An entry name must match `[A-Za-z0-9][A-Za-z0-9._-]*` — it is used verbatim as a
URL path segment — and be at most **63 bytes**, the Kubernetes label-value
length, so the same string can also be a `confidential.ai/cw` selector value and
a matched-workload leaf stamp (`docs/ratls.md`).

The grammar is enforced everywhere. The 63-byte bound is enforced only where
entries are **written**: `PUT /allowlist`, `PUT /allowlist/workloads/{name}`,
and the CLI. A document *served* by CDS is parsed leniently, because the bound
was introduced after entries could already have been stored and one legacy name
must not fail the whole document for every puller in the cluster. An over-long
entry is dropped from a served parse with a warning: its digests stop being
admitted by that consumer (fail-closed), and it could never have been stamped on
a leaf in the first place.

**Migration.** An over-long entry created before the bound is still served by
CDS and still counts toward the document's canonical digest, but no pod can be
named for it and every consumer ignores it. Rename it — `c8s allowlist apply`
under a new name followed by a delete of the old one — and pods matching it start
getting named leaves. The lenient served parse is a compatibility measure for
one release; do not rely on it.

The grammar is slightly wider than what the injection webhook accepts for the
`confidential.ai/cw` label: `a-`, `a_` and `a.` are valid entry names but are
not valid label values. It is not tightened here, because that would
retroactively invalidate stored entries.

## Process policy: command and args

An image digest already pins the image's baked `ENTRYPOINT`/`CMD` — they are in
the OCI config the digest covers. So a process policy does not restate the
image's defaults; it constrains what a pod may **run** for those bytes. This
matters because an image with an overridable entrypoint can otherwise be pointed
at an arbitrary command — credential extraction, a reverse shell — while keeping
an allowlisted digest.

The two policy fields mirror the Kubernetes container fields an operator already
sets: `command` overrides the image `ENTRYPOINT`, `args` overrides `CMD`.

### What the enforcers see

The host NRI plugin gates container start and observes the container's
**effective argv**: the OCI
`process.args`, which is the already-merged result of the image config and any
pod-spec `command`/`args` override. They do not see the override as an override,
and they do not fetch the image config. Policy is matched against that effective
argv:

- **`command`** is matched as an exact **prefix** of the argv (it may be several
  tokens — `/docker-entrypoint.sh nginx`, `/bin/sh -c`, `python3`).
- **`args`** governs the **remainder** of the argv after the command prefix.

Each field is one of:

| policy  | `command` (a prefix)                     | `args` (the remainder)          |
|---------|------------------------------------------|---------------------------------|
| `exact` | argv must **start with** its `argv`      | the remainder must **equal** its `argv` |
| `any`   | no prefix constraint                     | the remainder is unconstrained  |
| `deny`  | the whole argv must be empty (see below) | there must be **no** remainder  |

So the boundary between the two is `len(command.argv)` when `command` is `exact`,
and `0` when it is `any` — which makes every combination well-defined: `command
exact + args any` pins the executable and lets flags vary; `command exact + args
exact` pins the whole argv; `args deny` means "no arguments beyond the command".

An absent policy normalizes to `deny`, so a minimally specified container is
maximally restrictive. `command: deny` requires an empty argv and therefore can
never start (a workload that wants any argv should say `command: any`); `lint`
flags it. Because `command`/`args` map 1:1 to the Kubernetes fields, `derive` (on
its own branch) reads them straight off a pod spec, and `inspect-image` shows an
image's baked `ENTRYPOINT`/`CMD` so an operator can see what to pin.

### A digest may run many ways

A single digest can appear under several containers — in one entry or across
entries — each with a different policy. Admission at the per-container gate is
the **union**: the container is admitted if its effective argv satisfies *some*
allowing container's command and args policy. This is deliberate. A shared base
image (busybox, a distroless runtime) is legitimately invoked with different
command lines by different workloads; the operator allowlists each invocation,
and any of them may run those bytes.

The precision this trades away: at the single-container gate the effective policy
for a digest is the union of every entry that lists it, because the host controls
which pod pairs a digest with which argv. `lint` surfaces this — it warns when one
entry widens a shared digest to `any`, because that becomes the effective
container-level policy for the digest everywhere. The narrower, entry-scoped
guarantee is recovered at [cert issuance](#where-its-enforced) — for an entry
that is distinguishable. An entry whose every container another entry admits
under any argv, and which that entry needs nothing more running for, is
**shadowed**: every pod it describes matches both, so it is never the unique
match and `lint`, `apply` and `add` refuse it. To tighten a seeded any-argv
entry, edit it; do not add a narrower entry for the same image beside it.

## Environment policy (`env`)

`env` constrains the complete OCI launch environment: `exact` requires
equality, so all names and values must match, including image defaults and
runtime additions. `deny` requires an observed empty environment; `any` permits
any environment. Missing env evidence fails `exact` and `deny`. An empty
`exact.values` normalizes to `deny`, and an absent policy defaults to `any`.

```json
"env": { "policy": "exact", "values": {"PATH": "/usr/bin:/bin", "MODEL_DIR": "/models"} }
```

The NRI plugin enforces env after cumulative NRI adjustments, and the admission
inventory carries an environment fingerprint for CDS workload matching and
secret release.


## Secret grants (`secrets`)

An entry may grant secret-store paths to the workload it names. The subject is
the **entry**, not a container — see [`secrets.md`](secrets.md) for the model and
for what the admission inventory contributes to a release decision.

```json
"secrets": { "policy": "allow", "read": ["/tenant-a/**"], "write": ["/tenant-a/session"] }
```

- `allow` or `deny` only; there is deliberately no `any`.
- `write` requires `read`.
- Paths are absolute and clean (no `.`/`..`); the only wildcard is a trailing
  `/**` (subtree), which matches strictly beneath its base.
- A grant that releases nothing is omitted from the canonical document, so an
  entry without one serializes exactly as it did before the field existed.

CDS enforces this grant at `GET`/`POST /secrets/*`. Writing a grant is what
turns release on: an entry without one releases nothing
([`secrets.md`](secrets.md#when-it-is-served)). An operator supplying a value at
`PUT /secrets/*` is authorized by the operator key instead
([`secrets.md`](secrets.md#operator-supplied-values)).

Filesystem location is not an authorization boundary — a workload owns its own
filesystem once a value is inside it — so a grant names store paths only. An
install still setting the per-container `paths` field needs
[`secrets.md`](secrets.md#upgrading).

## Where it's enforced

Two independent points enforce, at different strengths:

1. **Host NRI plugin** (`nri-image-policy`), per container. Resolves the image
   digest and checks the effective argv at creation, validates env after
   cumulative NRI adjustments, and rechecks the final OCI spec before start.
   Fail-closed before the allowlist first loads; the plugin runs inside the
   node CVM and is the primary admission gate.

2. **CDS at cert issuance**, in `resolveSandboxWorkload`. Before signing a leaf
   for a pod, CDS asks that pod's own inventory which images its sandbox is
   running (`docs/ratls.md`, "Sandbox identity"). Every reported digest must be
   allowlisted as some entry's container, checked against one atomic allowlist
   snapshot. Membership only: issuance lands mid-lifecycle, where the running
   set is a strict subset of the declared one, so requiring a whole entry would
   deny ordinary states
   ([getcert-workload-binding.md](getcert-workload-binding.md), Corner 4).
   Additionally — and without changing the membership contract — when the
   high-water `(digest, argv)` inventory uniquely matches one workload entry,
   the leaf is stamped with that entry's name and the snapshot's version and
   canonical digest (OID `…1.5`, `docs/ratls.md` "Matched workload"), which is
   what `c8s verify --workload/--allowlist` and
   `ratls.VerifyPolicy.WorkloadName` enforce against the mesh-CA chain.

### What each layer can and cannot promise

Per-container digest+argv admission holds at both points. **Combinations**
("only this image set may run together") are **not enforced anywhere today**.
NRI sees containers one at a time and cannot detect a
*missing* container, so they cannot enforce a combination; CDS sees the whole
reported set but only at issuance, which lands mid-lifecycle when that set is
still a subset of the declared one, so it checks membership rather than
composition ([getcert-workload-binding.md](getcert-workload-binding.md),
Corner 4). The honest guarantee is therefore: **per-container digest + argv
everywhere; no combination gating.**

Combination gating wants a point where the pod is complete and the decision is
worth blocking on. **Secret release is that point** ([`secrets.md`](secrets.md)):
it happens once every main container is up, so it can require a whole entry
rather than membership. That gates a secret, not container start — making a
combination itself *attested* is the RTMR3 per-workload-measurement path, which
is not implemented and is out of scope here.

### The injected-container carve-out

c8s injects two init containers into every confidential pod — `c8s-cert`
(get-cert) and `c8s-cert-wait`. They pass the issuance gate by **digest**, not
by name: the injected image is seeded as its own entry, so a workload entry
never has to enumerate c8s's own sidecars. Nothing rests on the container
*name*, which the host writes. get-cert runs with per-pod dynamic arguments,
which is exactly why the seeded component entries carry `command: any, args:
any`: their argv is not fixed and must not be argv-policed. Before matching, a
container admitted that way and running an injected entrypoint is dropped from
the candidate set ([`secrets.md`](secrets.md#the-injected-drop-set)).

## Distribution and trust

CDS serves the allowlist over an RA-TLS channel that consumers pin to CDS's
launch measurement. The document body is not itself signed; its integrity in
transit is the attested channel. Provenance of the *write policy* is checkable:
`c8s cds verify --operator-keys` cross-checks the key set CDS serves at
`/operator-keys` — fetched over the attested serving cert — against the
operator's own bundle. The serving certificate itself commits neither the key
set nor the seed (see [`ratls.md`](ratls.md)). The canonical serialization
(`allowlist.Canonical`) is deterministic — fixed field order, sorted map keys,
sorted container and path lists — so any holder of an equivalent document
reproduces the same bytes.

Writes are authorized by an operator EC key. The `c8s allowlist` CLI mints a
short-lived token bound to the exact method, path, and body (so a captured token
cannot be replayed against a different payload) and CDS verifies it against the
operator public keys it pins.

### Refresh and rollback

Enforcers do not poll `GET /allowlist`. They follow the CDS-signed state
statement (next section) and apply only the policy object it names, fetched by
content digest. There is no version high-water mark on the node: a withheld or
stale statement leaves the applied policy in place, so a CDS outage degrades
to "stale", never to "open". A CDS whose state is restored from an older
snapshot is not detectable by the node — see [publication and the
coordinator](#publication-the-coordinator-and-the-journal).

### Enforcer updates

The node follows a CDS-signed *state* statement at `/.well-known/c8s/state`.
The statement names the active policy digest and, while a publication rolls
out, the one outstanding update. The node applies the policy object that digest
names, fetched from `/.well-known/c8s/objects/sha256/<hex>` and re-hashed
against the digest it asked for before it is parsed.

What the node does in each phase:

- **No update.** It applies the policy the state names as active and drops the
  pending set the finished update left behind.
- **Update, not switched.** The target authorizes nothing yet. The node closes
  an admission barrier — no container create is decided while it is closed —
  marks the running containers whose admitting rule the target no longer grants
  *pending*, and acknowledges to CDS with their count. A container is retired by
  any narrowing of the rule that admitted it: a removed entry, a pinned command,
  a dropped mount or environment value, a revoked secret grant. Its image
  staying allowlisted does not save it. A container created after the
  acknowledgement is still admitted by the source policy, and joins the pending
  set if the target drops its rule.
- **Switched.** The coordinator has authorized the target, which it does once
  every frozen participant acknowledged. The node applies it — the only step
  that widens what may run. A node that enrolled after the freeze, and so
  acknowledged nothing, marks its own retired containers pending first.
- **Drain.** Pending containers keep running: `Synchronize` leaves them alone
  even though the applied policy no longer admits them, and they are not
  restarted or re-admitted — a *new* container matching only a removed rule is
  refused like any other. When the last pending container is gone, the node
  posts its completion; an update that retired nothing here is completed at
  once.

Each node joins as a **participant** with a boot key generated at process
start. A plugin restart is therefore a new participant that re-enrols, and the
pending set does not survive it: CDS keeps the old boot outstanding until it
completes, and an unreachable participant blocks the update rather than being
dropped from it. An enrollment that arrives while an update is outstanding is
refused with 409 and retried on the next poll, so a joining node never serves as
a participant the update did not freeze. Set `plugin.node_name` to label the
node; the boot key, not the name, is the identity.

The **authority** is the fingerprint of the key CDS signs state with. The node
learns it from the first statement the attested pull channel carries, and
re-learns it only when it changes *and* the new statement verifies under the key
it carries — what a CDS restart looks like, since the signing key is generated
in memory and never persisted. Re-learning it re-enrols the node: the restarted
CDS knows nothing of this boot. `allowlist.pull.authority` pins the fingerprint
(`sha256:<hex>`); with it set, a statement from any other authority is refused
and the node keeps enforcing what it has applied.

Each enforcer also carries a **local seed** that admits by digest alone ahead of
the served document and is never touched by a pull: the host NRI plugin's
`always_allow` (chart-rendered from the chart's own component digests plus every
`bootstrapAllowlist.workloads` container admitted under any command and args).
That is what lets a node enforce at t=0 offline and bring the platform's own images
up before CDS is reachable.

## Publication, the coordinator and the journal

CDS records every allowlist change in an append-only journal and serves a signed
statement of what is in force. A write no longer takes effect the moment it
lands: it is **published**, and the coordinator **switches** enforcement to it
once every participant has a barrier in place. That split is what lets a rollout
account for instances still running under the policy being replaced.

Nothing in it is operator-driven. There is one outstanding update at a time,
from the write that published it to the last participant's completion, and the
coordinator moves it along as the acknowledgements arrive.

### Terms

| Term | Meaning |
| --- | --- |
| Version | The publication counter. It increases on every write; it says what exists, not what is enforced. |
| Active version | The version enforcement uses. `GET /allowlist` serves it, a certificate is stamped with it, and a secret is released against it. |
| Policy digest | SHA-256 of the canonical policy bytes. It is what a verifier pins. |
| Authority | The fingerprint of the key CDS signs state with. It is generated in memory at startup, so a restart is a new authority and every verifier re-anchors. |
| Log position | The position in the journal. It is dense and 1-based, so a gap is detectable. |
| Update | One move from the active policy to a published target. Only one may be outstanding. |
| Bound | The policy digests a participant on the protected path may still be executing under — what a verifier accepts or refuses. |

### Two events

The journal carries two event types, and a verifier needs no others to read the
bound:

- **`published`** records a target policy, the source it replaces, and whether
  retiring the source needs a drain (`requires_drain` is true when the target
  drops a rule the source granted). From here the bound is source-or-target: the
  publication announces potential exposure before any target-only permission can
  be used. It is not a claim that the target runs anywhere.
- **`drained`** records that every participant applied the target and nothing
  still holds a permission only the source granted. The bound narrows to the
  target. An additions-only update never emits one: its bound was the target
  from publication.

### Endpoints

Reads need no authorization; the RA-TLS channel authenticates CDS and every
answer is self-verifying.

| Route | Answer |
| --- | --- |
| `GET /.well-known/c8s/objects/sha256/<hex>` | The exact stored bytes of one object: a policy document or a journal entry. |
| `GET /.well-known/c8s/allowlist/latest` | Publication head: authority, version, policy digest, log head. |
| `GET /.well-known/c8s/state` | The signed state statement. |
| `POST /.well-known/c8s/state/challenge` | The statement bound to a caller's nonce, for strict freshness. |

Nodes post their own boot-key-signed messages to
`/.well-known/c8s/participants/{enroll,ack,complete}`. Those are not operator
routes, and the router's public front door does not publish them.

### The rollout

1. **Publish.** An allowlist write stores the resulting document as an object,
   appends `published`, and freezes the participant set that must acknowledge:
   every boot enrolled at that moment. Admission, issuance and secret release do
   not move.
2. **Switch.** When every frozen participant has acknowledged its barrier, the
   active version becomes the target. With nothing enrolled that happens in the
   publishing transaction itself.
3. **Complete.** When every frozen participant reports the target applied and
   nothing left holding a retired permission, CDS appends `drained` if the
   update needed one, and releases the single-update lock.

A second write while an update is outstanding is refused with `409` and **does
not touch the store**, so the operator repeats the whole request once the
rollout finishes. An enrollment during an update is refused the same way, and
the joining node retries on its next poll: a boot the freeze never captured must
not serve as a participant CDS is waiting on.

### First start

On its first start CDS publishes the installed allowlist as version 1. Nothing
has enrolled yet, so it switches and completes at once and a fresh cluster is
never left with a policy that exists and enforces nothing. A restart whose seed
adds entries publishes the result as the next version, rolled out like any
other.

There is no import path. A start that finds entries in the allowlist store and
an empty journal fails closed: publishing them would record a history no
operator authorized. Start from an empty store, or seed one with
`--allowlist-seed`.

### Rolling out a change

Write the entry the way you always have. Publication and rollout follow from it:

```sh
c8s allowlist apply entry.json
curl -s https://cds.example:8443/.well-known/c8s/state
```

The statement's `update` is `null` once the rollout is over. While it is
outstanding, `switched` says whether admission has moved to the target, and
`requires_drain` says whether the bound still covers both policies. A write that
answers `409` means a previous one has not finished.

### When a node does not answer

An unreachable participant blocks completion, and so blocks the next
publication. That is deliberate: there is no fence. Removing a node from
Kubernetes or from a registry cannot assert that its workloads stopped, and a
timeout cannot either, so CDS keeps the old permissions in the advertised bound
and refuses another update rather than emitting a drain nobody proved. Every
acknowledgement that leaves a participant outstanding is logged at warn, naming
it. Recovering from a node that will never answer means rebuilding the
deployment.

### Storage

The journal lives in its own SQLite database beside `--allowlist-db`, as
`coordinator.db`. It holds the objects, the journal index, the deployment id and
the coordinator's private participant and update state — never the signing key,
which is generated in memory at startup and never written anywhere.

CDS verifies the whole chain at startup and refuses to start on a journal that
does not recompute, or on private state that disagrees with the journal head.
There is no repair path: serving from a modified history would tell verifiers
something that never happened.

A restored database snapshot is not detectable from inside CDS. The chain proves
that what a client sees continues the history it already saw; proving that no
other branch existed needs the independent authority witness the design calls
for, which is not wired yet.

## Bootstrap

The chart renders the seed (`--allowlist-seed`) from the resolved component
digests (`c8s.imageAllowlist`) plus any `bootstrapAllowlist.workloads`. Each
component digest becomes one entry named `<image basename>-<first 12 hex of
digest>` with a single container under `command: any, args: any`; an
operator-authored `workloads` entry of the same name replaces it whole in the
rendered seed. Operator entries admitting a digest under any command and args
also feed the host plugin's `always_allow`; an entry that pins a command line
is seed-only. The
name is a function of the digest because CDS seeds **additively by name**: an
image bump adds the new digest's entry beside the old one, which pods still
running the old image keep matching while they recycle. The seed never
overwrites an entry the store already holds, so an edit made with `workload
apply` survives a restart, while a deleted entry returns on the next CDS start
for as long as the chart still renders it — to remove an image, roll the chart
with it gone. During an upgrade an enforcer that pulls the old document shape
before CDS restarts admits only workload containers until its next pull.

## CLI

`c8s allowlist` reads and mutates the allowlist. Reads are unauthenticated (the
RA-TLS channel provides integrity); writes are signed with the operator key you
supply via `--operator-key` (or `C8S_OPERATOR_KEY`). Persistent flags: `--url`,
`--measurements`/`--measurements-file` (RA-TLS pins), `--timeout`,
`--operator-key`, `-o text|json`, `--insecure`.

```
c8s allowlist
  list                              entry summary table
  get <name>                        one entry as canonical JSON
  export [file]                     write the full canonical document
  diff <file> [--exit-code]         entry/field diff vs the live allowlist
  add <digest> <image>              entry admitting the image under any command line
  derive <name> <file|->            entry from a live Pod/Deployment (pipe to apply)
  apply <file|-> [--dry-run]        upsert entries (whole-entry replace)
  edit <name>                       fetch, $EDITOR, diff, confirm, apply
  delete <name>...
  upload <file>                     replace the whole allowlist (diff-first, required-components guard)
  lint <file|-> [--online] [--strict]
  inspect-image <ref>               show an image's digest + baked entrypoint/cmd
```

`add` writes the same entry the chart seeds for a bootstrap digest, under the
same name (`<image basename>-<first 12 hex of digest>`), so a later chart bump
that derives the digest adds nothing.

Deleting a chart-seeded component entry does not lock its image out: the NRI
plugin's `always_allow` still admits it. To block a
compromised component image, roll the chart with the bad digest replaced.

### Editing and applying

Whole entries are the unit of a write. `apply` and `edit` replace an entire entry
and show the field diff first; nothing field-merges, so no command can silently
clobber a sibling field. `edit <name>` is the fetch → `$EDITOR` → lint → diff →
confirm loop, and the signed write is always a separate, reviewed `apply`.

### Footguns the CLI removes

- **No raw `""`/`"*"` on the command line.** Policies are keywords (`deny`,
  `any`) or an argv captured verbatim after `--`; the tri-state sentinels live
  only inside files. Nothing can be shell-globbed or silently emptied.
- **The wrong shape errors, never half-works.** A malformed entry or name fails
  validation instead of partially applying.
- **Signed writes are diff-first and lint-first.** `upload`/`apply` run the
  offline lint and print the diff before the write. A lint error blocks the
  write; `--strict` makes warnings block it too.

### lint

`lint` catches the semantic traps before a write: an entry that admits nothing
(both lists empty), a `command: deny` container that can never start, a
shared digest whose union is widened to `any` by some entry — an `any`-policy
entry for a digest silently makes every narrower entry for it unenforced at the
per-container gate — and tag-form labels (which can move under the operator).
`--online` cross-checks digests against the registry with
`crane`; `--strict` turns warnings into a non-zero exit for CI.

Two entries declaring the same containers with the same argv policy are an
**error**, not a warning: release requires exactly one entry to describe a
sandbox, so entries of the same shape either both match or neither does, and
every pod resolving to them is refused whichever grant was meant. Nothing a
workload can do resolves it. A [shadowed](#a-digest-may-run-many-ways) entry
is an error for the same reason. The shape compared is digests and argv policies per
container list — the image label and the secret grant are excluded, since two
entries alike but for their grants are exactly the case worth catching.

`apply` and `add` run that check against the served allowlist as well as the
file, because the entry a new one collides with is usually one already there.

## Operator credentials

Generating an operator key and pinning its public half is unchanged; see the
README and [`operator.md`](operator.md). Rotating the pinned set rolls CDS, and
a verifier detects a changed write policy by comparing the served
`/operator-keys` list against its own bundle. Secret grants (`secrets`) are
managed with the same `edit`/`apply` flow.
