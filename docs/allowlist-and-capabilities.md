# Allowlist and capabilities

How c8s decides which container images may run, which commands they may run
with, and — for future key-management integration — which secret paths they may
read and write. This document complements
[`kata-image-policy.md`](kata-image-policy.md) (where enforcement happens inside
a kata guest) and [`ratls.md`](ratls.md) (how the allowlist is bound into
attestation).

> **Trust model.** The host, hypervisor, and Kubernetes control plane are
> untrusted; the trust boundary is the TEE. The image *reference* a pod presents
> (`docker.io/vllm/vllm-openai:v0.6.3`) is chosen by the untrusted host and is
> not bound to the bytes that run. The image *digest* is. So every trust decision
> in this design keys on the digest — the reference is a label for humans, never
> a lookup key.

## The model

The active allowlist has two layers. Node-CVM also has a separate local
cold-boot floor.

- **Floor** — `digests`: a `digest -> image-label` map. An image whose digest is
  in the floor may run, **by digest alone**, regardless of its command line. The
  active compatibility entries can live here. Floor entries carry no process
  or path policy. New production policies must use exact workload entries.

- **Workloads** — `workloads`: named entries, each pinning an init/main
  container set. Every container binds a **digest** to the process policy
  (`command`, `args`) permitted for those bytes, and the entry as a whole may
  carry a secret-store grant (`secrets`). The
  entry name is operator-chosen. Optional `identity` is a stable mesh peer name.
  It defaults to the exact entry name. The entry `label` and per-container
  `image` are informational. Policy is always resolved by container digest.

The floor answers "may these bytes run at all"; the workload layer answers "and
with what command line, and what filesystem access". A digest may appear in the
floor, in one workload entry, or in several — see [union
semantics](#a-digest-may-run-many-ways).

On node-CVM, the local cold-boot floor admits the pinned c8s system bytes before
CDS is reachable. It is not part of the active allowlist. After the first
authenticated CDS pull, NRI removes that floor and applies the active policy as
one unit. The new policy must give every live Pod one exact named entry. If
it does not, NRI keeps the cold-boot policy and retries.

### Document shape

```json
{
  "schema": "c8s.allowlist/v1",
  "digests": {
    "sha256:<cds>":       "ghcr.io/confidential-dot-ai/cds",
    "sha256:<get-cert>":  "ghcr.io/confidential-dot-ai/get-cert"
  },
  "workloads": {
    "vllm-llama-2026-09-01": {
      "label": "docker.io/vllm/vllm-openai:v0.6.3",
      "identity": "vllm-llama",
      "initContainers": [],
      "containers": [
        {
          "name": "vllm",
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

`identity` uses the same grammar and length bound. It is part of the canonical,
operator-authorized policy. The matched-workload receipt keeps both the exact
entry name and the stable identity. Mesh peers pin the identity. Secret grants
and allowlist resolution use the exact entry name.

For a rolling update, keep the old and new exact entries in one active policy.
They can share one identity. This lets the fail-closed node policy cover both
live versions. Their container sets must still resolve without ambiguity. After
the old Pods drain and their named certificates expire, remove the old entry.

Use four steps. First, roll c8s, verifiers, and mesh proxies that read v1 and
v2. Keep `identity` absent and keep the exact-policy pin. Second, add `identity`
to the same exact entry and renew the v2 leaf. The exact pin still matches.
Third, change the proxy to the explicit stable-identity pin. Fourth, add the
new versioned entry with the same identity. A v1-only peer rejects v2. Do not
start the second step before the first step is complete.

**Migration.** An over-long entry created before the bound is still served by
CDS and still counts toward the document's canonical digest, but no pod can be
named for it and every consumer ignores it. Rename it — `c8s allowlist workload
put <new-name>` followed by a delete of the old one — and pods matching it start
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

Generated entries also pin the Kubernetes container `name`. The inventory
records that name and the resolved `init` or `main` role. Complete-set matching
uses a one-to-one assignment. One observed container cannot satisfy two
declarations. A stopped main cannot satisfy a required live main. A stopped init
can remain in the high-water record.

An old entry with no names remains usable when each process tuple identifies
only one role. An unnamed init and main with the same tuple are ambiguous. The
parser rejects that entry and tells the operator to re-derive it with names.

### What the enforcers see

The enforcers that gate container start (the host NRI plugin, and the in-guest
policy-monitor under kata) observe the container's **effective argv**: the OCI
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
guarantee is recovered at [cert issuance](#where-its-enforced).

## Mount and environment policy (`mounts`, `env`)

An image digest pins the bytes, and process policy pins what runs them, but
neither says anything about what the host lays *over* those bytes at start-up.
With `shared_fs="none"` the runtime seeds every configmap, secret and
serviceaccount token by copying it into the sandbox seeding directory and
bind-mounting it in — a mechanism a pod cannot work without, and one whose
source directory the host may write. Staging a file there and binding it over a
path inside the image runs host code from an allowlisted digest, and every
digest still reports as admitted.

Client-side verification does not catch this, unlike a pod whose trust
configuration was repointed: the pod keeps its genuine identity — real CDS, real
mesh CA, correct launch measurement — and a verifying client passes it and sends
data to a container running injected code.

`mounts` constrains **bind** mounts only, by destination. The rest of a mount
table names filesystem types (`proc`, `sysfs`, `tmpfs`, `devpts`, `mqueue`,
`cgroup`) and carries nothing in, so pinning it would only make an operator
restate the OCI base set to say nothing. `env` constrains variable **names**;
values are never matched, because the allowlist is served to every enforcer and
values carry secrets. `LD_PRELOAD` is the case that motivates it — an injected
name is code execution inside an otherwise-allowlisted image.

```json
"mounts": { "policy": "exact", "destinations": ["/etc/hosts", "/config"] },
"env":    { "policy": "exact", "names": ["PATH", "MODEL_DIR"] }
```

`exact` requires every observed bind destination (or name) to appear in the
list. An `exact` destination list is what the pod's `volumeMounts` declare plus
the handful the kubelet always adds — `/etc/hosts`, `/etc/hostname`,
`/etc/resolv.conf`, `/dev/termination-log`, `/dev/shm`, the serviceaccount token
— so it is written against a pod spec, not guessed.

Both default to `any` when absent, unlike argv, which defaults to `deny`. A
container always carries a mount table and an environment it never declared, so
a `deny` default would refuse every real pod and adopting the field would mean
adopting an outage. That makes these opt-in: a digest with no policy is
constrained exactly as much as it was before.

`mounts.kinds` records a small storage trust class. `private` is TEE-local
memory. `node` means the source can be persistent or host-selected. New policy
requires an exact class match. The node-CVM NRI reports `private` only for a
canonical source under the current Pod UID, in the memory-emptyDir plugin
location, that the kernel reports as an exact tmpfs mount point. A victim Pod
path, a hostPath plugin, a symlink, an ordinary tmpfs directory, and a path that
only contains a familiar substring all report as `node` or `unknown`.

This check proves TEE-local memory and current-Pod placement together. It does
not prove every Kubernetes volume type. The generator therefore classifies
disk emptyDir, ConfigMap, Secret, Projected, PVC, service-account, and hostPath
mounts as `node`. The older `pod` and Kubernetes kind values remain parseable
for document compatibility, but they do not accept the new conservative `node`
evidence. Re-derive those entries before this enforcer version becomes active.
New generated policy does not claim that evidence.

The pod-CVM OCI spec does not retain the original Kubernetes volume class.
Policy-monitor reports `private` only for a canonical, exact tmpfs mount that is
one direct child of kata-agent's fixed TEE-local ephemeral root,
`/run/kata-containers/sandbox/ephemeral`. It reports every other bind source as
`node`. This includes another guest tmpfs and a subdirectory below an ephemeral
volume. It does not infer ConfigMap, Secret, or emptyDir from a host-selected
path. This keeps exact policy deployable without a false source claim. A
secret-bearing memory volume such as `public-tls` requires `private`, so a
hostPath replacement fails. A `subPath` policy is `node` because both enforcers
cannot prove the direct private-volume identity after that conversion.

Two limits apply. They bind only digests a `workloads` entry names.
floor digests are admitted on the digest alone, so `c8s allowlist add` does not
produce a mount-gated image. The host NRI plugin reads these fields from the
effective CRI container. The in-guest `policy-monitor` reads them from the guest
OCI spec. Both inventories send the observed names and destinations to CDS.
An exact policy fails closed if an old inventory does not report the field.

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

Three independent points enforce, at different strengths:

1. **Host NRI plugin** (`nri-image-policy`), at CreateContainer, per container.
   Resolves the image digest. It checks effective argv, bind-mount destinations,
   and environment variable names against the allowlist. It does not retain
   environment values. It fails closed before the allowlist first loads. It runs on the untrusted
   side of the TEE boundary for kata pods, so it is defense-in-depth there, and
   the primary gate for non-kata (base-mode) pods.

2. **In-guest policy-monitor** (under kata), watching each new container's
   `config.json`. This is the load-bearing gate for confidential pods: the host
   is untrusted, guest-pull is forced, and a violation is a SIGKILL of the
   container. It reads the digest, `process.args`, the bind-mount destinations
   and the environment variable names out of the guest OCI spec, and applies the
   same index — so it is the enforcer that honours `mounts` and `env` policy.

3. **CDS at cert issuance**, in `resolveSandboxWorkload`. Before signing a leaf
   for a pod, CDS asks that pod's own inventory which images its sandbox is
   running (`docs/ratls.md`, "Sandbox identity"). Every reported digest must be
   allowlisted (floor or workload), checked against one atomic allowlist
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

Per-container digest and argv admission holds at all three points. NRI and
policy-monitor see containers one at a time. They cannot deny a missing
container during Pod start.

CDS applies a complete-set rule when it grants a named certificate or an
application secret. The trusted high-water inventory must contain every main
container and every observed helper. It must match one named workload entry.
An ordinary unnamed mesh certificate can still be issued during partial Pod
startup, but it cannot satisfy a workload-name pin or receive a protected
secret. This gates identity and secret release. It does not measure the
container combination into RTMR3.

### Injected c8s containers

An exact workload entry must include every c8s container that the webhook
injects. This includes `c8s-cert`, `c8s-cert-wait`, secret fetchers, and volume
fetchers. Each entry pins the effective digest, argv, mounts, and environment
names. CDS does not remove a helper by digest or by an argv prefix. Such a rule
would let an untrusted Pod add `/c8s workload-proxy` with attacker settings and
still get the named certificate or application secret.

The injected arguments are deterministic functions of the deployment values
and Pod template. Generate policy from the final rendered or mutated Pod. Do not
write one broad c8s helper rule for all workloads.

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
operator public keys it pins. The same operator keys authorize floor and workload
writes alike.

### Refresh, floor, and anti-rollback

Consumers poll `GET /allowlist` and refresh on a changed version (the ETag
counter). The two layers refresh differently, because they have different
failure modes:

- On **node-CVM**, the local cold-boot floor exists only until the first
  authenticated CDS policy is safe to apply. A failed initial pull keeps that
  floor. A successful pull replaces it. A failed later refresh keeps the last
  authenticated policy. The floor does not return.

- In **pod-CVM**, the measured guest floor remains additive. It is anchored by
  the guest image and starts enforcement at time zero. The CDS workload overlay
  still swaps by version.

- The **workload policy overlay swaps wholesale, gated by a monotonic epoch**
  (the version counter). A consumer applies a pulled overlay only if its version
  is greater than the last applied, and ignores a regression. This matters
  because workload policy can *tighten* (narrow `args`, revoke a `secrets` grant);
  a plain additive merge would let a host that withholds an update keep a laxer
  policy live forever. Epoch-gated replacement makes a withheld or rolled-back
  update fail toward the last-known-good policy, not toward the laxest one. The
  high-water-mark is process-local, so this rejects rollback only within a
  consumer's lifetime: after a restart (a fresh CVM, for the in-guest monitor)
  the first version seen is trusted and state re-syncs from CDS. A reboot-durable
  guarantee needs an attested freshness / monotonic-counter mechanism the host
  cannot reset — a tracked follow-on.

On node-CVM, the live-runtime guard and the policy pointer swap hold the same
write lock that container admission reads. Admission holds its read lock until
it records an allowed container. Thus, a container is fully checked and
recorded before a transition, or it is checked against the new policy after the
transition. It cannot enter through the old floor after the guard has passed.
Node inventory reads use the same read lock. They cannot report roles from the
new policy with the old policy digest or version.

On pod-CVM, policy-monitor holds one overlay read lock across the final
admission decision, role resolution, and inventory record. An overlay update
cannot split those operations across two policy versions.

## Bootstrap

The chart renders resolved c8s component digests into each node-CVM NRI
plugin's local cold-boot floor. It does not copy those chart-derived entries to
CDS. `c8s install --resolve-digests` first renders the chart, reads each pinned
image's OCI process configuration, and derives one exact named entry for every
steady Deployment, DaemonSet, and StatefulSet. It then renders the release a
second time with those entries in the CDS seed.

Use `c8s allowlist derive-system <rendered.yaml> --base <application.json>` for
a manual Helm flow. `enableServiceLinks: false` is required. The command rejects
floating images, `envFrom`, unsupported volume sources, and empty effective
argv. It includes container names, init containers, and native sidecars. It
also models the effective CRI inputs. `enableServiceLinks: false` removes
workload Service variables. The exact environment admits only declared names
and the kubelet `KUBERNETES_` API family.

Kubernetes expands `$(NAME)` before NRI sees argv. The generated policy records
an environment binding for `HOST_IP` or `NODE_IP` only when the rendered Pod has
one `status.hostIP` downward-API env item with that name. NRI and policy-monitor
observe the final argv and the effective CRI environment together. They admit
the argv only when its expanded bytes match the one observed value. A missing,
changed, or duplicate binding value fails closed. The operator carries a stable
non-Kubernetes token and the webhook converts it to `$(HOST_IP)` only in the
tenant Pod that kubelet will expand.

The guest-baked seed remains a flat `sha256_digests` list — it is the floor,
measured into the SNP launch digest, and keeping it digest-only means a policy
change never requires a guest-image rebuild.

## CLI

`c8s allowlist` reads and mutates the allowlist. Reads are unauthenticated (the
RA-TLS channel provides integrity); writes are signed with the operator key you
supply via `--operator-key` (or `C8S_OPERATOR_KEY`). Persistent flags: `--url`,
`--measurements`/`--measurements-file` (RA-TLS pins), `--timeout`,
`--operator-key`, `-o text|json`, `--insecure`.

```
c8s allowlist
  canonicalize <file|->              write canonical bytes without network use
  digest <file|->                    hash the canonical bytes without network use
  derive-system <rendered.yaml|->    derive exact named c8s system Pod policy
  list                              floor table + workload summary
  export [file]                     write the full canonical document
  diff <file> [--exit-code]         entry/field diff vs the live allowlist
  add <digest> <image>              add a floor digest
  remove <digest>...                remove floor digests (warns on component-floor images)
  upload <file>                     replace the whole allowlist (diff-first, required-components guard)
  lint <file|-> [--online] [--strict]
  inspect-image <ref>               show an image's digest + baked entrypoint/cmd

  workload list | get <name>
  workload apply <file|-> [--dry-run]
  workload edit <name>
  workload delete <name>...
```

### Editing and applying

Whole entries are the unit of a write. `apply` and `edit` replace an entire entry
and show the field diff first; nothing field-merges, so no command can silently
clobber a sibling field. `edit <name>` is the fetch → `$EDITOR` → lint → diff →
confirm loop, and the signed write is always a separate, reviewed `apply`.

### Footguns the CLI removes

- **No raw `""`/`"*"` on the command line.** Policies are keywords (`deny`,
  `any`) or an argv captured verbatim after `--`; the tri-state sentinels live
  only inside files. Nothing can be shell-globbed or silently emptied.
- **The wrong shape errors, never half-works.** `workload delete` takes names;
  `remove` takes `sha256:` digests; a mixup fails validation instead of partially
  applying.
- **Signed writes are diff-first and lint-first.** `upload`/`apply` run the
  offline lint and print the diff before the write. A lint error blocks the
  write; `--strict` makes warnings block it too.

### lint

`lint` catches the semantic traps before a write: an entry that admits nothing
(both lists empty), a `command: deny` container that can never start, a
shared digest whose union is widened to `any` by some entry, a digest that is
floor-listed while also carrying a workload policy — the floor admits it by
digest alone, so the process policy is not enforced — tag-form labels
(which can move under the operator), and a summary of how many `any` policies a document carries. `--online` cross-checks digests against the registry with
`crane`; `--strict` turns warnings into a non-zero exit for CI.

Two entries declaring the same containers with the same effective policy are an
**error**, not a warning: release requires exactly one entry to describe a
sandbox, so entries of the same shape either both match or neither does, and
every pod resolving to them is refused whichever grant was meant. Nothing a
workload can do resolves it. The shape includes container names, roles, digests,
argv, mounts, and environment policy. The image label and the secret grant are
excluded. Two entries alike only in those fields are the case worth catching.

`workload apply` runs that check against the served allowlist as well as the
file, because the entry a new one collides with is usually one already there.

## Operator credentials

Generating an operator key and pinning its public half is unchanged; see the
README and [`operator.md`](operator.md). Rotating the pinned set rolls CDS, and
a verifier detects a changed write policy by comparing the served
`/operator-keys` list against its own bundle. Secret grants (`secrets`) are
managed with the same `workload edit`/`apply` flow.
