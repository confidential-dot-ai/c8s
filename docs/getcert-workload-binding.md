# get-cert and the sandbox-identity → RA-TLS cert binding

This walks the **sandbox-identity** path end to end: how a pod's mesh
certificate comes to name the sandbox it was issued to, how CDS gates that
issuance on what the sandbox is actually running, and the several corners that
routinely confuse people. It is the companion narrative to
`docs/ratls.md` (the normative wire spec) — read this for *how the flow
works and why it is safe*, read that for *the byte formats and verification
rules*.

---

## The one-paragraph version

`get-cert` (the injected `c8s-cert` sidecar) asks a node-local **inventory** —
part of the image-admission component itself (`nri-image-policy` on node-CVM,
`policy-monitor` on kata), not a standalone service — "which pod sandbox am I
in?" *without saying who it is*. The inventory learns the caller's identity
from the **kernel** (unix-socket peer credentials), maps it to a sandbox, and
returns a **signed token** naming that sandbox, the requester's key, this
issuance's CDS challenge, and the address of its own digests endpoint.
`get-cert` forwards the token to CDS and says nothing about its own images.
CDS verifies the token, then calls that inventory back over mutually-attested
RA-TLS and asks what the sandbox is running; it issues only if every image is
allowlisted and the non-floor set matches one workload entry, and stamps the
sandbox ID onto the leaf. A relying party can then pin the workload
(`c8s verify --sandbox-id <id> --mesh-ca ca.pem`) or read a live mesh peer's ID
off the connection with `ratls.PeerSandboxID` (docs/ratls.md, "Reading a peer's
sandbox ID").

---

## FAQ — "wait, isn't this brittle?"

The flow looks indirect on first read. It is indirect on purpose: every
shortcut (let the pod report its own image, name the pod in the request, trust
get-cert outright) is a forgery vector. The answers below are the quick
version; each points at the Corner with the full argument.

**Doesn't the pod already know what image it runs?** It does not report one
either way. A pod is a set of containers; a single container sees its own
rootfs, not the registry *digest* it was pulled as, and nothing about its
siblings — and a malicious container could lie about its own digest regardless.
So the requester's only claim is *which sandbox it is in*; the image set comes
from the component that admitted those containers, asked directly by CDS.
(Corner 3, Corner 6.)

**How does the inventory know which pod is calling — is that operator-controlled?**
No, and that is the crux. get-cert sends no identity at all. When it connects,
the **kernel** stamps the caller's PID onto the socket (`SO_PEERCRED`); the
inventory reads that PID and resolves it PID → cgroup (`/proc`) → container → pod
from its *own* admission record. Every link is kernel/runtime-derived — nothing
the caller or the control plane supplies is used for identity. The kernel doing
the stamping is in the TCB (the node is the CVM under node-CVM; the measured
guest under kata). (Corner 1.)

**Does get-cert check it's in a TEE first?** No, and it doesn't need to. It
generates attestation evidence via the local attestation-api, and **CDS**
verifies that evidence — hardware signature chain plus the pinned launch
measurement — before issuing anything. Outside a real TEE the evidence does not
verify, so no certificate is issued. (Step 5; `docs/ratls.md`.)

**How does CDS know to trust get-cert — is it baked into the base image?** For
the image set it does not have to trust get-cert at all: get-cert is a conduit
for a token it cannot forge, and CDS asks the inventory itself. get-cert's own
integrity is still allowlist/measurement-rooted — under node-CVM its image runs
only because nri-image-policy admitted it; under kata it is baked into the
measured guest image — and the compiled-in socket path means the control plane
cannot repoint it at a rogue inventory. (Corner 5, Corner 6.)

**What stops a malicious pod claiming some other workload's identity?** It
cannot mint the token. The sandbox token is signed by an in-process inventory
key whose EAR CDS issued against an allowed launch measurement, and it names
the sandbox the *kernel* said the caller is in — so a pod can only ever obtain
its own sandbox ID. It cannot suppress the callback either: the inventory
address is inside the signature, and CDS re-verifies the RA-TLS identity of
whatever answers there. What a malicious pod *can* do is present no token at
all, which yields a leaf with **no** sandbox ID — and that fails any
`--sandbox-id` pin. What remains is not forgery but trust in the inventory
itself (Corner 6) and in the mesh CA signature that carries the ID (docs/ratls.md,
"What vouches for the ID").

**Is the unix socket secured so a malicious pod can't hijack it?** Two separate
threats:

- *Impersonating another pod over the socket* — closed by `SO_PEERCRED`. The
  socket's mode gates who can *reach* the inventory, but identity comes from the
  kernel-reported PID, not anything a caller sends, so even a reachable caller
  is bound to its own pod.
- *Replacing the socket file* — the real hijack vector. get-cert mounts the
  socket directory **read-only**, so it cannot swap the socket from inside its
  own pod. On node-CVM the socket lives on a host directory, so a *separate*
  malicious pod that could `hostPath`-mount that directory read-write could
  swap the socket before get-cert connects — a PodSecurity / filesystem-
  permission concern (the socket dir must be unwritable by untrusted pods), not something attestation closes. Under kata the mount is a
  guest bind-mount inside the measured VM, so there is nothing host-supplied to
  swap. **Who creates the socket, and why the L0 host can't inject one, is
  Corner 7.** (Corner 5, "Why a unix socket".)

---

## The actors

- **get-cert** — runs in the `c8s-cert` native sidecar the webhook injects
  into every `confidential.ai/cw` pod. Generates the leaf key, builds the CSR,
  redeems a sandbox token, drives the CDS attestation flow, writes the cert.
  (`internal/cmds/getcert`)
- **The inventory** — the component that already makes the admit/deny decision,
  so what it vouches for is exactly what was admitted. It serves two disjoint
  surfaces (`pkg/workloadclaims`): `POST /sandbox` on a node-local **unix
  socket** get-cert dials at one compiled path, and `GET /digests/{sandboxID}`
  on a **network endpoint over mutually-attested RA-TLS** that only CDS can
  reach. The socket cannot enumerate other sandboxes; the network endpoint
  cannot mint identity.
  - **node-CVM**: `nri-image-policy` (the host NRI plugin). The node is the
    confidential VM, so the plugin is in the TCB.
  - **pod-CVM (kata)**: `policy-monitor` inside the measured guest, whose
    socket directory the guest bind-mounts into the pod.
- **CDS** — verifies the evidence and the sandbox token, calls the inventory
  back for the sandbox's images, checks each against the allowlist store, signs
  the leaf with the mesh CA, stamps the sandbox ID.
- **The verifier** — anyone doing `c8s verify --sandbox-id … --mesh-ca …`, or a
  mesh peer pinning `VerifyPolicy.SandboxID`.

---

## Step by step

1. **get-cert fetches the CDS challenge first.** One single-use nonce then
   binds both the sandbox token and the evidence REPORTDATA, so the token rides
   the issuance's existing freshness rather than a wall clock of its own
   (`internal/cmds/getcert/run.go`, `obtainCert`).

2. **get-cert asks, anonymously.** It opens the inventory at its compiled Unix
   socket path (`--workload-claims`, the same in both shapes) and `POST`s
   `/sandbox` carrying only its CSR public key and that challenge. The request
   carries **no** PID, pod name, or container ID. (See "Corner 1".)

3. **The inventory binds the caller from the kernel and signs.** On the unix
   socket it reads the peer's PID with `getsockopt(SO_PEERCRED)`
   (`pkg/workloadclaims/peercred_linux.go`), resolves that PID to a container
   via `/proc/<pid>/cgroup` (`cgroup.go`), maps container → sandbox from its own
   admission record (`SandboxForPeer`), and signs a token over
   `(version 2, sandboxID, SHA-256(requester pubkey), challenge, inventoryAddr)`
   with an in-process key CDS attested via `POST /attest-key`. Nothing the
   caller *sent* is used for identity.

4. **get-cert forwards the token.** The envelope (token, signature, EAR) rides
   the `/attest` request body as `sandbox_token`, opaque to get-cert. It
   forwards **no image digests** — it has none to forward.

5. **CDS verifies, calls back, gates, and stamps.** It validates the EAR against
   its own JWKS, issuer, and measurement allowlist; verifies the token signature
   with the EAR's attested key; requires the token's nonce to be the challenge
   it is consuming and its key digest to name the CSR key. It verifies the
   requester's evidence and CSR policy as usual. Then it dials the token's
   `inventoryAddr` over mutually-attested RA-TLS (`workloadclaims.DigestsClient`,
   pinning the same measurements `/attest` uses, presenting CDS's own RA-TLS
   certificate) and asks `GET /digests/{sandboxID}`. Every returned image must
   be allowlisted, and the non-floor images must equal one workload entry's
   non-floor set. All pass ⇒ it signs the leaf and stamps the sandbox ID into
   its signed area (`internal/cmds/cds/attest.go` `verifySandboxToken` /
   `verifySandboxWorkload`, `internal/issuer/sign.go`).

6. **The relying party pins.** `c8s verify --sandbox-id <id> --mesh-ca ca.pem`
   requires the leaf to chain to the supplied mesh CA and to carry that exact
   sandbox ID. `--mesh-ca` is mandatory with `--sandbox-id`: the ID lives in the
   leaf's signed area, not in REPORTDATA, so CDS's signature is the only thing
   that authenticates it. In-mesh, `VerifyPolicy.SandboxID` is enforced on the
   CA-verified path only (`checkSandboxPin`).

---

## Corner 1 — get-cert sends no PID; the kernel reports it

The most common confusion: *how does get-cert tell the inventory which process to
look up?* It doesn't. If a caller could name a PID (or pod, or container), a
malicious pod would name a victim's and the binding would be worthless.

Instead, when the inventory **accepts** the unix-socket connection, the kernel
attaches the peer's credentials to the socket; the inventory reads them with
`SO_PEERCRED`. The PID comes from the kernel's own accounting of who opened the
socket. The chain is entirely kernel/runtime-derived — `SO_PEERCRED` → cgroup →
container → sandbox — and none of it is caller-supplied.

**Pinning the PID against reuse.** `SO_PEERCRED` returns a bare PID, and the
`/proc/<pid>/cgroup` read happens a few instructions later — a window in which
the peer could exit and the kernel recycle its PID to an unrelated process,
which the inventory would then resolve as the caller. The inventory closes this
by also reading `SO_PEERPIDFD` (Linux 6.5+), a pidfd that pins that *exact*
process instance, and rechecking `peer.IsAlive()` **after** the cgroup read: if
the pinned process exited during resolution — or the pidfd could not be obtained
at all — the answer is refused (`peercred_linux.go`, `Peer.IsAlive`;
`inventory.go`, `callerForPeer`). A supported CC node always has the pidfd:
`SO_PEERPIDFD` landed in Linux 6.5, and SNP hosts require ≥ 6.11, TDX ≥ 6.16, so
its absence is treated as an error and **fails closed**, not tolerated as a
best-effort fallback. This is orthogonal to Corner 2: the pidfd fixes *PID
identity over time*, the shallowest-tracked rule fixes *cgroup-nesting
spoofing*; both are needed.

**PID-namespace subtlety.** get-cert runs in a container where its own PID
might be 1. `SO_PEERCRED` reports the PID *as seen by the reader* — the
nri-image-policy plugin, which runs on the **host** (launched by containerd,
host PID namespace). So the kernel translates get-cert's PID into the host
namespace, and `/proc/<host-pid>/cgroup` on the host resolves to the
container's cgroup. This is why the plugin needs the host PID view and why
`workload_claims.proc_root` is `/proc` (the host's), not a mounted `/host/proc`.

**kata is simpler.** `policy-monitor` serves the *same* unix socket
(`policymonitor/inventory.go`), but in a kata guest there is exactly one pod, so
there is nobody to disambiguate: the inventory ignores the peer PID and returns
the guest's single sandbox ID (failing closed until it has observed one). Peer-cred
co-location does not matter here — the guest boundary *is* the isolation — but
reusing the socket lets get-cert dial one compiled path in both shapes.

---

## Corner 2 — the cgroup resolver picks the *shallowest tracked* container, not the deepest

A container's cgroup path can contain more than one 64-hex component
(CRI-O nests the sandbox ID above the container scope; an attacker can nest a
child cgroup). The resolver returns **all** candidates shallow→deep and the
inventory picks the shallowest that is a *tracked container*
(`ContainerIDCandidatesForPID`, `inventory.go`).

Why shallowest: a process can only move itself **deeper**, into cgroups it
creates — its runtime-assigned container scope is always an *ancestor* of
anything it nests. So a caller that creates a child cgroup named with a
victim's container ID produces `…/cri-containerd-<attackerCID>.scope/<victimCID>`;
shallowest-tracked resolves to `<attackerCID>` (the caller's own container) and
never to the nested victim. It also skips CRI-O's untracked parent sandbox ID
(it is not a tracked *container*). Taking the last/deepest match — the naive
choice — is the exploitable one.

---

## Corner 3 — the digests answer is one flat set for the sandbox, not a per-role split

`GET /digests/{sandboxID}` returns the **sorted, deduplicated** image digests of
every container the inventory currently tracks in that sandbox — user init
containers included (NRI's `CreateContainer` fires for init and regular
containers alike), and the c8s-injected `c8s-cert` sidecar included too. The
pause/sandbox container is in neither shape's answer: on node-CVM it never
reaches the plugin's `CreateContainer` hook, and in the guest policy-monitor
skips it (it is measured via the rootfs, not allowlisted). Unknown sandbox ⇒
404; a known sandbox with no containers ⇒ `{"digests": []}`.

- **Order-independent.** The same images in a different container order answer
  identically, so a reschedule that reorders containers does not churn the
  identity.
- **All-or-nothing.** If the inventory cannot resolve a tracked container's
  image digest it records an empty one (logged at error, see
  `recordForInventory`), and rather than answer with the containers it *can*
  describe — a subset passed off as the whole set — it fails the whole request,
  which CDS treats as fail-closed.
- **CDS excludes the floor, then matches exactly.** Injected c8s containers are
  allowlist floor entries, so their measured digests drop out of the comparison
  by digest, not by name. Whatever remains must equal one workload entry's
  non-floor set (`enforceWorkloadCombination`), so containers from different
  entries cannot be mixed into an unauthorized pod.

**Matching is set-based over init and main together.** The inventory tracks
admission, not pod-spec roles, so two workload entries differing only in which
role holds an image are indistinguishable here. What actually constrains how an
image runs — the per-container argv policy — is enforced at admission by
nri-image-policy / policy-monitor, where the role distinction is not needed
(`docs/allowlist-and-capabilities.md`).

---

## Corner 4 — the sandbox ID binds at first issuance; the combination gate is as-of-issuance

There is **one cert per pod**, not one per container. get-cert writes it to the
shared `c8s-certs` tmpfs, which the webhook mounts read-only into every
container, so the identity is the pod's — get-cert is just the thing that
fetches and renews it. The pod's single cert is minted *before the pod's app
containers are admitted*: the webhook injects `c8s-cert` as a **native sidecar**
(an init container with `restartPolicy: Always`) plus a `c8s-cert-wait` init
gate, and the app containers only start after all init containers pass.

The **sandbox ID** is unaffected by that ordering. get-cert's own sidecar
container is already tracked when it asks, so `SandboxForPeer` resolves at first
issuance and the leaf carries the ID from the start. (This is what the
requester-reports-its-own-images shape could not do: at first issuance it had
nothing to report.)

The **combination gate** is still evaluated against whatever is running at that
instant. At first issuance that is the injected sidecar alone — all floor
digests — so the non-floor set is empty and the gate passes vacuously. It bites
from the first renewal onward, once the app containers are up.

Everything that used to degrade to a claim-free certificate now **fails closed**
at issuance instead:

- **Staggered starts.** Regular containers start ~together, but a renewal
  landing mid-startup sees a partial set. If that partial set matches no
  workload entry, CDS refuses the renewal; the pod keeps serving on its current
  leaf and the next renewal succeeds. A strict verifier can still momentarily
  see a leaf issued against a partial set. Waiting for an expected container
  count before answering would fix it; not baked in.
- **Init-container eviction.** An init container runs to completion and exits;
  once the kubelet garbage-collects it, NRI fires `RemoveContainer` and the
  node-CVM inventory evicts it, so the sandbox's set shrinks. A workload entry
  listing init images must therefore still match after GC, or renewals start
  failing. A digest-set *change* here is expected, not tampering.
- **A plugin restart empties the inventory, and the startup check refills it.**
  The node-CVM inventory is in-memory only. `nri-image-policy` is not a pod — it
  is a host process containerd launches from `/opt/nri/plugins`, and NRI does
  not respawn it on exit — so it restarts when containerd does: a chart upgrade
  that bumps the plugin binary or its config (the installer restarts
  containerd), a node reboot, or a crash. Running containers survive that
  restart, so their digests must be re-derived; NRI replays `Synchronize` with
  the full container list on every plugin start, and `checkExisting` records
  what it admits. That recovery deliberately does **not** depend on
  `policy.enforce_existing` — that knob gates only the *kill* step, because
  "learn what is running" and "kill what shouldn't be" are separate concerns.
  Until the check completes, a callback landing in between gets a 404 (unknown
  sandbox) or a short set, and CDS refuses; get-cert retries at the next renewal
  interval. The window is bounded by the plugin's initial pull (backoff plus
  fetch timeouts, tens of seconds), against a renewal interval measured in
  hours.
- **A partially repopulated check.** The `c8s-cert` image sits in the plugin's
  `always_allow` floor, so the check always admits it; a tenant app image does
  not, and a check running after the allowlist changed can deny one. The
  sidecar is then tracked and the app container is not, so the callback answers
  a floor-only set and the renewal is issued against it. With
  `enforce_existing` on, the same check kills the offending container and the
  state cannot persist; with it off, tolerating that container is the operator's
  stated intent.

**Enforcement is on both sides now.** Issuance refuses a sandbox whose images
are not allowlisted or match no workload entry; a relying party pinning
`c8s verify --sandbox-id … --mesh-ca …` refuses a pod that carries no or a
wrong sandbox ID.

---

## Corner 5 — the inventory is not control-plane-redirectable, at either end

Two independent properties keep a malicious control plane out of the loop.

**get-cert's inventory target is measured, not injected.** get-cert dials a
**compiled** Unix socket path (`workloadclaims.InventoryEndpoint`, selected by
`--workload-claims`) in both shapes — the platform injects only the
read-only socket *mount* (a webhook hostPath on node-CVM, a guest bind-mount
under kata), never the path — so the control plane cannot point get-cert at a
rogue inventory by changing an arg.

**CDS's callback target is inside a signature, and re-verified on arrival.** The
`inventoryAddr` CDS dials comes from the sandbox token, covered by the
inventory's signature over the whole token — a host that rewrites it invalidates
the token. And reaching the address is not sufficient: the callback is
mutually-attested RA-TLS, so whatever answers must present a leaf whose launch
measurement is in the same allowlist `/attest` pins, and must in turn accept
CDS's own attested client certificate. An unreachable or unpinnable endpoint
refuses the issuance rather than downgrading it.

**Neither is an identity proof on its own.** The remaining assumption is the
inventory's honesty about what it admitted (Corner 6), and the fact that the
sandbox ID on the leaf is vouched by the mesh CA signature rather than bound
into hardware evidence (`docs/ratls.md`, "What vouches for the ID"). Making the
pod's images part of a hardware measurement, enforced at `/attest`, is the
stronger close and is unimplemented (GAPS §Trust model).

The one surface still on an untrusted path is the **node-CVM** socket mount:
the inventory socket sits on a host directory the webhook hostPath-mounts, so a
malicious *allowlisted* pod able to mount that directory read-write could swap
the socket file before get-cert connects. That is a PodSecurity /
filesystem-permission concern (the socket dir must be unwritable by untrusted
pods; overlaps THREAT_MODEL §Addressable), not a redirectable arg — see
the residual note under "Why a unix socket". Under kata the mount is a guest
bind-mount inside the measured VM, so it is not control-plane-supplied at all.

### Why a unix socket, not an HTTP/DNS endpoint

The *token* surface is reached over a **unix socket** (a kernel filesystem path)
in both shapes — never a network/hostname endpoint. That is deliberate; an HTTP
endpoint addressed by name would forfeit three properties:

- **Co-location.** `SO_PEERCRED` works only across a same-kernel socket, so the
  inventory get-cert reaches *is provably the one on its own node* — the real
  admission record for this pod (Corner 1). An HTTP call to another
  genuinely-attested node or pod cannot prove co-location: it would pass a
  measurement check yet answer for the wrong pod (the "any attested TEE passes"
  problem). This is also why authenticating the inventory's RA-TLS cert would not
  help — a cert proves *measurement*, not that you reached the local inventory.
  (Under kata there is one pod per guest, so co-location is free — but reusing
  the socket keeps get-cert on one compiled path in both shapes.)
- **DNS-immunity.** A kernel path has no name-resolution step. Cluster DNS is
  control-plane-configured, so a hostname endpoint would be redirectable
  *regardless of what value is baked in* — baking the name buys nothing. A unix
  socket sidesteps resolution entirely.
- **Non-redirectability.** get-cert bakes the socket path as a compiled
  constant (`workloadclaims.InventoryEndpoint`, in allowlisted/measured code), so
  the control plane cannot change *where* get-cert looks — the platform supplies
  only the socket mount, not the path. A network endpoint would be only as
  fixed as the arg carrying it.

The *digests* surface is a network endpoint precisely because none of those
three apply to it: CDS is not co-located with the inventory, it needs no
peer-credential binding (it names the sandbox the token already vouched for),
and its target address is signature-covered rather than name-resolved. What it
does need — that the answering party is a measured inventory and the asking
party is CDS — is exactly what mutual RA-TLS provides. The pattern: go over the
network by name only when you can authenticate the endpoint's measurement; stay
on the kernel-local socket when what you need is co-location, which attestation
cannot prove.

The residual left is neither DNS nor attestation: the socket file lives on a
node path, so a malicious *allowlisted* pod that can `hostPath`-mount that
directory read-write could swap the socket before get-cert connects. That is a
PodSecurity / filesystem-permission hardening (the socket dir must be
unwritable by untrusted pods), not more crypto.

Note this is *not* the same as the socket's own permissions. The non-root
get-cert reaches the socket because the inventory group-owns it
(`workloadclaims.InventorySocketGID`, mode 0660) and the webhook puts the sidecar
in that group — that is reachability for the *file*. The swap vector is about
the *directory*: the installer keeps it root-owned and non-world-writable (mode
0711, see the install script), so an untrusted pod still cannot unlink/replace
the socket. Group-owning the socket for liveness does not open the swap.

---

## Corner 6 — what CDS actually trusts (it can't inspect the running container)

CDS cannot independently observe a pod's running image digests — no component
outside the pod can. So how is the answer trustworthy? The chain, weakest link
named:

- **The evidence proves the requester is a measured TEE**, bound to the CSR key
  and challenge. That is what gates issuance at all; it says nothing about
  images.
- **The sandbox ID comes from the kernel, via a key CDS attested.** get-cert
  cannot choose it (Corner 1) and cannot forge the token (the signing key's EAR
  is a CDS-issued credential on an allowed measurement). It can only decline to
  present one, which costs it the sandbox ID entirely.
- **The ground truth for "what runs" is the inventory** — the admission record —
  and CDS asks it *directly*, at issuance, over a mutually-attested channel.
  There is no requester-supplied list to re-derive or cross-check, because the
  requester supplies none.
- **CDS's own backstop is the allowlist.** Every digest the inventory reports is
  re-checked against the allowlist store, and the non-floor set must match one
  workload entry. So even a compromised inventory cannot smuggle an
  unallowlisted image or an unauthorized combination past issuance.
- **The remaining assumption is the honest inventory on an honest node.** The
  EAR proves the signing key lives in a TEE on an allowed measurement — on
  node-CVM that is the whole node, so "came from nri-image-policy" rests on the
  measured node image running only the intended inventories (Corner 7). Under
  kata the guest boundary is per-pod, which is tighter.

"Did get-cert reach the *real* inventory" is not a control-plane-supplied link:
get-cert bakes one compiled Unix socket path for both shapes (Corner 5). What
remains is the node-CVM socket-file swap — a PodSecurity / filesystem-permission
item, not attestation (and under kata even that is gone, the mount being a
measured guest bind-mount).

---

## Corner 7 — who creates the socket, and why a hostile host can't inject one

A natural challenge: the socket is a filesystem object on the node — what stops
a malicious host from planting its own and answering for the inventory?

**First, who actually creates it.** Not the c8s installer. The nri-image-policy
installer DaemonSet only lays down three things on the node: the plugin
*binary* (into `/opt/nri/plugins`), a *containerd drop-in* that registers it as
a pre-installed NRI plugin, and the *runtime directory*
(`mkdir -p` + `chmod 0711`). The socket itself is created at **runtime by the
plugin**: containerd launches it as a node process and `workloadclaims.ListenUnix`
calls `net.Listen("unix", …)` — that syscall materializes the socket. It
`os.Remove`s the path first, so any pre-existing (stale or planted) socket is
deleted before it binds its own. Under kata the same is true of `policy-monitor`
inside the guest. So: **the inventory creates the socket, not the installer and not
the host.**

**The reframe that answers the challenge.** The socket is not a root of trust —
it is intra-TCB plumbing between two components that are *both already inside*
the measurement boundary (the inventory and get-cert). Its integrity is *inherited*
from that boundary, not established by the socket. Which "host" can subvert it
splits cleanly:

- **The L0 hypervisor — defeated by hardware.** The runtime dir is under `/run`,
  which is **tmpfs (RAM)**, and under SEV-SNP / TDX the guest's RAM is
  hardware-encrypted. The L0 host physically cannot read, write, inject, or swap
  a socket in that memory. Under **kata** this is total: `policy-monitor`
  creates the socket inside the measured guest, there is exactly one pod per
  guest (no co-tenant), and the bind-mount is guest-internal — nothing outside
  the guest can reach it. Under **node-CVM** the whole node is the CVM and the
  socket sits in the node's encrypted tmpfs, so the L0 host is out the same way.
  A guest the host booted with a swapped plugin would not match the launch
  measurement, so a CDS with `--measurements` set refuses to issue to it.

- **The residual is a co-tenant, not the L0 host** (node-CVM only). The exposure
  is a *malicious allowlisted pod* — inside the node's TCB in the TEE sense, but
  not benign — that can `hostPath`-mount the socket directory **read-write** and
  swap the file. This is a PodSecurity / filesystem-permission problem, the same
  residual as "Why a unix socket" (overlaps THREAT_MODEL §Addressable). It is
  gated by: the dir is **root-owned `0711`** (untrusted pods cannot write it),
  get-cert's own mount is **read-only**, and get-cert dials a **compiled** path
  the control plane cannot redirect. It opens only if PodSecurity lets untrusted
  pods RW-mount host paths. (One nuance: the mount *source*
  `WorkloadClaimsHostDir` is operator-supplied, so a malicious operator could
  point it at a rogue dir — but the operator/webhook runs inside the node-CVM
  and is measured, so this reduces to "is the node's TCB intact", which the node
  launch digest attests. The plugin binary's on-disk integrity rests on the same
  node measurement + allowlist + guest lockdown, not on the socket.)

**And a subverted socket is bounded anyway.** A swapped socket can hand get-cert
a token, but not one CDS accepts: the signature must verify under a key whose
EAR CDS itself issued against an allowed measurement, and the `inventoryAddr` it
names must answer over mutually-attested RA-TLS. The worst a co-tenant swap
achieves is denying the pod its sandbox ID.

The **digests endpoint** needs no equivalent argument: it is not a filesystem
object, it never answers an unauthenticated caller, and its address is
signature-covered. It does need to be *reachable* from CDS — see Enablement.

---

## Enablement

Always on for node-CVM: the chart wires the NRI inventory socket, the webhook
mount, the digests port, and the operator flag. get-cert is fail-closed on an
inventory error, so a broken nri-image-policy blocks workload cert issuance
node-wide — by design.

**Network reachability.** The digests endpoint is a new *inbound* path: CDS must
be able to reach node-CVM nodes (and kata guest pods) on
`nriImagePolicy.sandboxDigests.port` / policy-monitor's `SandboxDigestsPort`,
9443 by default. The advertised host is inferred from the route to CDS; set
`nriImagePolicy.sandboxDigests.advertiseHost` or
`$C8S_SANDBOX_DIGESTS_ADVERTISE_HOST` when that inference is wrong (NAT).

**Unpinned measurements do not disable the flow.** With an empty measurement
allowlist both ends still require a hardware-attested RA-TLS peer but pin no
measurement — any TEE can answer as the inventory, and any TEE that can reach
the port can read what a node runs. Both log it as UNSAFE outside development;
the allowlist gate still runs. A CDS with no `--ratls-platform` has no RA-TLS
identity to present, makes no callback, and **refuses** any request carrying a
sandbox token; an inventory whose CDS measurements fail to parse serves no
tokens, and get-cert issues without a sandbox ID.

**Upgrade ordering.** Because get-cert fails closed on an inventory error, roll
`nri-image-policy` (which creates the socket and serves both surfaces) **before
or with** the operator/webhook that injects `--workload-claims`. If the
webhook starts injecting the flag while an old plugin (no inventory socket) is
still running — or before the socket's host directory exists for the hostPath
mount — every newly admitted `cw` pod fails cert issuance until the plugin is
current. A chart upgrade that rolls both together is safe; a partial rollout is
not.

(The kata path is not yet chart-wired: the guest image must serve
`policy-monitor`'s inventory socket via `--workload-claims-socket-dir` and
bind-mount that directory into pod containers at
`workloadclaims.SidecarSocketDir` before the chart injects
`--workload-claims` for kata pods — a follow-up.)

## Audit pointers

| Concern | Where |
|---|---|
| Inventory protocol (both surfaces), sandbox token, peer-cred + cgroup binding | `pkg/workloadclaims/` |
| node-CVM inventory (shallowest-tracked resolution, sandbox/container eviction) | `internal/cmds/nri-image-policy/inventory.go` |
| kata guest inventory (single-pod, same unix socket) | `internal/cmds/policymonitor/inventory.go` |
| get-cert challenge → token fetch → `/attest` forward | `internal/cmds/getcert/run.go`, `pkg/attestclient/client.go` |
| get-cert leaf-embed (nonce-free RA-TLS extension on the CSR) | `pkg/attestclient/ratls.go` (`AttestationExtension`) |
| CDS token verify + inventory callback + allowlist/combination gate + leaf stamp | `internal/cmds/cds/attest.go`, `internal/issuer/sign.go` |
| verifier pin | `internal/cmds/verify/` (`--sandbox-id`, `--mesh-ca`) |
