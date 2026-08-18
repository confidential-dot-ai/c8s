# Kata image policy

How c8s prevents an arbitrary container image from running inside a
confidential kata guest. Both confidential shims — `kata-qemu-snp` and
`kata-qemu-tdx` — run the same guest image and the same enforcement; the
walkthroughs below say `kata-qemu-snp` and hold for either. This document
complements
[`kata-guest-base.md`](kata-guest-base.md) (the guest-image design) and
[`kata-guest-base/README.md`](../kata-guest-base/README.md) (the recipe)
by walking through the threat scenarios the policy defends against, and
the gaps it does not.

> **Measurement model.** Wherever this doc says a file is "baked in" or
> "part of the launch measurement", that means it sits on the dm-verity
> root, whose root hash rides the kata kernel cmdline. On SEV-SNP the
> cmdline reaches the launch digest via `kernel-hashes`, so those bytes
> cannot change without changing the value operators pin. On TDX the launch
> measurement is MRTD, which covers TDVF only — the kernel lands in RTMR[1]
> and the cmdline in RTMR[2] — so pinning MRTD alone leaves the guest image
> substitutable. Those two registers are pinnable
> (`c8s verify --rtmr 1=<hex> --rtmr 2=<hex>`, `ratls.VerifyPolicy.RTMRs`);
> what is not yet derivable offline is their expected values, so today they
> have to come from a known-good boot. The measurement mechanics (osbuilder dm-verity ext4, `kernel-hashes`, the
> verity root hash in the kata kernel cmdline, no IGVM/UKI) live in
> [`kata-guest-base/README.md`](../kata-guest-base/README.md).

The short version: the decision is split in two, and both halves are on the
dm-verity root.

kata-agent's baked OPA policy fails closed on CreateContainerRequest. It does
not know the allowlist — regorus has no crypto builtins, so it cannot verify a
signed allowlist update — but it does bind the request to itself: exactly one
`image_guest_pull` storage, mounted at that container's rootfs, whose `source`
is the digest-pinned reference the `io.kubernetes.cri.image-name` annotation
carries. It runs before `do_create_container`, so a request that fails it is
`PERMISSION_DENIED` with no pull and no bundle.

The in-VM `policy-monitor` daemon then decides whether that digest is
allowlisted: it watches kata-agent's container-bundle directory via inotify,
reads the digest out of the same annotation, and SIGKILLs the container's cgroup
if it is not on the list.

Neither half is sufficient alone. The image reference and the guest-pull storage
source are independent fields of a request the host writes, so without the
binding the digest policy-monitor checks need not describe the bytes the guest
fetches; without the allowlist the binding only proves the request is
self-consistent. **A confidential pod must therefore reference its images by
digest** — a tag names whatever the registry serves the guest at pull time.

The allowlist is a **baked seed plus a CDS refresh** (see
[Allowlist sourcing](#allowlist-sourcing-baked-seed--cds-refresh)). The
seed — `/etc/c8s/bootstrap-allowlist.json`, on the verity root and part
of the launch measurement — lets the guest enforce from t=0 with no
network. At runtime policy-monitor polls CDS's `/allowlist` over RA-TLS
(pinned to `cds.measurements` and the `minTcb` floor) and merges what CDS
serves on top, so
operator additions land without a guest rebuild. The merge only ever
*grows* the set, so a compromised or unreachable CDS degrades to "stale
but no smaller" — never "open".

A previous design (`guest-policy-agent`) also fetched a allowlist from
CDS over RA-TLS, but only *rendered* it informationally — it enforced
nothing inside the VM. policy-monitor keeps the same authenticated CDS
source and actually enforces (SIGKILL). The trade-off it makes — a
post-start kill window — is documented in
[Post-start kill window](#post-start-kill-window) and the
[BPF-LSM upgrade path](#bpf-lsm-upgrade-path) below.

## Trust boundary

| Component | In TCB? | Notes |
|---|---|---|
| `kata-guest-base` guest image (`vmlinuz` + dm-verity rootfs) | yes | Launch measurement verified at boot: SEV-SNP launch digest via `kernel-hashes`. On TDX MRTD covers TDVF only, so the guest image is attested only when RTMR[1] and RTMR[2] are pinned too. |
| `kata-agent` inside the guest | yes | Installed into the rootfs by kata's osbuilder (version-matched) at build. |
| `policy-monitor` inside the guest | yes | Built from this repo, baked into the dm-verity root. |
| `/etc/c8s/bootstrap-allowlist.json` (verity root) | yes | The allowlist **seed** the monitor loads at boot. Part of the launch measurement. |
| CDS `/allowlist` additions (pulled over RA-TLS) | yes, via attestation | Runtime additions merged on top of the seed. Trusted because the pull is RA-TLS-pinned to `cds.measurements` and the `minTcb` floor (the host can't substitute a fake or weaker CDS), not because they're measured into this guest. |
| `ratls-mesh` + `attestation-service` inside the guest | yes | Same. |
| Host (containerd, kata-runtime, kata-shim) | **no** | Adversarial. Can call kata-agent RPCs via vsock, cannot read VM memory (SEV-SNP or TDX). |
| Cloud-init user-data (the `C8S_*` env file) | **partially** | Host controls its contents when per-pod injected; pinned values must be verifiable inside the guest. Today this is a single fixed default baked into the rootfs, not per-pod host-injected. |

## Bootstrap order (the load-bearing piece)

Systemd inside the guest brings the services up in two largely
independent dependency chains. The image-policy chain is short:
`policy-monitor.service` orders only on `local-fs.target` so
`/etc/c8s/bootstrap-allowlist.json` is readable when the monitor
starts — nothing else needs to be up. Only the two units this doc
reasons about are shown below; for the full boot/dependency graph
(attestation-service, ratls-mesh, `c8s-ready.target`) see
[Boot order inside the guest](kata-guest-base.md#boot-order-inside-the-guest)
in [`kata-guest-base.md`](kata-guest-base.md).

```
local-fs.target ─→ policy-monitor.service ─→ kata-agent.service
                   (orders only on              (Requires=+After= the
                    local-fs.target;             monitor; loads
                    Type=notify: READY=1         /etc/kata-opa/default-policy.rego
                    once the watch is            — a baked file on the
                    installed and the seed       dm-verity root)
                    pass has run)
```

Key invariants:

- **kata-agent's policy is the baked
  `/etc/kata-opa/default-policy.rego`**, a real file on the verity
  root that's part of the launch measurement. It denies
  `SetPolicyRequest`, denies the RPCs that reach into a running
  container, and binds a `CreateContainerRequest` to the image it
  names. It does NOT carry the digest allowlist — regorus has no
  crypto builtins, so that half is policy-monitor's job.
- **kata-agent gates on policy-monitor.** The drop-in
  `kata-agent.service.d/10-c8s-policy-monitor.conf` adds
  `Requires=`+`After=policy-monitor.service`, so a monitor that cannot
  start keeps the agent from starting at all — no `CreateContainer`, no
  bundle, no unenforced image. `Type=notify` makes the ordering resolve
  on READY=1 (watch installed, seed pass run) rather than on a fork. The
  monitor depends on nothing but the dm-verity root, which is what lets
  it sit ahead of the agent without a cycle: it enforces from t=0 on the
  baked seed with no network.
- **A dead policy-monitor takes the guest with it.**
  `FailureAction=`/`StartLimitAction=poweroff-force` fire once the
  restart budget is spent. Ordering only covers startup; this is what
  covers a monitor that dies while containers are running.
- **`kata-agent.service` carries `FailureAction=poweroff`.** If
  kata-agent crashes after start, the VM shuts down rather than
  entering an ambiguous half-running state. kata-runtime sees the
  VM gone, surfaces `CreateContainerError` to kubelet.
- **The seed is read-only; the in-memory set only grows.**
  policy-monitor loads `/etc/c8s/bootstrap-allowlist.json` once at boot
  — the file is on the verity root, so neither the guest nor the host
  can rewrite it, and CVM memory encryption covers the in-memory
  copy. The runtime CDS refresh only ever *adds* digests to the
  in-memory set (see [Allowlist sourcing](#allowlist-sourcing-baked-seed--cds-refresh));
  it cannot remove the seed or shrink the set, so a compromised or
  unreachable CDS can never reduce enforcement below the measured seed.

## Post-start kill window

`policy-monitor` enforces *after* kata-agent has called fork+exec on
the container init. Concretely:

1. kata-agent's `do_create_container` (rpc.rs:200) writes
   `/run/kata-containers/<cid>/config.json` and forks the init
   process via rustjail. The init lands inside an `exec` fifo wait
   (it cannot run user-supplied code until kata-agent receives a
   StartContainerRequest and writes to the fifo).
2. The directory creation triggers a kernel inotify event on
   policy-monitor's watch. policy-monitor's handler reads config.json,
   extracts the digest, consults the allowlist, and (on deny) reads
   `cgroup.procs` to get the init PID and `kill(pid, SIGKILL)`.
3. The init never reaches the user-binary `execve` — it dies inside
   the exec fifo wait, or (in the worst case) within a few ms after
   StartContainer fires.

The window between fork and SIGKILL is the **post-start kill gap**.
It exists because:

- kata-agent has no upstream-supported pre-start callout we can
  intercept other than the in-process OPA policy, and that policy
  is structurally permissive (see "Why the OPA policy is permissive"
  below).
- Userspace inotify delivers events asynchronously; the kernel
  doesn't pause the writer until a userspace consumer reads the
  event.

The window is bounded (single-digit ms on real hardware), and the
denied container has no useful capabilities inside it (no network
configured yet, no `execve` to user code yet). The
[BPF-LSM upgrade path](#bpf-lsm-upgrade-path) below describes how to
close the gap by hooking `security_bprm_check_security` in the kernel.

**The bound holds only if the kill actually lands.** Step 2's `cgroup.procs`
read depends on locating the container's cgroup, and on a systemd-PID-1 guest
that cgroup is a systemd *scope* — `cri-containerd-<cid>.scope` nested under
`kubepods*.slice` — not a bare `<cid>` directory. A cgroup matcher that only
recognizes the bare `<cid>` silently misses the kill on the common (systemd)
guest: policy-monitor *denies* the container but `findInitPID` returns
not-found, so the SIGKILL never fires and the denied image runs **unenforced**
(this was a 2026-07 field bug, fixed). The matcher must handle the
systemd-scope naming — see `internal/cmds/policymonitor/kill.go`
(`cgroupDirMatchesCID`).

The other way the kill silently misses is the write itself. The unit's
`ProtectControlGroups=yes` remounted `/sys/fs/cgroup` read-only *inside
policy-monitor's own mount namespace*, so every `cgroup.kill` write returned
`EROFS` while the hierarchy looked `rw` to everything else in the guest — a
non-allowlisted image ran unenforced for its full lifetime. Because that class
of failure is invisible from outside the unit, policy-monitor now runs a
**boot-time kill-path self-test** (`cgroupKiller.selfTest`): it creates a
scratch cgroup under the configured cgroup root, writes its `cgroup.kill`, and
removes it. On failure the process exits non-zero before installing the inotify
watch, so READY=1 is never sent, kata-agent's start job never resolves, and the
poweroff action ends the guest. A policy-monitor that cannot kill must not look
healthy.
The same reasoning applies after boot. A denied container is re-killed until
the kill lands or kata-agent removes its bundle; a kill path that keeps
**erroring** past `killEscalateAfter` exits the process non-zero, which the
unit turns into restarts and then poweroff — the running-guest counterpart of
the self-test, for a hierarchy remounted read-only after boot. A kill that is
merely never **confirmed** (cgroup absent or unpopulated) keeps retrying and
logs at error instead: a denied container that exited on its own is
indistinguishable from one that never got a cgroup, and that must not power off
a healthy guest.

## Why the OPA policy is permissive

kata-agent's bootstrap OPA policy in this image is
`allow-all.rego`-plus-`SetPolicyRequest := false`. We don't carry a
per-image-digest Rego rule there because:

1. **Regorus crypto.** Adding `data.agent_policy.allow if
   input.digest in allowed_digests` to the baked Rego would couple
   the guest image to a specific allowlist (the same coupling we get
   from the JSON file policy-monitor reads). That's fine in principle,
   but if the operator later wants to sign a runtime update,
   regorus would need crypto builtins it doesn't have — and the
   c8s posture is "the guest image is the version pin", so adding a
   runtime-update path would be re-creating a problem we already
   solved.
2. **Policy-monitor cleanliness.** Keeping enforcement in a
   userspace daemon means the audit log is in journald (where the
   operator already looks), the decision logic is in Go (easier
   to test and patch than embedded Rego), and the "kill the
   container" action is a syscall not an ttRPC reply that
   kata-runtime might map back into a CreateContainerError that
   the operator has to grep for in kubelet logs.

A future PR may revisit this and put a `default allow := false`
clause in the baked policy plus the allowed digests as Rego data;
that would close the post-start window in the agent itself, but at
the cost of regorus integration testing on every kata version
bump. Today the simpler path is policy-monitor.

## Allowlist sourcing: baked seed + CDS refresh

policy-monitor's allowlist has two sources, unioned in memory:

1. **Baked seed.** `/etc/c8s/bootstrap-allowlist.json` is materialised
   at guest-image build time (`kata-guest-base/scripts/fetch.sh`
   substitutes the resolved **cds** and **get-cert** image digests) and
   sits on the dm-verity root, so it's covered by the kernel-hashes
   launch measurement. policy-monitor loads it once at boot. This is
   what lets the guest enforce from t=0 with **no network** — there's
   no boot-path fetch, so no CDS-bootstrap deadlock and no "fails open
   until the first pull" window.

2. **CDS refresh.** When the guest is configured with a CDS URL
   (`C8S_CDS_URL`, delivered via the same cloud-init env file
   `ratls-mesh` reads — **Status:** today that env file is a single fixed
   default baked into the rootfs, not per-pod host-injected, so a
   non-default-namespace install needs the real injection),
   policy-monitor polls CDS's `GET /allowlist` on
   an interval and merges the result on top of the seed. The pull uses
   the **same mechanism the host nri-image-policy worker uses**:
   `pkg/allowlistclient` over an RA-TLS transport (`pkg/ratls`) whose
   peer cert is pinned to `cds.measurements`. So the in-guest enforcer
   and the host enforcer consult the same authenticated CDS allowlist;
   the in-guest one is the strictly-stronger check (the TEE re-deciding
   for itself rather than trusting the host's NRI verdict).

The merge is **grow-only**: it adds digests, never removes them, and
never touches the seed. Consequences:

- A CDS outage, a slow CDS, or a CDS the RA-TLS handshake rejects
  (measurement mismatch) leaves the current set intact — at minimum the
  measured seed. Enforcement degrades to "stale but no smaller", never
  "open". (This is the right failure mode for an *allow*-list.)
- Operator additions to the cluster allowlist propagate to running kata
  guests within one refresh interval, **without a guest-image rebuild**
  — the operational cost the older baked-only model carried (see
  [G2](#g2--allowlist-additions-no-longer-need-a-guest-image-rebuild)).
- With `C8S_CDS_URL` unset (no cloud-init, or a deliberately air-gapped
  guest) policy-monitor never opens the network and enforces the baked
  seed alone — still fully fail-closed.

`C8S_CDS_MEASUREMENTS` pins CDS's RA-TLS serving-cert launch digest.
Leaving it empty **disables the refresh** (logged as an error at
startup): policy-monitor deliberately refuses to pull unpinned. This is
*stricter* than `ratls-mesh`, which warns and proceeds on an empty pin —
the asymmetry is intentional. For the mesh, an unpinned peer still has
to be *some* attested TEE; for the refresh, "any attested TEE" is not
enough, because the host can boot its own CVM from this same guest
image, run a CDS in it serving an attacker-chosen allowlist, and pass
"attested" — and grow-only merging is no defence when *additions* are
the attack. With the refresh disabled the guest enforces the measured
seed alone, which is fail-closed.

Baking the pin is structurally impossible — under kata, CDS runs from
this same guest image, so the pin's value would change the launch
measurement it pins — and a plain cloud-init value would be
host-controlled, so a host-supplied pin could point at the host's own
fake CDS.

**Delivery: SEV-SNP init-data.** The host writes an init-data document
the guest reads at `initdata.GuestDocumentPath`, and the shim commits
`sha256(document)` into `HOST_DATA` at launch. policy-monitor attests
itself against the in-guest attestation-service, has that report
verified through the same attestation-api `/verify` endpoint the RA-TLS
refresh uses, and compares the document against the `HOST_DATA` the
verifier reports. The host still chooses the document, but it cannot choose one
and commit another — the value is sealed into the measurement the
operator already verifies, so a substituted pin changes an attested
field rather than passing silently.
On a mismatch, or with no document, the guest falls back to the baked
seed.

The same document carries the minimum-TCB floor (`c8s.cds.min-tcb`,
from the chart's `minTcb`) for the same reason: a host that could strip
it from an unattested channel would run known-vulnerable firmware
unobserved. A document that carries the measurements but no floor — or a
zero floor, which is no floor — is refused: refresh stays disabled rather
than run unfloored, unless an explicit floor already covers the guest.

**TDX has no equivalent path yet:** the digest goes to `MRCONFIGID`,
which is 48 bytes where the anchor is 32, so the guest refuses the
claim and enforces the baked seed alone. Empty `cds.measurements` (the chart
default) also leaves the refresh disabled on every platform — operator
additions then reach the host-side enforcer but not running guests.

## Scenarios

For each scenario: setup, attacker action, expected outcome, why.

### S1 — Cold pod start, happy path

**Setup.** Operator has built and pinned a kata-guest-base image whose
baked `/etc/c8s/bootstrap-allowlist.json` seed contains the SHA-256
digests of the c8s bootstrap images at the matching release tag
(cds, get-cert). Pod manifest references `kata-qemu-snp` (after webhook
injection).

**Flow.** kata-runtime boots the guest → systemd starts services →
policy-monitor opens the inotify watch and loads the allowlist →
kata-agent starts and accepts CreateContainerRequest → kata-agent
writes config.json and forks the init → inotify event reaches
policy-monitor → monitor extracts the digest, finds it on the
allowlist, logs allow, does nothing → kata-agent receives
StartContainerRequest and signals the init's exec fifo → container
runs.

**Outcome.** Pod runs.

### S2 — Malicious workload image (not on allowlist)

**Setup.** Adversary submits a pod manifest referencing an image
whose digest is not on the operator-pinned allowlist baked into the
guest image. (The "adversary" here is anyone with cluster-write
permission: a compromised CI pipeline, a tenant in a multi-tenant
cluster, etc.)

**Flow.** Pod is admitted. Pod gets `kata-qemu-snp` via the c8s
webhook. kata-runtime boots the guest, kata-agent's CreateContainer
forks the container init. policy-monitor sees the new bundle, reads
config.json, extracts the image digest from the OCI annotation, the
digest is NOT in the allowlist → monitor resolves init PID via the
container's cgroup, sends SIGKILL.

**Outcome.** Container's init process dies before its first
post-StartContainer instruction. kata-agent's exec fifo notification
arrives to a dead PID (ESRCH on the signal); kata-agent reports
container exit to kata-runtime; kubelet records `CrashLoopBackOff`
or `CreateContainerError` depending on timing. Pod doesn't reach a
running state.

### S3 — Host attempts to relax policy via SetPolicy

**Setup.** Pod is running. Compromised host wants to bypass the
baked kata-agent policy (e.g. so it can land a container with a
different policy).

**Flow.** Host's kata-shim opens a vsock connection to kata-agent's
control channel and sends a `SetPolicyRequest` → kata-agent
evaluates against the current (baked) policy → the baked policy has
`default SetPolicyRequest := false` → kata-agent returns
`PERMISSION_DENIED` → the in-memory policy is unchanged.

Note: even if SetPolicy were allowed, the host could not change
the policy-monitor's allowlist. SetPolicy targets kata-agent's
in-process Rego engine, not the verity-protected
`/etc/c8s/bootstrap-allowlist.json` file.

**Outcome.** Host's policy mutation is rejected.

### S4 — Host attempts to modify the allowlist file on disk

**Setup.** Pod is running. Compromised host wants to swap
`/etc/c8s/bootstrap-allowlist.json` to permit a new image.

**Flow.** The file lives on the verity-protected rootfs.
Any modification breaks the verity hash chain — the kernel's
dm-verity layer fails the read, policy-monitor sees an I/O error
on its (cached) in-memory snapshot... actually policy-monitor
already loaded the file at boot, so the in-memory snapshot is
the authoritative copy for the lifetime of the VM. Modifying the
on-disk file does nothing.

Even if the host could tamper with the on-disk file pre-boot:
that would change the guest image's launch measurement, and the
operator's attestation flow would reject the pod.

**Outcome.** Allowlist tampering is not reachable from the host.

### S5 — Host attempts to kill policy-monitor

**Setup.** Pod is running with a denied container queued. Compromised
host wants to disable policy-monitor so the denied container runs.

**Flow.** kata-runtime can ask kata-agent to signal arbitrary PIDs
via the SignalProcessRequest RPC, but only against PIDs of
*containers* kata-agent knows about. policy-monitor runs under
systemd as a system service (PID is allocated by systemd at boot,
unknown to kata-agent), not as a container; its PID is not a valid
target for SignalProcessRequest. The host can't otherwise reach into
the VM's process table because CVM memory encryption hides it.

**Outcome.** policy-monitor cannot be killed from the host.

### S6 — Container init exits before SIGKILL lands

**Setup.** A denied container's init process exits on its own (e.g.
a crash, or it's a `/bin/false` test) before policy-monitor can
SIGKILL it.

**Flow.** policy-monitor reads cgroup.procs and either gets ESRCH
on the kill (process already gone) or doesn't find a PID at all
(cgroup empty). The monitor logs the case at **error** level and moves
on. The container is effectively "killed" — by itself — before any
useful work. The severity is deliberate even though this case is benign:
"denied, and not confirmed dead" is indistinguishable from a kill that
silently missed (the two field bugs above), so an operator has to see it.

**Outcome.** Denied container exits, just as if policy-monitor had
killed it. No false-positive enforcement; no leakage.

### S7 — kata-agent crashes mid-pod

**Setup.** Pod is running normally. kata-agent encounters an
unrecoverable bug, panic, or OOM.

**Flow.** Process exits → systemd sees the failure →
`FailureAction=poweroff` fires → guest VM shuts down → kata-runtime
sees the VM gone → kata-shim reports failure to kubelet.

**Outcome.** Pod terminates. policy-monitor's state is moot — the
VM is gone.

### S8 — Pre-startup container injection

**Setup.** Adversary wants to run code in the guest VM before
kata-agent is up.

**Flow.** Before kata-agent is up, the only processes inside the VM
are systemd-managed services from the guest image — `attestation-service`,
`ratls-mesh`, `policy-monitor`, plus the cloud-init phase. None of
these are container runtimes; none of them honor arbitrary
exec-this-binary requests from the host. To run a container, the
host has to talk to kata-agent over vsock. kata-agent doesn't exist
yet.

**Outcome.** No exposure window before policy load.

### S9 — Bootstrap: c8s-cert sidecar, which the webhook injects

**Setup.** Operator deploys a workload pod. The c8s webhook injects a
single `c8s-cert` native sidecar (init container with
`restartPolicy: Always`). It uses `cfg.GetCertImage` from the chart
(`ghcr.io/confidential-dot-ai/get-cert:<tag>`).

**Flow.** kata-runtime calls CreateContainer for the sidecar.
kata-agent forks its init; policy-monitor sees the new bundle,
extracts the digest, the get-cert digest IS in the allowlist (the
bake-time substitution at guest-image build time put it in the seed
alongside cds), monitor logs allow, init runs, gets the workload's
leaf, exits 0.

**Outcome.**
- If the operator built the guest image from a c8s release that
  included the get-cert image at the matching tag (the default path —
  `scripts/fetch.sh` resolves the digest from the IMAGE_TAG env
  var): pod runs as designed.
- If the operator overrode the IMAGE_TAG to a tag whose get-cert
  was different and forgot to refresh: get-cert's digest is not on
  the allowlist, the init container is killed, the pod never
  reaches the workload container. Operator's monitoring catches
  it; the workload never runs.

The hazard ("operator forgot to refresh") is a configuration
concern, not a security failure — the design is fail-closed.

### S10 — Cold pod start with no user-data at all

**Setup.** Pod creation racing some kata-runtime bug, or a
misconfigured pod that doesn't trigger user-data injection.

**Flow.** cloud-init runs but finds no NoCloud datasource. The c8s
`cloudinit-env.sh` script falls back to writing an empty env file.
ratls-mesh's validation fails → ratls-mesh.service enters `failed`
→ c8s-ready.target never reaches active. policy-monitor reads the same
env file: with no `C8S_CDS_URL` it simply runs **baked-seed-only** (the
CDS refresh never starts, the network is never touched) and continues
to enforce the seed on any container kata-agent does start.

**Outcome.** Pod doesn't reach mesh-ready state; workloads can't
talk over the mesh. But the kata-agent + policy-monitor pair still
behaves correctly on any in-bundle workload — fail-closed for
ratls-mesh, still-enforcing (against the measured seed) for
policy-monitor.

### S11 — Two CreateContainer calls (pause + workload)

**Setup.** Standard kubernetes pod with a pause sidecar and a
workload container. kata-agent gets two CreateContainerRequest calls
in succession.

**Flow.** Both calls are evaluated against the same baked OPA policy in
kata-agent (allow-all on CreateContainerRequest). policy-monitor sees an
inotify event per container bundle and evaluates each independently
against the in-memory allowlist — except the sandbox (pause) container,
which is out of allowlist scope (see Outcome).

**Outcome.** The workload container passes iff its digest is on the
allowlist; the first denied workload container halts the pod. The
sandbox (pause) container is **not** an allowlist entry: kata-agent
ships its own pause baked into the dm-verity rootfs (the `/pause_bundle`
staged by `build.sh`), so its integrity is anchored by the launch
measurement — the host cannot substitute it — and it needs no allowlist
digest. The bootstrap allowlist therefore carries only the host-pulled
component images (`cds`, `get-cert`); the sandbox container is treated as
measured-by-construction and skipped, not digest-enforced.

## Host can't substitute a fake CDS allowlist

policy-monitor *does* fetch the allowlist from CDS at runtime (the
hybrid refresh), so the question is whether a compromised host — which
brokers the guest's network — can feed it a fake, over-permissive list.
It cannot, for two independent reasons:

- **RA-TLS measurement pinning.** The refresh dials CDS over an RA-TLS
  transport that verifies the peer's attestation evidence against
  `cds.measurements` (the same `pkg/ratls` pin `ratls-mesh` and the host
  nri-image-policy worker use). A host that MITMs the connection or
  points it at an attacker-run service presents evidence that doesn't
  match the pinned CDS launch digest, the handshake fails, and the pull
  is rejected — policy-monitor keeps its current set.
- **Grow-only merge over a measured seed.** Even if a fetch returned
  bogus data, the merge only *adds* digests on top of the verity-measured
  seed; it can't remove the seed or shrink enforcement. And a host that
  simply *blocks* the refresh achieves nothing beyond freezing the set
  at its current (≥ seed) contents.

So the host can, at most, prevent *new* legitimate additions from
reaching a guest (a liveness nuisance, surfaced as denied workloads the
operator can see) — it cannot inject an entry to smuggle an
unattested image past policy-monitor.

## BPF-LSM upgrade path

This is a future-direction note, not a TODO we're committing to —
the goal is "we won't forget this is an option." It is the
documented way to close the post-start kill gap (G1).

The post-start kill window is inherent to a userspace inotify
watcher. To close it pre-`bprm_check`, the policy decision has to
happen inside an LSM hook — and the kernel hook that fires before
a process's first `execve` settles its credentials is
`security_bprm_check_security` (LSM's `bprm_check_security`).
Linux's BPF-LSM (CONFIG_BPF_LSM=y, with `CONFIG_LSM` containing
"bpf") lets us attach a CO-RE eBPF program to that hook.

Sketch:

1. **Boot-time install.** A small initialisation phase in
   policy-monitor (or a sibling unit ordered before `kata-agent`)
   loads a CO-RE BPF object on boot. The object exposes:
   - An eBPF `BPF_MAP_TYPE_HASH` from container-id (or PID
     namespace cookie) to a "allow" bool.
   - A program attached to `lsm/bprm_check_security` that
     looks up the calling task's cgroup → container id → map
     entry, returns -EPERM if denied.
2. **Per-container population.** When the userspace monitor sees a
   new bundle and resolves its digest, it writes the allow/deny
   decision into the map under the container's cgroup id (the
   bprm_check hook can read the cgroup id of `current`).
3. **Race-free start.** The kernel evaluates the hook before
   `do_execveat_common` commits the new mm to the task, so a
   denied digest never reaches userspace `main`. No millisecond
   gap.

Practical considerations:

- BTF: the kernel must be CO-RE-friendly. The confidential guest
  kernels (>= 6.x, SNP or TDX) ship BTF by default.
- LSM stacking: `CONFIG_LSM=...,bpf,...` must place "bpf" before
  any LSM that fails closed if our program is unloaded. The
  kata-static kernel we use already builds with bpf+selinux
  stacking; verify before relying.
- Allowlist materialisation: unchanged from today's sourcing. The
  userspace monitor still owns the allowlist (baked seed + CDS
  refresh) and just writes each allow/deny decision into the BPF map
  per container; the kernel hook only reads the map. So the BPF path
  inherits the same seed-plus-refresh trust chain — it moves *where*
  the decision is enforced (pre-execve in-kernel), not *how* the
  allowlist is sourced.

The work is non-trivial but linear; it's captured here so a future
contributor doesn't rediscover the option from scratch.

## What this design does and doesn't claim

**It claims:**

- The host cannot mutate kata-agent's policy. `SetPolicyRequest := false`
  rejects the runtime mechanism, the on-disk file is on the
  verity-protected, memory-encrypted rootfs the host can't write to
  (S3, S4), and the boot-time init-data channel — which replaces the
  engine outright, ahead of any rule — is removed from the agent by
  `kata-guest-base/patches/0001-agent-refuse-an-init-data-supplied-policy.patch`.
- The host cannot inject an over-permissive allowlist. The seed
  `/etc/c8s/bootstrap-allowlist.json` is on the verity root and part of
  the launch measurement on SEV-SNP — and on TDX when RTMR[1] and RTMR[2]
  are pinned alongside MRTD (S4) — and the runtime
  CDS additions arrive over RA-TLS pinned to `cds.measurements`, so the
  host can't substitute a fake CDS ("Host can't substitute a fake CDS
  allowlist"). At worst the host blocks new additions — it can't shrink
  enforcement below the measured seed.
- The host cannot kill policy-monitor from outside the VM. (S5.)
- The kata VM is the trust boundary (CVM memory encryption — SEV-SNP or
  TDX) and policy-monitor + ratls-mesh + attestation-service inside
  the guest image are part of the launch measurement. (S1, S11.)
- Per-image-digest enforcement happens for every CreateContainer
  inside the VM (S2, S6, S9, S11) — at the cost of a single-digit-ms
  post-start window (G1). The container id set the baked policy admits is
  the set policy-monitor and rtmr3-measurer resolve, and a bundle whose
  config.json has not been written yet stays undecided rather than being
  passed over, so "every CreateContainer" is literal.
- The digest enforced is the digest of the reference the guest pulls. The
  baked policy requires the guest-pull storage's `source` to equal the
  `io.kubernetes.cri.image-name` annotation and to be digest-pinned, and
  the in-guest puller verifies the manifest against that digest, so an
  admitted digest describes the bytes that become the rootfs.

**It does not claim:**

- That a denied container's init is never *forked*. It is, and
  policy-monitor SIGKILLs it. What the guest does claim is that it never
  reaches `execve`: the agent waits for the admission verdict before
  releasing the exec fifo (G1). The forked init runs no image code in that
  window — it is parked on the fifo.
- That CDS unreachability blocks the pod from booting or changes what
  policy-monitor enforces. The measured seed enforces regardless; a CDS
  outage only stops *new* additions from merging (grow-only). (Mesh-layer
  mTLS still fails closed on unreachable CDS via the get-cert init, but
  that's a separate enforcement layer.)
- That image *content* is hidden from the host during the
  guest-pull transport (G3).
- That the rootfs still holds the admitted bytes at `execve`. The claim is
  that it *originates* from a digest-pinned in-guest pull. `CopyFileRequest`
  is scoped to `/run/kata-containers/shared/containers/` so it cannot reach
  the container rootfs, and a mount's *source* must be one of the directories
  the runtime manages — so nothing binds the verity root, `/run/c8s` or
  another container's rootfs into a container. But a mount *destination* is
  any path inside the container, and the host still chooses argv and env
  (THREAT_MODEL §5). Which paths a given image may have shadowed is
  per-image knowledge; it belongs in the allowlist document next to the argv
  policy, not in a policy baked before any workload is known.

The most consequential honest limitations left are the host's control of
argv, env and mount destinations (THREAT_MODEL §5), and — on TDX — that the
RTMR values which make the guest image attested cannot yet be derived from a
guest-image build, only read off a boot that is trusted for other reasons.
