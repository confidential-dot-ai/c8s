# 2026-07-03 — Pre-upgrade keystone push so chart upgrades roll under fail-closed

## Context

With `nriImagePolicy.policy.mode: fail-closed`, a chart upgrade that bumps
component digests deadlocks the cluster:

- Each node's plugin admits only its `always_allow` floor (plus, on workers,
  the last CDS pull; on the CDS node, the last pushed entry). Floors change
  only when the installer DaemonSet rolls — and the new installer image is
  itself denied by the old floor. The enforcer cannot upgrade itself.
- CDS is a Recreate singleton: the old pod is killed before the new one is
  admitted, so worker pulls (`runPullLoop`, 30s) lose their source and keep
  serving the old floor.
- The push hook ran at `post-upgrade` — after a rollout wait that can never
  complete — in the NEW nri image the old plugin denies, and pushed only the
  cds digest.

The render guards (`validations.yaml`) only check that the new values are
self-consistent; nothing seeded the old, running plugins ahead of the roll.
Every promote required manual intervention.

## Decision

Make the push hook the upgrade keystone, and let kubelet retries plus the
existing pull/seed machinery do the rest:

1. **Hook phase**: `pre-upgrade` only (was `post-install,post-upgrade`).
   Pre-upgrade runs before any manifest changes, on every helm-controller
   retry attempt (`before-hook-creation` + idempotent PUT). Post-install was
   redundant: on day 0 the installer writes the complete floor and CDS seeds
   from the same JSON — nothing needs pushing. No pre-rollback: `helm
   rollback` replays the target release's STORED hooks without re-rendering
   (`pkg/action/rollback.go` copies `Manifest`/`Hooks` from the previous
   release), so the hook would run with a stale lookup image and block
   otherwise-clean rollbacks.
2. **Payload**: the NEW installer digest (single entry — old receivers enforce
   exactly-one-digest, so this is version-skew-proof). One digest suffices:
   admitting the new installer pod on the CDS node lets it deliver the full
   new floor (+ containerd restart), which admits the new CDS pod (the cds
   self-entry is always in the floor); CDS seeds its DB additively and bumps
   the ETag; workers pull the new set within one refresh interval; kubelet
   CreateContainerError retries admit every other new pod. Displacing the
   previously-pushed cds entry is safe for the same reason — the floor always
   carries the cds self-entry.
3. **Hook image**: a Running installer pod's `install` image via helm
   `lookup` — preferring a cds-archetype pod (its image ran on the CDS node,
   so the plugin the hook talks to admits it; a worker pod's image only
   proves admissibility under floor ∪ CDS-pull), falling back to any
   installer pod, then to the chart's own image when lookup is empty (fresh
   install, `helm template`, CI). The DaemonSet *object* is deliberately not
   consulted: on a wedged cluster a failed upgrade attempt has already
   pointed its spec at the new, denied digest — exactly when the hook
   matters most.
4. **Socket-absent no-op**: if the plugin socket never appears within the
   retry budget the hook exits 0 — no socket means policy is not active on
   the node, so there is nothing to unblock (covers upgrades that first
   enable `nriImagePolicy`). The socket hostPath is `DirectoryOrCreate` so
   the pod can start on an untouched node.
5. **Installer healthz wait 60s → 120s**: the worker plugin's initial CDS
   pull retries through 4 backoff sleeps (2+4+8+16s) plus per-attempt fetch
   timeouts before going Ready on the floor; 60s undercut that window.

The floor itself already propagates on any change without extra plumbing:
the boot config is embedded in the DaemonSet pod template, so a floor-only
change rolls the DS (same installer image — admitted everywhere).

## Version skew

The first upgrade from a pre-fix release runs the NEW hook manifest against
the OLD plugin: the single-entry payload matches the old receiver contract,
the socket path and `PUT /allowlist` route are unchanged, and lookup selects
an image the old floor self-allows. Sweep churn during the roll is bounded:
the CDS allowlist DB is additive, so workers serve old ∪ new digests while
Deployments roll.

The socket path (`hostPaths.runtimeDir` + `healthSocketName`) is part of
this contract: the hook probes the PREVIOUS release's socket, and a missing
socket is treated as "policy not active" (exit 0). Renaming either value
silently no-ops the keystone — don't, without a migration.

CI cannot execute the lookup match branch (`helm template` renders lookup
empty, exercising only the fallback); the first fix-promote doubles as its
live verification — confirm the hook pod runs a digest the old floor admits.

## Deliberately NOT changed

- No multi-digest push protocol, no socket auth change — the receiver
  contract is untouched.
- No CDS restart on seed-only changes (e.g. a checksum annotation): the
  in-memory mesh CA does not survive a restart, so that would rotate the
  trust root on every allowlist edit. Host admission doesn't need it — the
  boot config is part of the installer DS pod template, so a floor change
  rolls the DS and updates every node. Only CDS's served set lags until its
  next restart; making CDS re-seed without restarting is a separate change.
- No fleet-repo changes; the fix is chart-only and cluster-agnostic.

## Residual limits (manual keystone)

Both cases below are resolved the same way: run a pod on the CDS node with
any still-admitted image, mount the plugin runtime dir, and PUT the target
installer digest as a single-entry allowlist to the socket.

- Rollbacks are not keystone-covered: helm rollback replays stored hooks, so
  no hook can re-resolve an admitted image at rollback time. The fleet never
  rolls back automatically (`remediation.retries: -1`); a manual rollback
  that changes digests needs the manual keystone.
- If NO installer pod is Running anywhere at render time (every node wedged
  at once), lookup falls back to the new image, the hook pod is denied, and
  the upgrade attempt fails closed and retries.
