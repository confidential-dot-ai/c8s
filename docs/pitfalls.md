# Pitfalls

Gotchas for humans and agents working on c8s. Each cites the relevant code.

## kata-image-puller vs kata-deploy: the guest-pull config clobber

`internal/helmchart/c8s/templates/kata-image-puller.yaml`

kata-deploy rewrites the stock `runtimes/qemu-snp/configuration-qemu-snp.toml` on
every (re)install and has **no ordering dependency** on the puller. If the puller
patched once and idled, a later kata-deploy restart silently reverts
`experimental_force_guest_pull` (and the kernel/rootfs pointers) — and the next
`kata-qemu-snp` sandbox dies with `failed to mount …/rootfs: ENOENT` (no guest
rootfs, because guest-pull is off and `shared_fs="none"` shares nothing).

The puller is therefore a **reconcile loop** (single `reconcile` container) that
re-applies the patch whenever it drifts; readiness tracks "patch present". Do not
"simplify" it back to a one-shot initContainer + `pause` — that reintroduces the
clobber. Verified: clobbering the config self-heals in ~24s.

## kata-qemu-snp pods still need a host-side image pull (no nydus-snapshotter)

Without a nydus-snapshotter, containerd does a host-side CRI pull of the workload
image **before** kata guest-pulls it inside the VM. For a private image
(e.g. `ghcr.io/lunal-dev/cds`) the host pulls *anonymously* and gets `401` unless
`serviceAccount.imagePullSecrets` supplies creds. So a guest-pull workload needs
creds in **two** places: the host (an image-pull Secret) **and** the guest
(`agent.image_registry_auth`, set by the puller — see
`internal/helmchart/c8s/files/scripts/pull-and-configure.sh`). Adding a
nydus-snapshotter would make the host pull metadata-only and remove the host-creds
requirement.

## cds cannot reach Ready as runc on a host that is not an SNP guest

`internal/helmchart/c8s/templates/cds.yaml`

cds's RA-TLS serving cert needs SNP evidence from `/dev/sev-guest`, which only
exists **inside** an SNP guest (the host has `/dev/sev`, not `/dev/sev-guest`).
The non-kata probes are httpGet/HTTPS. So running cds as host runc (no `--kata`)
on bare metal has no clean Ready path — it is intended to run as `kata-qemu-snp`
(gated on `kata.enabled`). For a non-confidential dev box, disable cds's RA-TLS
(`cds.ratlsPlatform=""`, plaintext) and expect the HTTPS probe to fail.

## Do not flip `kata.enabled` on a live cluster

`internal/helmchart/c8s/templates/cds.yaml`

cds's `runtimeClassName`, attestation-api URL (host DaemonSet vs in-CVM
loopback `127.0.0.1:8400`), `securityContext`/`runAsUser`, and probes are all
keyed on `kata.enabled`. Toggling it on an existing release therefore silently
moves cds between a runc pod and a `kata-qemu-snp` CVM, and between host and
in-guest attestation — a disruptive, easy-to-miss change that rewrites the trust
boundary cds runs in. It is harmless on a fresh install but sharp on a running
one. Pick kata vs non-kata at install time and keep it fixed; to switch, plan it
as a deliberate migration (drain, reinstall), not a `helm upgrade --set`.

## The bootstrap allowlist binds to floating `:main` digests — operators MUST pin by digest

`kata-guest-base/scripts/fetch.sh`, `internal/helmchart/c8s/values.yaml`

The kata-guest-base build resolves `cds:main` and `get-cert:main` via
`oras manifest fetch` at build time and bakes their **digests at that moment**
into `/etc/c8s/bootstrap-allowlist.json` on the dm-verity rootfs. The allowlist
is therefore sealed into the SNP launch measurement and is, by construction,
**only as fresh as the floating `:main` tag at the moment of build**. Two
consequences worth knowing:

1. `kata-guest-base.yml` chains off `Docker` via `workflow_run` so the build
   reads a `:main` that Docker just finished pushing — this kills the
   *concurrent-read* race (Docker mid-push while fetch.sh resolves). It does
   **not** make `:main` immutable; Docker's next main push moves it.
2. If a `kata-guest-base` build fails for an unrelated reason (snapshot 5xx,
   docker+apparmor, …), `cds:main` has already advanced and `kata-guest-base:main`
   stays at the previous build. The two floating tags drift, and a deploy that
   pulls both at `:main` produces a `kata-guest-base` whose baked seed doesn't
   permit the deployed `cds`'s digest — policy-monitor SIGKILLs cds and the
   bootstrap stalls.

**Mitigation — pin by digest in `values.yaml`, not by tag.** Every c8s image
(`cds`, `get-cert`, `attestationService`, the oras puller, …) exposes an
`image.digest` field. Resolve it once at deploy time:

```sh
oras manifest fetch --descriptor ghcr.io/lunal-dev/cds:<release-tag> \
  | jq -r .digest
```

and set it in your values file. With every image pinned by digest, the floating
`:main` movement is invisible to your deployment.

**Runtime mitigation that does the heavy lifting in production:** the
`policy-monitor` CDS-whitelist-refresh path
(`kata-guest-base/extra/etc/systemd/system/policy-monitor.service` + `internal/
cmds/policymonitor/cds_refresh.go`) **grows** the in-VM allowlist at runtime
from CDS's RA-TLS-pinned whitelist, so operator-pinned digests not in the baked
seed are still admitted. The seed only needs to be "good enough to boot the
first cds container," after which the in-cluster CDS extends the set. That's
why bootstrap-allowlist drift is tolerable for any deploy where the operator
pinned the chart's digests; it's only fatal for an unpinned `:main`-everywhere
deploy.

**Known gap (deferred fix):** `kata.guestImage` (the kata-guest-base oras
artifact itself) currently has only a `tag:` field, no `digest:` — the puller
pulls by tag. Pin to a specific `<short-sha>` tag rather than `latest`/`main`
until the puller learns `oras pull <ref>@<digest>`. The proper fix is **atomic
floating-tag promotion**: a third workflow that rolls `:main` and `:latest` on
all c8s artifacts only after BOTH `Docker` AND `kata-guest-base` succeed for
the same commit. Out of scope here; tracked as a follow-up.

## `ghcr-auth.json` is a live PAT — keep it gitignored

`kata-guest-base/extra/etc/c8s/ghcr-auth.json` is a **TEST-ONLY** docker auth.json
holding a live GHCR PAT, baked into the dm-verity rootfs for local guest-pull. It
is gitignored (`kata-guest-base/.gitignore`) and must **never** be committed or
baked in CI — production delivers in-guest creds via `kbs://` after the guest
attests. The CI guest-base build does not reference it.
