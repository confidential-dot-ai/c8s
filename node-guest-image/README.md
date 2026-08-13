# node-guest-image

The c8s node image (`node-guest-base`, `rke2[-cdi]-*` tags), defined in THIS repo
and built by [confidential-os-builder] acting purely as a builder — the same
ownership split `kata-guest-base/` already has with confos as a pinned tool.
Tracking issue: [#264].

Layout:

- `c8s/` — the mkosi profile (config, `mkosi.extra/`, `mkosi.sync`,
  cloud-init `user-data`). Staged into the confos build via
  `confos build --profile-dir` (confos ≥ the release carrying
  confidential-os-builder#81); the dir basename **is** the profile name, so
  it must stay `c8s`.
- `kernel/` — the guest-kernel config fragments (`c8s.config`,
  `c8s-dev.config`), passed via `--kernel-config-fragment` exactly like
  kata-guest-base's `container.config`. confos's `required`/`hardening`
  baselines stay in confos: a fragment request that conflicts with them
  fails the build (see the balloon catch in #263).
- `build` — drop-in replacement for confos's `bin/build-c8s`: same env
  contract (`C8S_REF`, `C8S_REGISTRY`, `C8S_DEV`, `C8S_NAME`, `C8S_MEMORY`) and the same profile stack
  and order; only the c8s profile content and kernel fragments come from
  here. Point `CONFOS_DIR` at a confos checkout (default: a sibling dir).

Migration state (see [#264] for the full plan):

1. This directory is the canonical definition: `c8s-image.yml` builds via
   `node-guest-image/build`, which stages `c8s/` into a confos checkout
   with `--profile-dir` and passes the kernel fragment and
   `c8s-ref`/`c8s-registry` sync inputs explicitly. The
   `node-guest-image lint` workflow is permanent: it carries the four
   invariants that moved here from confos `bin/lint` (fragment supersets
   vs confos's gpu/dev fragments at the pinned `CONFOS_REF`, the NRI
   floor template's no-hardcoded-digest rule, and the nested RKE2/Cilium
   pod-CIDR match).
2. The switch was gated on building the same c8s ref both ways (confos
   in-tree vs staged from here) with identical `manifest.json`
   measurements; `c8s-image.yml`'s `gate=true` dispatch input reruns that
   A/B check against any confos ref.
3. Remaining cleanup, so the inherited interface doesn't become canonical
   selector.

[confidential-os-builder]: https://github.com/confidential-dot-ai/confidential-os-builder
[#264]: https://github.com/confidential-dot-ai/c8s/issues/264
