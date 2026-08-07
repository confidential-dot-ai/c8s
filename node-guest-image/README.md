# node-guest-image

The c8s node image (`c8s-base`, `rke2[-cdi]-*` tags), defined in THIS repo
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
  contract (`C8S_REF`, `C8S_REGISTRY`, `C8S_DEV`, `C8S_NO_GPU`,
  `C8S_STOCK_ATTEST`, `C8S_NAME`, `C8S_MEMORY`) and the same profile stack
  and order; only the c8s profile content and kernel fragments come from
  here. Point `CONFOS_DIR` at a confos checkout (default: a sibling dir).

Migration state (see [#264] for the full plan):

1. Content here is a verbatim copy of confos main at v0.3.0 (`3e6f858`);
   nothing consumes it yet.
2. `--profile-dir` refuses to shadow an in-tree profile, so building from
   here requires a confos ref with `mkosi.profiles/c8s` deleted (the
   phase-1 confos PR). The switch gate: build the same c8s ref both ways
   and require identical `manifest.json` measurements.
3. After the gate passes, `c8s-image.yml` flips to `node-guest-image/build`
   (its kernel cache key must hash the fragment paths here instead of
   confos's), confos deletes its copy, and profile changes become one-PR
   changes in this repo.

[confidential-os-builder]: https://github.com/confidential-dot-ai/confidential-os-builder
[#264]: https://github.com/confidential-dot-ai/c8s/issues/264
