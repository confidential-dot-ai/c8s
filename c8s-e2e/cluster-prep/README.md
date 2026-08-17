# cluster-prep

One-shot prep of the runner clusters, applied by a human with the Rancher
kubeconfig. `apply.sh` is the whole procedure and is idempotent.

```
KUBECONFIG=~/dev/conf/github-runner.yaml ./apply.sh
```

## Bumping the TDX node image

The TDX lane boots a pinned node image and proves the guest against that
image's measurements. Four things must move together, and moving one alone is
how this breaks.

1. Find the build. Every c8s merge publishes
   `ghcr.io/confidential-dot-ai/node-guest-base:rke2-tdx-<c8s-short-sha>` and a
   matching `rke2-tdx-cdi-<sha>`. Pick the CDI tag's digest for `image`, since
   that is what CDI imports.

2. Read the measurements from that build, never from a running guest. They are
   in the `manifest.json` layer of the `rke2-tdx-<sha>` oras artifact, pushed by
   the same job as the CDI image. Fetch that layer alone, because `oras pull` would
   drag the 2.8GiB rootfs down with it:

   ```sh
   IMG=ghcr.io/confidential-dot-ai/node-guest-base
   # --password-stdin, not --password: the insecure-password warning goes to
   # stdout and lands in the middle of the JSON you are about to pipe to jq.
   auth() { gh auth token | oras "$@" --username "$USER" --password-stdin; }

   d=$(auth manifest fetch "$IMG:rke2-tdx-<sha>" \
       | jq -r '.layers[] | select(.annotations["org.opencontainers.image.title"] == "manifest.json") | .digest')
   auth blob fetch --output - "$IMG@$d" | jq .tdx
   ```

   `mrtd` often does not change between builds: it measures the initial TD
   memory, so it only moves when the firmware does. Both RTMRs will change.

3. Edit both files together. `tdx-rke2-image-refs.cm.yaml` carries the tuple;
   `tdx-rootdisk-dv.yaml` carries the same digest and a `c8s-root-<first-12-of-
   digest>` name. `c8sRef` must be the commit the image was built from, because
   the image bakes an admission floor from its own build ref and a mismatched
   CLI gets its own components denied. The `tdx-pin-check` consistency job
   enforces all of this on the PR.

4. Merge, then run `apply.sh`. Nothing publishes the pin for you: CI can read
   the ConfigMap but deliberately cannot write it, because `mrtd`/`rtmr1`/
   `rtmr2` are what the lane proves the guest against and an e2e job that could
   rewrite them could lower the bar the lane exists to enforce.

Old rootdisks are digest-named and survive a bump, so delete the superseded one
once the lane is green on the new pin:

```
kubectl -n confai-images delete dv c8s-root-<old-digest-prefix>
```

## Why the pin is a ConfigMap and not a file the lane reads

`tdx-metal-e2e.yml` is vendored byte-identical into c8s, which runs it as
`uses: ./.github/workflows/tdx-metal-e2e.yml`. Its `actions/checkout` therefore
checks out **c8s**, and c8s has no `c8s-e2e/` directory. c8s is public and
confidential-ci is private, so that run also has no credential to fetch one.
The ConfigMap is the one place both copies of the lane can read the same pin.

## When tdx-pin-check fails

It compares the ConfigMap against the files here, on merge and on a daily cron.
A failure means git and the cluster disagree, and it does not tell you which is
right. If the lane is green, the cluster is right and git should be corrected.
If someone just merged a bump, run `apply.sh`.

That check exists because the pin silently went stale for three weeks
(c8s#329): a c8s change required a CLI flag newer than the pinned `c8sRef`, and
nothing compared the two until the lane had been red for a week.
