# containerd patches for the node image

The node image runs the containerd that RKE2 unpacks from its `rke2-runtime`
airgap image; nothing in this repo builds containerd. The patches here are
the source-level fixes the image pipeline must build into that containerd
before static mode can require them.

## containerd-nri-fail-closed.patch

Against `github.com/containerd/nri` `v0.12.2`, `pkg/adaptation`. In
v0.12.2 `Adaptation.CreateContainer` registers a plugin with the validators
before the plugin replies, and a fatal reply error (`context.DeadlineExceeded`,
`ttrpc.ErrClosed`) becomes a nil reply. The default validator's
`required_plugins` therefore refuses every later request, but the request
that timed out is admitted, and two seconds of a privileged container is
enough to read CDS memory. The patch:

1. registers a plugin with the validators only after a successful reply, so a
   plugin closed on a fatal error is not present for that request;
2. returns a globally required plugin's fatal error as the error of
   `CreateContainer`, `PostCreateContainer` and `StartContainer`;
3. fails `PostCreateContainer` and `StartContainer` while a globally required
   plugin is absent. Upstream drops a closed plugin from its list after every
   request, so without this a container admitted at `CreateContainer` starts
   with no plugin present once the plugin has died, whatever verdict it
   cached for `StartContainer`.

Required plugins are the `required_plugins` of the default validator's
config (the node image sets `["nri-image-policy"]` in
`config-v3.toml.d/nri-image-policy.toml`). `CreateContainer` keeps the
validator's own presence check, toleration annotations included; per-pod
required plugins declared by annotation are covered by point 1 at
`CreateContainer` only.

### How the image pipeline applies it

The pipeline builds containerd with a `replace` for the nri module:

```sh
git clone --branch v0.12.2 https://github.com/containerd/nri
patch -p1 -d nri < containerd-nri-fail-closed.patch
# in the containerd checkout RKE2's rke2-runtime image is built from:
go mod edit -replace github.com/containerd/nri=../nri
```

and sets the version marker the plugin checks:

```sh
make VERSION="$(git describe --tags)+c8s.nri-failclosed"
```

`containerd --version` must then report a version containing
`+c8s.nri-failclosed` (`FailClosedRuntimeMarker` in the NRI plugin). In
sealed mode with `runtime.require_fail_closed: true` in
`image-policy.yaml.in`, the plugin exits when the marker is absent; the baked
template keeps the key `false` until the patched containerd ships.

### Checking the patch

```sh
cp -r "$(go env GOMODCACHE)/github.com/containerd/nri@v0.12.2" nri && chmod -R u+w nri
patch --dry-run -p1 -d nri < containerd-nri-fail-closed.patch
```
