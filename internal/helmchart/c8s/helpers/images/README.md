# Image helpers

Source: [templates/_images.tpl](../../templates/_images.tpl).
[All helpers](../README.md).

Image helpers render `repository@digest` when a digest is supplied, otherwise
`repository:tag`, and fail when neither is set. `c8s.kataDeployImage` and
`c8s.kataContainerdPrepImage` also reject setting both tag and digest. Other image
helpers prefer the digest when both are present. `volumed.image` delegates to
`c8s-common.image`; volumed's image carries cryptsetup and veritysetup.

`c8s.kataGuestImageTag` appends `-debug` when `kata.guestImage.debug` is enabled.
`c8s.kataGuestImageNvidiaTag` appends `-nvidia` or `-nvidia-debug` to the same base
tag. Published guest artifacts must follow these suffix conventions; the debug
variants allow the guest-agent log and exec RPCs used by `kubectl logs/exec`.
See [Kata GPU documentation](../../../../../docs/kata-gpu.md).

`c8s.imagePullSecrets` takes `(dict "root" $ "local" <list>)`. A nonempty local
list takes precedence over `Values.imagePullSecrets`; the install-time
`Values.imagePullSecret` is then appended and deduplicated. Callers indent the
rendered `imagePullSecrets:` block with `nindent`.
`c8s.serviceAccountImagePullSecrets` supplies the service account's local list.
