# Image helpers

Source: [templates/_images.tpl](../../templates/_images.tpl).
[All helpers](../README.md).

`c8s.imagePullSecrets` takes `(dict "root" $ "local" <list>)`. A nonempty local
list takes precedence over `Values.imagePullSecrets`; the install-time
`Values.imagePullSecret` is then appended and deduplicated. Callers indent the
rendered `imagePullSecrets:` block with `nindent`.
`c8s.serviceAccountImagePullSecrets` supplies the service account's local list.
