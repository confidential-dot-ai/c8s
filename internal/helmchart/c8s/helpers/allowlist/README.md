# Allowlist helpers

Source: [templates/_allowlist.tpl](../../templates/_allowlist.tpl).
[All helpers](../README.md).

`c8s.components` resolves `Values.c8sComponents` into a JSON list of
`{name, image, enabled, cdsExempt}` records. `valuePath` selects the image object;
`enabledPath` selects its boolean gate, with an empty path enabling the component.
The derived name is the component's `valuePath`. `c8s.valueAtPath` takes
`(dict "root" <dict> "path" "a.b.c")` and returns the resolved value as JSON.
Boolean gates compare that JSON text to `true`: Helm's `fromJson` expects an
object, so scalar booleans must be handled as text here.

The component inventory drives both allowlist derivation and the coverage guard
in [validations.yaml](../../templates/validations.yaml); `c8s install` also reads
it from chart values. CDS is exempt from that guard because its self-entry is
seeded independently.

`c8s.imageAllowlist` returns a digest-to-image-reference map containing enabled,
digest-pinned components when `bootstrapAllowlist.deriveComponents` is true,
plus the CDS self-entry, enabled tls-lb nginx, and applicable RKE2 containerd-prep
image. Nginx is independently versioned and derives from its own image values.
Prep entries apply when NRI enforcement is enabled: the NRI prep image requires
an unbaked RKE2 installer.

`c8s.anyArgvDigests` extracts workload digests whose command and args policies
are both `any`. `c8s.alwaysAllow` merges these with `c8s.imageAllowlist` for the
host plugin's local admission list. Workloads that pin argv remain in the served
seed without being added by `c8s.anyArgvDigests`.

`c8s.digestWorkloadName` takes `digest` and `image`, strips the image reference
to its final repository segment, truncates it to 50 characters, substitutes
`image` for an invalid name, and appends the first 12 lowercase digest hex digits.
Keep this naming rule aligned with `pkg/allowlist.DigestEntryName`.

`c8s.allowlistSeedJSON` emits `c8s.allowlist/v1`: one workload per derived image
digest, with command and args policies set to `any`, followed by
`bootstrapAllowlist.workloads`. A supplied workload replaces the entire derived
entry of the same name. The document must satisfy `pkg/allowlist.ParseJSON`.
