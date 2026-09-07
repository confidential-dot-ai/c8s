# Loader-control environment policy

The node-side `nri-image-policy` plugin blocks container creation when the
runtime environment contains any name beginning with these case-sensitive prefixes:

| Prefix | Scope |
| --- | --- |
| `LD_` | Every name beginning with `LD_`, including `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, tracing, debugging, profiling, and future controls |
| `GLIBC_TUNABLES` | glibc runtime and loader tuning, including all suffixed names |
| `GCONV_PATH` | Search path for dynamically loaded character-conversion modules, including all suffixed names |

The check applies to every `CreateContainer` request, including floor images,
workload images, captured namespace exemptions, and requests during startup.
It also applies in image-policy audit mode and with image allowlisting disabled.
Empty values, duplicate entries, and bare blocked names are rejected. Operators
resolve a rejection by removing the blocked variable from the image or deployment.
The policy has one strict setting, shared by all namespaces and workloads.

The plugin checks the runtime environment supplied by containerd through NRI,
which includes resolved image and deployment environment settings. The check
runs before image admission and inventory registration. A rejection returns the
blocked name and emits an audit event with reason `loader_env_blocked`.
Environment values remain private in both errors and policy logs.

## Security scope

This rule blocks loader-control variables at container creation. Existing
containers keep their current lifecycle when the plugin is upgraded; recreating
a container applies the rule. The rule ships in both the baked node plugin and
the chart-installed node plugin. Pod-as-CVM uses its separate in-guest policy.

Runtime components and other NRI plugins remain trusted to preserve the checked
environment. Commands executed later inside an admitted container follow the
workload's own execution controls. Library files, `/etc/ld.so.preload`, direct
loader invocation, application plugins, and interpreter configuration require
image, command, filesystem, and application policy appropriate to the workload.
Ordinary application environment variables remain configurable.

## Implementation and verification

`internal/cmds/nri-image-policy/loader_env.go` defines the reserved names and
rejection behavior. `plugin.go` calls the check at the start of `CreateContainer`.
`loader_env_test.go` covers reserved names, empty and duplicate values, ordinary
configuration, and admission through startup, floor, namespace, and audit paths.

Run the plugin suite with:

```sh
go test ./internal/cmds/nri-image-policy
```
