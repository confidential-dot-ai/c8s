# Static allowlist: a fixed workload set measured into RTMR[3]

A static allowlist seals a TDX node-as-CVM cluster to one reviewed policy
bundle. The node measures the bundle into RTMR[3] before RKE2 starts, the
baked NRI plugin admits only the containers the bundle describes, and CDS
issues certificates only to pods on nodes that carry that register. A
relying party recomputes the register from the bundle it reviewed and checks
one fresh quote.

This document is the concept and operations reference. The dynamic
allowlist, where an operator key authorizes `c8s allowlist` writes, is
described in [`allowlist-and-capabilities.md`](allowlist-and-capabilities.md);
the node image side in [`node-guest-image/README.md`](../node-guest-image/README.md).

## Goal

A user reviews one generic node image and one policy bundle. From one quote
they can then verify that the cluster runs only that set of pods and that the
operator, who holds `cluster-admin`, cannot read user data. The operator can
still scale, restart, and delete allowed pods.

Out of scope, by decision: availability and liveness (any failure may power
the node off), routing and where tls-lb forwards plaintext, SEV-SNP,
pod-as-CVM, operator keys, and browser clients. Clusters with the same image
tuple and the same bundle are indistinguishable to a relying party.

## Adversary

The adversary holds `cluster-admin` on the running cluster and controls the
hypervisor, every disk other than the published image, the network, and the
launch attachments. They have no code execution inside the CVM at boot. They
want plaintext, secrets, or memory.

Trusted: TDX; the measured image (kernel, initrd, systemd units, containerd,
RKE2 including kubelet and API server, attestation-api, the NRI plugin, CDS,
tls-lb); the reviewed code of every allowlisted workload. Privileged platform
pods (cilium, volumed, the NVIDIA device plugin) are node TCB: pinned by the
bundle, not proven harmless.

## Trust chain

`pkg/runtimemeasure` owns the arithmetic. Every side, the node, the
installer, and every verifier, derives the register through that package.

```text
manifest.json {MRTD, RTMR[1], RTMR[2]}     published with each generic image build

Extend(reg, event) = SHA-384(reg ‖ event)   the hardware extend primitive

static boot:
  RTMR[3]     = Extend(Extend(Zero, mode_static), policy)
  mode_static = SHA-384("c8s/rtmr3/mode/static/v1")
  policy      = SHA-384("c8s/rtmr3/policy/v1:" ‖ index)
  index       = {"static-allowlist.json":"sha256:<hex>"}
                JSON with sorted keys and no whitespace, one entry per bundle
                member, each digest over the member's raw bytes

dynamic boot:
  RTMR[3]      = Extend(seed, mode_dynamic), then one extend per measured workload
  mode_dynamic = SHA-384("c8s/rtmr3/mode/dynamic/v1")
  seed         = ForOperatorKey(pubkey) on an operator-key boot, else Zero
```

The static tuple is `{MRTD, RTMR[1], RTMR[2], RTMR[3]}`. The verifier
recomputes RTMR[3] from the reviewed bundle, exactly as `--operator-pkey`
derives it from the key on a dynamic node. The policy digest needs no
certificate extension: it is in the register, and every mesh leaf already
carries the allowlist digest in its matched-workload stamp (`.1.5`,
[`ratls.md`](ratls.md)).

**Every boot extends a mode event before containerd starts.** A dynamic boot
extends `mode_dynamic`, a static boot `mode_static` and then `policy`. Without
this, a dynamic node, where `cluster-admin` is node root through any
privileged pod, could write the static events into the register itself and
pass every static check. `c8s policy-measure` also refuses a register that is
not the launch value (`Zero`, or `ForOperatorKey` of the initrd-staged key)
before it extends anything.

## The policy bundle

A bundle is a flat set of JSON members. `static-allowlist.json` is the only
member today and is required; `pkg/policybundle` refuses any other name until
a consumer exists for it. Limits: 64 members, 8 MiB each. The index digests
the raw member bytes, so a member that differs by one byte is a different
bundle.

`c8s allowlist lint --sealed` requires `static-allowlist.json` to be
byte-equal to its own canonical form. The reviewed bytes are the measured
bytes, and CDS stamps every leaf with the SHA-256 of the same bytes.

### Attaching the bundle at launch

The node looks the bundle up as an ISO9660 disk with volume label
`policydata` (`/dev/disk/by-label/policydata`). `c8s policy-disk` builds it.

- **KubeVirt**: a Secret holding the members, mounted as a `secret` volume
  with `volumeLabel: policydata` on a virtio disk. `c8s policy-disk
  --kubevirt-secret NAME` writes that Secret and the disk and volume entries
  to add to the VirtualMachine.
- **libvirt**: a CD-ROM device pointing at the ISO (`xorrisofs -V
  policydata -J -R`).

A static node has no operator key. `c8s policy-measure` fails, and the unit
powers the node off, when an `opkeydata` disk is attached beside
`policydata`.

### Node-side state

`c8s-policy-measure.service` runs on every boot before `rke2-server` and
`rke2-agent`, which require it. It writes the measured state to a tmpfs
directory that every static consumer reads:

| Path | Content |
|---|---|
| `/run/confai/policy/mode` | `static` or `dynamic`, written last |
| `/run/confai/policy/digest` | lowercase hex SHA-256 of the index (static only) |
| `/run/confai/policy/<member>` | the raw member bytes (static only) |
| `/run/confai/attestation-api.sock` | attestation-api, served by `c8s-attest-socket.service` |

On a TDX boot the unit:

1. Reads RTMR[3] back. It must equal `Zero`, or `ForOperatorKey` of the
   initrd-staged public key when one exists.
2. Without a `policydata` disk: extends `mode_dynamic`, writes
   `mode=dynamic`, exits 0.
3. With one: fails if `opkeydata` is present, mounts the ISO read-only,
   reads every member under the bundle limits, lints
   `static-allowlist.json` as sealed, writes the members and the index digest
   under `/run/confai/policy`, extends `mode_static` and then `policy`, reads
   the register back and compares it, and writes `mode=static` last.

Any failure exits non-zero and `FailureAction=poweroff-force` powers the node
off. On an SEV-SNP image the unit writes `mode=dynamic` without touching any
register; a `policydata` disk there is fatal.

`c8s-attest-socket.service` fronts the confos `attestation-api.service`
(loopback `:8400`) with `c8s attest-proxy` on `/run/confai/attestation-api.sock`.
Root owns the socket, mode 0660, group 65532, so CDS (uid 65532, given that
supplementary group by the chart) and the injected sidecars can connect. The
socket is what makes the verifier immutable to the control plane: the baked
plugin config and the sealed CDS argv name a path, not an address, so no
chart value or pod restart can point either at another verifier.

In static mode `cred-release.service` starts without an operator key. RTMR[3]
must equal the value recomputed from `/run/confai/policy`, and any caller
receives the operator credential. The caller attests the node, not the other
way round: `c8s get-kubeconfig` verifies the RA-TLS serving certificate of
`cred-release` and presents no evidence of its own. `cluster-admin` is the
adversary in this design, so that gives nothing away.

## Mode is explicit, never inferred

No component infers static mode from a file's presence:

- The baked plugin config sets `allowlist.policy_dir: /run/confai/policy`.
  At start the plugin reads `mode`. `static` requires the member, the digest
  file, and sysfs RTMR[3] equal to `ForStaticAllowlist(index)`. `dynamic` on
  TDX requires the register to equal `ForDynamic(seed)`. A missing or unknown
  mode, or a register mismatch, powers the node off.
- CDS runs with `--static-allowlist` and refuses to start unless `mode` reads
  `static`, the members index to `digest`, that index derives the RTMR[3] the
  measurements entry pins, and its own evidence over the socket carries the
  full static tuple.
- The chart renders static mode from `staticAllowlist.enabled=true`.
  `c8s install --static-allowlist` refuses a node whose RTMR[3] disagrees
  with the bundle.

## The sealed document

A sealed `static-allowlist.json` is a `c8s.allowlist/v1` document in which
`digests` is `{}` and every container carries a complete rule. Dynamic
consumers ignore the new fields, and a document without them canonicalizes
byte-identically.

```json
{
  "schema": "c8s.allowlist/v1",
  "digests": {},
  "workloads": {
    "demo-nginx": {
      "label": "docker.io/library/nginx:1.27",
      "containers": [
        {
          "digest": "sha256:<nginx>",
          "image": "docker.io/library/nginx:1.27",
          "command": { "policy": "exact", "argv": ["/docker-entrypoint.sh"] },
          "args":    { "policy": "exact", "argv": ["nginx", "-g", "daemon off;"] },
          "env": {
            "policy": "exact",
            "names": ["KUBERNETES_SERVICE_HOST", "PATH", "POD_IP"],
            "values": {
              "KUBERNETES_SERVICE_HOST": { "value": "10.53.0.1" },
              "PATH": { "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
              "POD_IP": { "from": "podIP" }
            }
          },
          "mounts": {
            "policy": "exact",
            "destinations": ["/data", "/dev/shm", "/etc/hosts", "/var/run/secrets/kubernetes.io/serviceaccount"],
            "rules": {
              "/data": { "source": "pvc", "review": "read-only model weights; the server parses them with a bounded loader" },
              "/dev/shm": { "source": "platform" },
              "/etc/hosts": { "source": "platform" },
              "/var/run/secrets/kubernetes.io/serviceaccount": { "source": "serviceAccountToken" }
            }
          }
        }
      ]
    }
  }
}
```

### Environment values

Under `env.policy: exact`, every observed name must be listed and every
listed name carries a rule. `{"value": "..."}` matches byte-exact.
`{"from": SOURCE}` matches the value the plugin reads for that pod field;
`SOURCE` is one of `podIP`, `podName`, `podNamespace`, `podUID`, `hostIP`, or
`nodeName`. There is no unconstrained value: a name the reviewer cannot pin is
a container the reviewer cannot admit. `render --sealed` refuses `envFrom` and
ConfigMap, Secret, or resource-field references for that reason.

### Mount rules

Under `mounts.policy: exact`, every bind destination carries a `source` class:

| Class | What the plugin classifies there | Review |
|---|---|---|
| `emptyDir` | `kubernetes.io~empty-dir` volumes | no |
| `serviceAccountToken` | the kubelet's `kube-api-access-*` projected volume | no |
| `pvc` | CSI and local volumes, and local-path-storage's `/opt/local-path-provisioner/` | required: why operator-supplied contents cannot steer the workload |
| `platform` | the kubelet's `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`, `/dev/termination-log`, `/dev/shm`, and the plugin's own socket directory `/run/nri-image-policy` | no |
| `nodeState` | binds from `/run/confai`: the attestation socket and the policy directory | required: why the entry may reach the node's verifier or policy state |
| `hostPath` | anything else, admitted only through `privileges.hostPaths` | through `privileges.review` |

`nodeState` is its own class rather than `platform` so the `platform` rule
every container carries for `/etc/hosts` can never admit the attestation
socket bound there. ConfigMap, Secret, other projected, downward-API, and
hostPath volumes classify outside the reviewed classes; `render --sealed`
turns them into a `hostPath` rule with `privileges.hostPaths:
["/var/lib/kubelet/pods/"]` (or the host path as bound) and a `privileges`
block the reviewer must complete.

### Privileges

`privileges` marks an entry as node TCB. It carries `privileged`,
`hostNamespaces` (`net`, `pid`, `ipc`), `capabilities` (OCI form, beyond the
runtime default set), `devices`, `hostPaths` (an entry ending in `/` admits
the subtree), `unmaskedProc`, and a `review` string that says why the entry is
acceptable. A privileged entry holds every capability and device, so those
lists are not compared for it. An entry without `privileges` must pin
`command`, `mounts`, and `env` exactly and `args` exactly or `deny`.

### What `lint --sealed` checks

`c8s allowlist lint --sealed FILE` runs the offline lint and then, as errors:

- the file is byte-equal to its canonical form;
- `digests` is `{}` and `workloads` is an object (the form the CDS store
  serves back, so the stamp matches the measured bytes);
- every `privileges` block has a non-empty `review`;
- every unprivileged entry has exact `command`, `mounts`, and `env`, and
  `args` exact or deny;
- every exact `env` carries `values` and every exact `mounts` carries `rules`;
- every `pvc` and `nodeState` rule has a `review`;
- a `hostPath` rule appears only on an entry with `privileges`.

The same function runs in the node (`c8s policy-measure`), the plugin,
`c8s policy-disk`, `c8s install`, `c8s get-kubeconfig`, and `c8s verify`, so
none of them can disagree. CDS trusts the node's measurement instead: it
refuses to start unless the members index to `digest`, that index derives the
pinned RTMR[3], and its own evidence carries the tuple.

## What the sealed plugin enforces

On a static boot the NRI plugin loads the measured member, checks the index
against `digest` and sysfs RTMR[3] against `ForStaticAllowlist(index)`, and
runs with no digest floor, no `always_allow`, no pull loop, no exempt
namespaces, and `policy.mode` forced to fail-closed. It pins CDS to the
node's own tuple, read from a fresh quote of itself over the attestation
socket, so no installer writes pins into the measured config and a CDS on an
unsealed node of the same image is refused.

- **Synchronize.** In a valid static boot no container exists when the plugin
  registers. Any container reported at Synchronize powers the node off.
- **CreateContainer** builds an observation: argv, env names and values, bind
  sources classified as in the table, host namespaces, devices not explained
  by a CDI spec under `/etc/cdi` or `/var/run/cdi`, whether any OCI hook is
  present, and privilege. `Index.Admit` must match a complete rule; hooks are
  never admitted. `policy.label_rules` still apply (deny only).
- **PostCreateContainer** loads the OCI spec through containerd for
  capabilities and masked paths and caches a verdict. **StartContainer**
  returns the cached verdict; containerd deletes the task before the
  entrypoint runs. No cached verdict at start means re-evaluate, else deny.
- Every hook answers within 1.5 s and a timeout denies. containerd's own
  request timeout is 2 s, and the unpatched `containerd/nri` admits a request
  whose plugin call times out (see [Known gaps](#known-gaps-and-follow-ups)).
- The plugin writes `-1000` to its own `oom_score_adj`, since a plugin the
  kernel kills mid-request admits that request.

Any fatal condition after `mode` reads `static` calls `systemctl poweroff
--force --force`, falling back to the reboot syscall.

## CDS and the chart

CDS runs with `--static-allowlist --policy-dir /run/confai/policy
--allowlist-seed /run/confai/policy/static-allowlist.json` and a `unix://`
`--attestation-api-url`. It refuses `--operator-keys` and
`--allowlist-persistent`, requires `--ratls-platform=tdx`, and requires a
`--measurements-config` with exactly one entry pinning RTMR[1], RTMR[2], and
RTMR[3]. `/attest` enforces that entry for every requester: a pod on an
unsealed node of the same image, or on a node sealed to another bundle,
presents a different RTMR[3] and is denied even when its containers match a
workload entry. Each start reseeds from the measured member, so no stored
entry can outlive the bundle.

`c8s install --static-allowlist` sets these chart values:

| Value | Default | Static install |
|---|---|---|
| `staticAllowlist.enabled` | `false` | `true` |
| `staticAllowlist.policyDir` | `/run/confai/policy` | unchanged |
| `staticAllowlist.attestationSocketDir` | `/run/confai` | unchanged |
| `nriImagePolicy.enabled` | | `false` (the image bakes the sealed plugin) |
| `cds.persistence.enabled` | | `false` |
| `cds.measurementsConfig`, `ratlsMesh.measurementsConfig` | | one entry `static-allowlist`: MRTD, RTMR[1], RTMR[2] from the manifest, RTMR[3] from the bundle |
| `cds.measurements`, `cds.rtmrs`, `ratlsMesh.*` | | MRTD and RTMR[1], RTMR[2] only |
| `<component>.repository`, `<component>.digest` | | the digest the bundle names for each deployed component |

When `staticAllowlist.enabled` is true the chart:

- mounts `policyDir` and `attestationSocketDir` into the CDS pod read-only as
  `hostPath` volumes of type `Directory`, and gives the pod supplementary
  group 65532;
- has CDS, tls-lb, ratls-mesh, and the operator dial
  `unix://<attestationSocketDir>/attestation-api.sock`; no pod carries a
  `HOST_IP` environment variable and no unprivileged argv contains
  `$(HOST_IP)`;
- sets `enableServiceLinks: false` on every c8s pod, so the environment is
  the one the sealed rules list;
- passes `--static-allowlist --attestation-socket-dir <dir>` to the operator,
  which mounts the socket directory into every injected sidecar and passes
  `--cds-pins-from-own-quote` instead of flat CDS pins;
- carves the two hostPaths out of the deny-host-namespaces
  ValidatingAdmissionPolicy on the same terms as the inventory socket
  directory.

RTMR[3] goes only into the measurements config file, never into the flat
lists: flat pins land in container argv, that argv is in the bundle, and the
register is derived from the bundle.

The render fails (`VALIDATION_ERROR kind=static_allowlist_*`) when
`staticAllowlist.enabled` is combined with any of: `attestationApi.cvmMode`
other than `node`, a platform other than TDX, `cds.operatorKeys`,
`cds.persistence.enabled`, `kata.enabled`, `attestationApi.enabled`,
`nriImagePolicy.enabled`, or an empty `cds.measurementsConfig`.

## Sealing a cluster

The bundle client commands take the bundle as a directory (every regular
file is a member) or as the `static-allowlist.json` file alone (a one-member
bundle). They refuse an `.iso`: pass the directory the ISO was built from.
The examples use `bundle/`.

### 1. Render the sealed document

`render --sealed` needs the chart values the cluster is installed with. The
component digests in that file are the digests the c8s entries pin, and
`c8s install --static-allowlist` later pins the same digests from the bundle.
Derive a measurements config from the image manifest and render the values
for the target release:

```sh
c8s measurements derive manifest.json > image.measurements.json
c8s render-values --cvm-mode=node --hardware-platform=tdx --image-tag TAG \
  --measurements-config image.measurements.json > values.yaml
```

Add the static keys to `values.yaml`: `staticAllowlist.enabled: true`,
`nriImagePolicy.enabled: false`, `cds.persistence.enabled: false`. The
measurements config content is not yet the static entry; that is fine for
rendering, because it reaches CDS and ratls-mesh through a ConfigMap, never
through argv. Then render:

```sh
c8s allowlist render --sealed --system-floor system-floor.json \
  --chart-values values.yaml --workloads workloads.yaml \
  --report review.txt > bundle/static-allowlist.json
```

- `--system-floor` is the `system-floor.json` the image build publishes
  beside `manifest.json`: one skeleton entry per RKE2 floor image with the
  image's own `entrypoint` and `cmd`. The build cannot see the static pod
  manifests, so `env`, `mounts`, and `privileges.review` start empty. Complete
  them from a dynamic node's observations before linting.
- `--chart-values` renders the chart with `helm template` and derives one
  entry per c8s pod from the image configs and the templates.
- `--workloads` takes Pod, Deployment, StatefulSet, DaemonSet, Job, and
  CronJob manifests; it requires `--chart-values` because it runs the
  webhook mutator in-process on each pod template, so `c8s-cert`,
  `c8s-cert-wait`, `c8s-secret`, and `c8s-volume` get rules from the same
  code that injects them.
- `render` needs `helm` on `PATH`, and `crane` to read image configs.
- The report lists every executable, argv, env rule, mount rule, and
  privilege. Reviews for privileged entries, `pvc`, and `nodeState` mounts
  start empty; `lint --sealed` refuses the document until you complete them.
- Pods that do not set `enableServiceLinks: false` get a warning: the kubelet
  adds one environment variable per Service in the namespace, which no rule
  can pin. `KUBERNETES_SERVICE_HOST` defaults to `10.53.0.1`, the node
  image's service CIDR; override with `--kubernetes-service-host`.

### 2. Lint and build the disk

```sh
c8s allowlist lint --sealed bundle/static-allowlist.json
c8s policy-disk --member bundle/static-allowlist.json -o policydata.iso
```

`policy-disk` prints `index-digest: sha256:<hex>` and `rtmr3: <hex>`, the
values a node sealed to this bundle reports. Record them. For KubeVirt:

```sh
c8s policy-disk --member bundle/static-allowlist.json -o policydata.iso \
  --kubevirt-secret c8s-policydata > policydata-secret.yaml
```

The Secret goes to stdout and the digest lines to stderr. The file ends with
the disk and volume entries to add to the VirtualMachine, as comments.
`policy-disk` needs `xorrisofs`, `genisoimage`, or `mkisofs` on `PATH`.

### 3. Launch the nodes

Attach `policydata.iso` (label `policydata`) to the generic node image with
no `opkeydata` disk. A node that fails to seal powers off.

### 4. Get a kubeconfig

```sh
c8s get-kubeconfig --node NODE_IP --image-manifest manifest.json \
  --static-allowlist bundle/ --out guest.kubeconfig
```

`--static-allowlist` replaces `--operator-key`: the gate pins the image tuple
from the manifest and RTMR[3] derived from the bundle, and fetches the
credential without an operator token. It is mutually exclusive with
`--operator-key` and `--workload-image`.

### 5. Install

```sh
c8s install --cvm-mode=node --hardware-platform=tdx \
  --static-allowlist bundle/ --image-manifest manifest.json
```

Before the chart renders, `install`:

- lints `static-allowlist.json` as sealed;
- requires `--cvm-mode=node` and `--hardware-platform=tdx`;
- refuses `--operator-keys`, an explicit `--resolve-digests=true`,
  `--measurements`, `--measurements-config`, and `--rtmrs`, and forces digest
  resolution off: every component digest comes from the bundle, and a
  component the bundle does not name fails the install;
- attests every node through `http://NODE_INTERNAL_IP:8400/attest` and
  requires the static tuple, RTMR[3] included. When a node's InternalIP is
  not routable from where you run `install` (a KubeVirt masquerade guest),
  pass `--static-node-attest NODE_NAME=HOST:PORT` for that node;
- lists every running container whose digest the bundle does not name and
  fails; `--force` installs anyway with a warning. The containers' argv, env,
  and mounts are not visible through the API, so that check stays the sealed
  plugin's.

A static install emits no image tag: every component is pinned by the
digest the bundle names for its repository. For GitOps, `c8s render-values` takes the same `--static-allowlist` and
`--image-manifest` flags and emits the install-time values, static entry
included. Rendering the bundle again against those values produces the same
bytes.

### 6. Verify from outside

```sh
c8s verify https://TLS_LB --kind lb --image-manifest manifest.json \
  --static-allowlist bundle/ --workload ENTRY --mesh-ca mesh-ca.pem -o json
```

`--static-allowlist` is a sibling of `--operator-pkey`: it derives and pins
RTMR[3] from the bundle and holds the leaf's matched-workload stamp to the
bundle's own document. It requires `--image-manifest`, `--workload`, and
`--mesh-ca`, and conflicts with `--operator-pkey`, `--expected-rtmr3`,
`--rtmr 3=`, and `--allowlist`. A verified verdict reports
`static_policy_digest` (`sha256:<hex>` of the index), the value RTMR[3] was
derived from. Exit codes are the `c8s verify` contract: `0` verified, `1`
usage, `2` policy failed, `3` evidence unavailable, `4` partially verified
([`operator.md`](operator.md#verifying-attestation-after-install)).

`install` and `verify` take the same bundle the node booted with, never the
disk on the node: they recompute the index and RTMR[3] from it.

## What the operator can still do

- Scale, restart, and delete allowed pods; deny service; reboot into another
  bundle, which pinned clients reject.
- Point a Service or EndpointSlice at another allowed pod, and choose where
  tls-lb forwards plaintext. This design makes no claim about where user
  data goes after the front door.
- Supply PVC contents at mount paths whose rule's `review` says why that
  cannot steer the workload. Volume integrity and encryption are the volume
  design ([`volumes.md`](volumes.md)).
- Run another copy of a privileged platform pod with its sealed argv and env
  and drive it through its own API. Such entries are reviewed node TCB.
- Read Kubernetes Secrets in etcd. Workloads take secrets from CDS
  `/secrets`; the sealed rules admit no Secret or ConfigMap mount outside a
  reviewed `privileges.hostPaths`.
- Obtain the operator kubeconfig: `cred-release` serves any caller in
  static mode. `cluster-admin` is the adversary already.

## Known gaps and follow-ups

- **containerd admits a timed-out plugin call.** `containerd/nri` v0.12.2
  registers the plugin with its validators before the reply and turns a
  deadline or closed-connection error into a nil reply, so `required_plugins`
  refuses later requests but the request that timed out is admitted. The fix
  ships as `node-guest-image/c8s/patches/containerd-nri-fail-closed.patch`
  for the image pipeline to build into RKE2's containerd with the
  `+c8s.nri-failclosed` version marker. Until that containerd ships, the
  baked `image-policy.yaml.in` keeps `runtime.require_fail_closed: false` and
  the plugin's own 1.5 s deadline and OOM protection are the mitigation.
- **The attestation-api socket is a proxy, not a native listener.**
  attestation-api lives in attestation-rs and listens on loopback only;
  `c8s-attest-socket.service` fronts it with `c8s attest-proxy` inside the
  measured image. A native unix listener is a follow-up in that repository.
- **The mesh CA is not evidence-authenticated.** Only leaves carry RA-TLS
  evidence, so `verify --static-allowlist` still needs `--mesh-ca` to vouch
  for the matched-workload stamp. Authenticating the CA by its own evidence
  would make `--mesh-ca` optional.
- **`install` cannot preflight observed container specs.** containerd is not
  visible through the API, so `install` checks running image digests against
  the bundle and leaves argv, env, and mounts to the sealed plugin.
- **CDI and GPU workloads are denied in sealed mode.** A CDI device injects
  OCI hooks and host bind mounts; the hooks rule denies the container, and the
  binds classify as `hostPath`. GPU workloads on a sealed node need a typed
  rule.
- **local-path-storage's helper pod has no admissible rule.** Its `busybox`
  argv is per PVC. Static images ship without local-path-storage until a
  typed rule exists.
- **SEV-SNP** has no runtime register. The same policy digest would go
  through HOSTDATA, as `HostDataForOperatorKey` does for the operator key.
- **The threat model and requirements documents** live in the c8s-workspace
  repository, not here.
- **Two power-off assertions have no e2e coverage**: delaying the plugin past
  its deadline and a container present at Synchronize both need an in-guest
  fault injector, which a locked image does not carry.
- **A launch wrapper** that attaches the bundle and the generic image in one
  step is a follow-up.
