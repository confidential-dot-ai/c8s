# Encrypted volumes

Data too large to be a secret, encrypted at rest on host-visible storage, and
decryptable only inside a TEE by a workload the allowlist names. Model weights
are the case this is built for.

This complements [`secrets.md`](secrets.md) — a volume key *is* a secret, stored
and released by exactly the machinery described there. What is new is the
artifact the key opens, and the fact that it persists.

## Why a volume is different from a secret

Every other value c8s protects is RAM-resident and dies with the pod. A volume
does not: its ciphertext sits on storage the host reads and writes freely, and
the host keeps it.

That makes a leaked volume key **retroactive and permanent**. A leaked session
key forges future connections; a leaked volume key decrypts a copy the adversary
already has. Treat volume keys accordingly.

## The artifact

An image built by `c8s volume create`, in three layers:

| | |
|---|---|
| filesystem | erofs, read-only by construction |
| integrity | dm-verity, hash tree appended to the filesystem |
| confidentiality | plain dm-crypt, `aes-xts-plain64`, 512-bit key, 512-byte sectors |

**There is no LUKS header.** A LUKS2 header is on-disk metadata whose integrity
is an unkeyed checksum the host can recompute, and it is parsed as root inside
the TEE on every open. Plain dm-crypt has no on-disk metadata at all, so every
parameter comes from the key blob, which only ever travels over the attested
channel. What a header would buy — rotating the key via keyslots — is not real
against a host that keeps a copy of the old header and can restore it.

**The hash tree is inside the encryption.** A hash tree is a fingerprint of the
plaintext, so leaving it in the clear would let the host identify what a volume
holds. Keeping it inside also means the root hash commits to the data rather
than to one encryption of it.

**Sector size is 512.** For `aes-xts-plain64` the tweak is the sector index, but
at a larger sector size dm-crypt's numbering depends on `iv_large_sectors` — and
a writer and an opener that disagree produce a volume that decrypts to noise
with nothing to say why.

### The key blob

The value stored at the secret path. Everything needed to open the volume, and
nothing taken from anywhere else:

```json
{ "type": "c8s.volume/v1",
  "key": "<base64, 64 bytes>",
  "verity": { "root_hash": "<hex>", "salt": "<hex>",
              "data_blocks": 26214400, "hash_offset": 107374182400 } }
```

The verity root hash rides here rather than in an annotation or the allowlist
entry because it is the integrity anchor, and an anchor the host can edit
anchors nothing. It is also a fingerprint naming which model a volume holds, and
`GET /allowlist` is unauthenticated.

## Creating a volume

```sh
c8s volume create \
  --name weights \
  --source ./llama-3.1-8b \
  --out ./weights.img \
  --path /tenant-a/volumes/weights \
  --escrow-out ./weights.escrow.json \
  --node node-1 \
  --url https://cds.example --measurements-file ./m.txt \
  --operator-key ./operator.key
```

It packages the directory, formats the hash tree, generates a key, encrypts, and
`PUT`s the blob. It prints the annotations, the `nodeSelector`, and the
allowlist grant to apply; it does not modify any workload.

The key is generated per volume and never taken from you. AES-XTS is
deterministic, so re-encrypting a changed directory under a reused key would
tell the host exactly which sectors changed between versions.

`--name` is capped at 12 characters. The node selects the device by its disk
serial, `VIRTIO_BLK_ID_BYTES` is 20, and `c8s-vol-` takes eight; a thirteenth
character is silently dropped, so two volumes would be indistinguishable to the
node.

Creation needs `mkfs.erofs` and `veritysetup` on the machine running it. It does
**not** need root, a loop device, or `cryptsetup`: the encryption is done in
process.

### Keep the escrow file

`--escrow-out` is required, written `0600`, and refuses to overwrite. It holds
the key.

CDS keeps secrets in process memory and nowhere else, so **a CDS restart makes
every volume in the cluster unopenable until its key is written again**, and the
escrow file is what you write it back from. Lose it and restart CDS and the
ciphertext is unrecoverable — there is no other copy.

Keep escrow files somewhere durable and access-controlled. Their compromise is
equivalent to handing over the plaintext, permanently.

## Placing the image on a node

The image is ciphertext. Copy it to the node by any means, including through the
untrusted host — that the host holds the bytes is the design premise, not a
compromise of it.

Attach it as a **raw block device** whose disk serial is `c8s-vol-<name>`. The
node reads that serial from `<dev>/serial` (virtio-blk) or from VPD page 0x80 at
`<dev>/device/vpd_pg80` (SCSI), so either transport serves.

A confos node has no persistent writable storage — the root overlay is
reformatted on every boot — so a volume must be its own device rather than a
file on the node's filesystem.

How the device is produced depends on the hypervisor:

| | |
|---|---|
| QEMU/KVM | `-device virtio-blk,drive=…,serial=c8s-vol-<name>` |
| cannot set a serial | `c8s volume attach <name> --image <path>`, on the node, as root |

Hyper-V exposes no virtio bus at all, and a cloud disk's serial belongs to the
provider, so on those nodes there is nothing to set. `attach` drives LIO's
loopback target instead — a local SCSI disk whose unit serial is ours to choose.
`c8s volume detach <name>` removes it again, leaving the ciphertext and the key
where they are.

The serial is a **selector, not a trust input**. The host chooses it and answers
the query per read. Pointing a pod at the wrong device fails closed: the wrong
key produces noise, and verity refuses it.

Because the device is on one node, the pod must be scheduled there; `create`
emits the matching `nodeSelector`.

## The grant

Release is gated on the workload entry's `secrets` grant, exactly as in
[`secrets.md`](secrets.md#the-grant):

```json
"secrets": { "policy": "allow", "read": ["/tenant-a/volumes/weights"] }
```

**Name the exact path, not a subtree.** `/tenant-a/volumes/**` grants every
volume beneath it, and the annotation naming which volume to open is
host-written. `create` prints an exact-path grant for this reason.

`read` only. A volume is mounted read-only, so a write grant says nothing about
whether a workload may see the plaintext.

## Consuming a volume

A pod names its volumes in an annotation:

```yaml
annotations:
  confidential.ai/cw: llama-infer
  confidential.ai/c8s-volumes: "weights=/tenant-a/volumes/weights"
  confidential.ai/c8s-volume-dir: "/models"    # optional; default /run/c8s/volumes
```

Each entry is `NAME=/store/path`. `NAME` selects the node's device by its
`c8s-vol-<NAME>` serial and names the directory the plaintext appears in under
the volume dir — above, `/models/weights`. It must be a DNS-1123 label of at
most 12 characters, because the serial holds no more.

The webhook injects a `c8s-volume` sidecar and, per volume, an `emptyDir`
mounted read-only with `mountPropagation: HostToContainer`. The sidecar fetches
the key over the attested `/secrets` flow and posts `{name, blob}` to
`c8s volumed`, which opens the device and mounts it read-only into that pod's
`emptyDir`.

Where volumed runs, and how the sidecar reaches it, depends on the shape:

| | node-CVM | kata |
|---|---|---|
| volumed | a privileged DaemonSet on every node | `volumed --guest`, baked into the guest rootfs |
| reached over | a unix socket in the inventory's socket directory | the guest's loopback `127.0.0.1:8402` |
| mounts into | the pod's kubelet directory | kata's ephemeral directory inside the VM |
| `emptyDir` medium | default — volumed resolves with `RESOLVE_NO_XDEV` | `Memory`, so kata keeps it a guest tmpfs; with `shared_fs="none"` a default-medium one becomes a `disk.img` block device |

The node-CVM DaemonSet is **off by default**: it runs privileged, with `hostPID`
and a writable bind of the kubelet directory. Turn it on with
`c8s install --volumes` where volumes are served, or `volumed.enabled=true` for a
chart consumer. Under kata the flag deploys nothing — the guest image carries the
daemon — so it is safe to pass in either shape. A pod requesting a volume on a
cluster with neither shape — `nri-image-policy` disabled and not kata — is
refused at admission rather than left waiting on a mount that can never land.

Under kata the device must also reach the guest. kata-agent always mounts a
block storage it is handed and cannot mount ciphertext, so direct-volume
assignment is not usable; the qemu wrapper
(`kata-guest-base/scripts/kata-qemu-scratch-wrapper.sh`) attaches this pod's
volume devices to its VM instead, read-only and with the serial preserved. Which
volumes it attaches comes from the pod's annotation — a selector, not a trust
input, on the same reasoning as the serial: attaching another tenant's device
hands the guest ciphertext the host already holds, and it still cannot be opened
without the key CDS releases against the grant.

What decides whether a mount happens, in order:

1. CDS releases the blob to the pod's sandbox — verified mesh leaf, single-use
   challenge, inventory-signed sandbox token, whole-container-set match against
   one workload entry, grant covers the path.
2. The daemon mounts into **the calling pod's directory and no other**. The pod
   comes from the caller's cgroup via kernel peer credentials; the request has no
   field naming it, and the mount target is built from the resolved UID.
3. The device opens only if the key is right and the verity root hash matches.

A request naming a volume already open under that pod must present the same key
and root hash. Without that the volume *name* — a label in a host-written
annotation — would be the credential.

The volume appears **after the workload starts**, because release is gated on
the whole container set having been admitted. A consumer must wait for it rather
than read it at startup.

The key must already be in the store. Unlike a secret — where the first pod to
ask is the one that defines the value — `get-volume` only ever reads, so a pod
scheduled before `c8s volume create` has run retries and then fails.

Teardown follows the pod's cgroup, not its kubelet directory: kubelet cannot
remove that directory while a volume is mounted under it, so it survives exactly
as long as the mount that would be torn down.

### Possession of the blob is the authorization

The daemon does not repeat CDS's release decision. It resolves who is calling
only to decide where to mount, and checks nothing about what that caller is
entitled to — any pod that reaches it presenting a well-formed blob has that
volume opened into its own directory.

What makes that sound is that the daemon's reach is confined to one tenant:

- **node-CVM** rests on the node being single-tenant. Every pod on it belongs to
  the same tenant, so a blob one of them can obtain is one they are all entitled
  to.
- **kata** rests on the guest holding exactly one pod. The daemon serves only
  that guest's loopback, so the only caller that can present a blob is the pod
  the blob was released to — and with no second pod there is nothing to
  disambiguate, which is why `--guest` needs no peer credentials, the same
  reasoning as the token route on `:8401`.

A node shared between tenants breaks the first and needs a daemon-side check
restored. That needs the caller's *sandbox*, which the node daemon cannot
resolve for itself — the inventory's socket answers only for the process asking
it — so the sandbox would have to arrive as an inventory-signed token bound to a
nonce the daemon issued, because such a token is otherwise transferable between
pods. The kata shape does not need this: moving the daemon inside the guest
removes the second caller instead of authenticating it.

## What this defends

| Threat | |
|---|---|
| Host reads the volume at rest | prevented — AES-XTS, key never leaves the TEE |
| Host tampers with the ciphertext | detected — dm-verity fails the affected read |
| Host rolls the volume back | detected — the root hash covers the whole plaintext |
| Host swaps in a different device | fails closed — wrong key, or wrong root hash |
| A pod outside the grant reads it | refused — no grant, no key |
| An allowlisted but different workload reads it | refused — whole-entry match |

Tamper detection is **lazy**: `veritysetup open` checks the top of the tree, and
a modified data block surfaces as an I/O error when it is read, not at open.

### What it does not

- **Any pod on the node can open a volume whose blob it holds.** The daemon
  authorizes on possession, not entitlement — see [Possession of the blob is the
  authorization](#possession-of-the-blob-is-the-authorization). The blob still
  only comes from CDS, and only to a pod the grant covers.
- **Anyone with pod create or exec RBAC in the workload's namespace can read a
  mounted volume.** Under `--cvm-mode=node` the control plane runs inside the
  node CVM, so this is not a capability the host has — but it is a Kubernetes
  RBAC boundary, not an attested one.
- **Volume integrity is rooted in the operator keys CDS pins**, and CDS's
  arguments are host-supplied. A host that restarts CDS under its own operator
  key can write a matching grant and blob. This is detection rather than
  prevention; the detection is
  `c8s cds verify --operator-keys`, and running it continuously is a
  precondition for trusting a volume.
- **Access patterns are visible.** Which sectors are read, and when, leaks
  structure.
- **Availability.** The host can withhold or destroy the device.
- **Whatever the workload does with the plaintext** once it has it.
