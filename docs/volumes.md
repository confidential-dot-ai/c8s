# Encrypted volumes

Data too large to be a secret, encrypted at rest on host-visible storage, and
decryptable only inside a TEE by a workload the allowlist names. Model weights
are the case this is built for.

> **Status.** `c8s volume create` builds a volume and stores its key. **Delivery
> is not built yet**: nothing mounts a volume into a pod, so the annotations and
> the daemon described under [Consuming a volume](#consuming-a-volume) do not
> exist. Volumes are read-only; read-write is out of scope.

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

`--name` is capped at 12 characters. The node selects the device by its virtio
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

Attach it as a **raw block device** whose virtio serial is `c8s-vol-<name>`.

A confos node has no persistent writable storage — the root overlay is
reformatted on every boot — so a volume must be its own device rather than a
file on the node's filesystem.

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

> Not built. Described here because the grant and the artifact above are built
> against it.

A pod will name its volumes in an annotation, and an injected sidecar will fetch
the key over the attested `/secrets` flow and hand it to a node daemon that opens
the device and mounts it read-only.

What decides whether a mount happens, in order:

1. CDS releases the blob to the pod's sandbox — verified mesh leaf, single-use
   challenge, inventory-signed sandbox token, whole-container-set match against
   one workload entry, grant covers the path.
2. The daemon **independently** repeats the entry match and the grant check for
   the sandbox the kernel says is calling. Possession of a blob is not authority
   on its own.
3. The device opens only if the key is right and the verity root hash matches.

The volume appears **after the workload starts**, because release is gated on
the whole container set having been admitted. A consumer must wait for it rather
than read it at startup.

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

- **Anyone with pod create or exec RBAC in the workload's namespace can read a
  mounted volume.** Under `--cvm-mode=node` the control plane runs inside the
  node CVM, so this is not a capability the host has — but it is a Kubernetes
  RBAC boundary, not an attested one.
- **Volume integrity is rooted in the operator keys CDS pins**, and CDS's
  arguments are host-supplied. A host that restarts CDS under its own operator
  key can write a matching grant and blob. `THREAT_MODEL.md` records this as
  detection rather than prevention; the detection is
  `c8s cds verify --operator-keys`, and running it continuously is a
  precondition for trusting a volume.
- **Access patterns are visible.** Which sectors are read, and when, leaks
  structure.
- **Availability.** The host can withhold or destroy the device.
- **Whatever the workload does with the plaintext** once it has it.
