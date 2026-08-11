# Node join policy

`c8s join` and `c8s join-release` have a legacy TDX-only same-image mode.
This is used when `--policy-file` is absent. It compares MRTD, RTMR[1], and
RTMR[2] with the local TDX node exactly as before.

`--policy-file` enables a versioned registry of native SNP and TDX node
policies. The file must be in the measured image root filesystem, or another
read-only filesystem. A writable host mount is rejected. The policy is public
configuration, but it controls release of an RKE2 agent token and is part of
the node's trusted measured state.

Example:

```json
{
  "version": 1,
  "platforms": [
    {
      "platform": "tdx",
      "measurements": ["<96-character MRTD hex>"],
      "allow_peers": ["snp"],
      "tdx": {
        "profiles": [
          {"rtmr_1": "<96-character hex>", "rtmr_2": "<96-character hex>"}
        ]
      }
    },
    {
      "platform": "snp",
      "measurements": ["<96-character LAUNCH_DIGEST hex>"],
      "min_tcb": {"bootloader": 0, "tee": 0, "snp": 0, "microcode": 0},
      "allow_peers": ["tdx"]
    }
  ]
}
```

The node first asks its local attestation service for its own evidence. The
attested evidence selects one preconfigured policy. The service then verifies
the evidence signature, key binding, debug state, platform-specific minimum
TCB, and the platform's measurement pin. A peer follows the same process.
The policy does not trust `--platform` to choose a platform in this mode.

`allow_peers` is required. It states which registered platforms a verified
local node may admit during the join exchange. Both sides must permit the
other platform for a cross-platform join to succeed. The released credential
is still only the RKE2 **agent** token; this mechanism does not release a
server/control-plane token.

The TDX `profiles` field is optional. When present, one complete RTMR[1]/
RTMR[2] pair must match. SNP has no equivalent register rule. Therefore a
cross-platform policy means "registered approved node policies", not "the
same image".

This feature changes only node join. It does not make `c8s install`, the
Helm chart, Kata runtime installation, CDS, or workload scheduling
heterogeneous.
