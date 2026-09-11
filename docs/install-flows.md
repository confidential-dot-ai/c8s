# Install flows

All modes run workloads inside confidential nodes. Choose `node` for the c8s
measured node image, `gke` for GKE confidential nodes, or `aks` for AKS
confidential nodes. Set `--hardware-platform` to `sev-snp` or `tdx` and pin the
node image measurements. The node is one trust domain.

```sh
c8s install --cvm-mode=node --hardware-platform=sev-snp \
  --operator-keys operator-pub.pem --measurements <node-measurement>
```

For one node, add `--single-node` to clear the dedicated CDS node selector.
Add `--volumes` to deploy the encrypted-volume daemon. To expose an existing
workload through tls-lb, adopt it and select it as the upstream:

```sh
c8s install --cvm-mode=node --hardware-platform=sev-snp --single-node \
  --operator-keys operator-pub.pem --measurements <node-measurement> \
  --workload-ref vllm=vllm/deployment/serving:8000 --upstream vllm
```

For TDX, supply the image's RTMR pins using `--rtmrs`, or use a
`--measurements-config` file covering the complete measured image.
See [the quickstart](QUICKSTART.md) and [operator options](operator.md).
