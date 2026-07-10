# Pricing

All prices include hardware-enforced integrity, privacy and verifiability by TEEs.

Two ways to run Confidential:

- **Cloud.** Our infrastructure. Usage-based. Pay for what you use.
- **Licensed.** Your infrastructure. Per hardware unit, per year.

Run on our infra: Cloud. Run on yours: Licensed.

---

## Cloud

On-demand usage. No commitments. Custom pricing is available for high-volume deals, [get in touch](mailto:hello@confidential.ai).

### Confidential Inference

| Model             | Input (per 1M tokens) | Output (per 1M tokens) |
| ----------------- | --------------------- | ---------------------- |
| GLM 5.1           | $1.00                 | $3.50                  |
| Qwen 3.5 35B      | $0.25                 | $2.00                  |
| Qwen3.6 27B       | $0.30                 | $2.00                  |
| DeepSeek V4-Flash | $0.20                 | $0.40                  |
| DeepSeek V4-Pro   | $2.50                 | $5.00                  |

Additional models available on request: [hello@confidential.ai](mailto:hello@confidential.ai).

### Confidential VMs

**GPU VMs**: billed per GPU-hour.

| GPU          | VRAM         | Host CPU TEE             | Per GPU-Hour |
| ------------ | ------------ | ------------------------ | ------------ |
| RTX PRO 6000 | 96 GB GDDR7  | AMD SEV-SNP              | $1.50        |
| H100         | 80 GB HBM3   | AMD SEV-SNP or Intel TDX | $2.00        |
| B200         | 192 GB HBM3e | AMD SEV-SNP or Intel TDX | $5.00        |
| B300         | 288 GB HBM3e | AMD SEV-SNP or Intel TDX | $6.00        |

**CPU VMs**: billed per vCPU core-hour, plus per GB-hour of RAM.

| TEE Backend | Per Core-Hour | Per GB-Hour (RAM) |
| ----------- | ------------- | ----------------- |
| AMD SEV-SNP | $0.05         | $0.012            |
| Intel TDX   | $0.05         | $0.012            |

### Attested Builds

Base rate: $0.008 per vCPU-minute. Runners scale linearly.

| Runner   | Specs          | Per Minute |
| -------- | -------------- | ---------- |
| Standard | 2 vCPU, 8 GB   | $0.016     |
| Medium   | 4 vCPU, 16 GB  | $0.032     |
| Large    | 8 vCPU, 32 GB  | $0.064     |
| XL       | 16 vCPU, 64 GB | $0.128     |

---

## Licensed

Deploy the Confidential stack on your own infrastructure. On-prem, bare metal, all major clouds.

One stack. Licensed per enabled hardware unit, per year.

### What you get

The full confidential-computing stack, one bundle:

- **Confidential Metal**: attestable, verifiable confidential VMs on bare metal.
- **C8s**: Confidential Kubernetes. Scale AI workloads to datacenter scale.
- **AI Workload Services**: Confidential-optimized inference, training, fine-tuning, agents.
- **Confidential OS**: hardened VM guest OS for development and production.
- **Client Libraries & SDKs**: clients verify confidentiality claims themselves.

No per-component line items. Software updates included. Standard support included.

### How pricing works

License per GPU per year, or per CPU-core per year. CPU-cores in machines with GPUs are covered by the GPU license.

Pricing is annual. Same prices in every region.

### GPU licenses

Per GPU, per year:

| GPU class    | Per GPU-Year |
| ------------ | ------------ |
| RTX PRO 6000 | $2,500       |
| H100         | $3,500       |
| H200         | $4,500       |
| B200         | $7,000       |
| B300         | $9,000       |

Each license covers one GPU of that class. Licenses are not tied to unique GPUs; they transfer freely across GPUs of the same class.

GPU prices include Nvidia's requisite Confidential Computing (CC) SKU license. We handle CC licensing with Nvidia on your behalf. No action required.

### CPU-core licenses

Per CPU-core, per year:

|               | Per CPU-core-Year |
| ------------- | ----------------- |
| CPU-core only | $45               |

Covers Intel and AMD cores. Licenses transfer freely across cores. Not required for cores in GPU machines.

### Volume discounts

Tiered and marginal. Each rate applies only to the GPU licenses within that tier.

| GPU licenses    | Rate |
| --------------- | ---- |
| First 20,000    | list |
| 20,000 - 60,000 | -10% |
| Above 60,000    | -20% |

### Support

|                              | Standard        | Enterprise                          |
| ---------------------------- | --------------- | ----------------------------------- |
| Price                        | Included        | 25% of total license price          |
| Coverage                     | Business hours  | 24/7 for production outages         |
| Response, production outage  | 1 business day  | 1 hour                              |
| Contact                      | Shared queue    | Dedicated technical account manager |

### Minimum

$80,000 per month. You are billed the greater of the monthly minimum or your monthly licensed rate.

### Example

500 B200s: 500 x $7,000 = $3,500,000/year, invoiced monthly at about $291,667. That is $583 per GPU per month, with the full stack, Nvidia CC licensing, updates, and support included.

Order of operations at larger scale: license total, then volume discount, then any enterprise support uplift. Multiplicative. Discounts are marginal: each tier's rate applies only to licenses within that tier.

Multi-year and volume commitments are negotiable. [Contact sales](mailto:hello@confidential.ai).

---

## Getting Started

Let us know what you need: [hello@confidential.ai](mailto:hello@confidential.ai).