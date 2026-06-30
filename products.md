# Products

Private AI, built in layers from the hardware up. Prompts, weights, data, and agent state stay encrypted in memory while they run, and every result carries a cryptographic attestation of what ran and where.

Run the whole stack yourself, take a single layer, or have us operate all of it as a service.

```
┌────────────────────────────────────────────────────────┐
│     Confidential Inference  /  Confidential Agents     │
│       private AI, operated for you as a service        │
╞════════════════════════════════════════════════════════╡
│             Confidential Kubernetes  (C8s)             │
│        one CVM becomes a platform you can scale        │
╞════════════════════════════════════════════════════════╡
│                   Confidential Metal                   │
│          hardware becomes a CVM you can trust          │
╞════════════════════════════════════════════════════════╡
│   TEE hardware: AMD SEV-SNP / Intel TDX / NVIDIA CC    │
└────────────────────────────────────────────────────────┘
```

## Confidential Metal

The foundation. Confidential Metal turns on confidential computing in the hardware and hands back a CVM whose measurement actually means something: a minimal, hardened image, a reproducible launch measurement, and build provenance signed by the hardware.

```
╔════════════════════════════════════════════╗
║              Confidential VM               ║
║                                            ║
║           minimal hardened image           ║
║      reproducible launch measurement       ║
║          signed build provenance           ║
╚════════════════════════════════════════════╝
                      │
                      ▼  attestation
┌────────────────────────────────────────────┐
│        measured, attested, trusted         │
└────────────────────────────────────────────┘
```

## Confidential Kubernetes

One CVM is not a service. Confidential Kubernetes (C8s) turns it into a platform you can host and scale on. Every workload gets an attested identity, all traffic between components is encrypted, and the control plane stays outside the boundary, so an operator can run your workloads without ever seeing them.

```
┌──────────────────────────────────────────────────────┐
│    Control plane   (untrusted, outside boundary)     │
└──────────────────────────────────────────────────────┘
                           │  schedules
╔══════════════════════════════════════════════════════╗
║                                                      ║
║       [ Pod CVM ]   [ Pod CVM ]   [ Pod CVM ]        ║
║          attested identity, encrypted mesh           ║
║                                                      ║
║          CDS - root of trust, issues certs           ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
            hardware-enforced trust boundary            
```

## Confidential Inference

Private AI without running any of it yourself. Swap one base URL for our OpenAI-compatible API; your prompts, responses, and the model weights stay encrypted in CVM memory, with an attestation on every response.

```
┌──────────────────────────────────────────────────┐
│                     Your app                     │
│                swap one base URL                 │
└──────────────────────────────────────────────────┘
                         │  OpenAI-compatible API
                         ▼
╔══════════════════════════════════════════════════╗
║                  TEE model pool                  ║
║      prompts + weights encrypted in memory       ║
╚══════════════════════════════════════════════════╝
                         │
                         ▼  response + attestation
┌──────────────────────────────────────────────────┐
│                     Your app                     │
└──────────────────────────────────────────────────┘
```

## Confidential Agents

A private, isolated environment for your AI agent, ready over SSH in under 15 seconds, preloaded with an agent runtime and attested inference. The code, data, and keys inside are invisible to everyone but you, including us. Treat each one as disposable: spin it up for a task, run it, throw it away.

```
┌────────────────────────────────────────────────┐
│              You hold the SSH key              │
└────────────────────────────────────────────────┘
                        │  ssh, ready in <15s
                        ▼
╔════════════════════════════════════════════════╗
║                   Agent CVM                    ║
║                                                ║
║       agent runtime + attested inference       ║
║        code, data, keys invisible to us        ║
║                                                ║
║           disposable - one per task            ║
╚════════════════════════════════════════════════╝
```

## How they fit together

Confidential Metal produces trustworthy CVMs. Confidential Kubernetes turns them into a platform that can host and scale a real service. Confidential Inference and Confidential Agents are that platform, run for you. Operate it yourself from the metal up, or hand off any layer, the attestation guarantees are the same either way.

To scope a deployment, [contact sales](mailto:hello@confidential.ai).
