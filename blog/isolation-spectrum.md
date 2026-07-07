# The Isolation Spectrum: From Plaintext to TEEs

*Sandboxes, containers, microVMs, and TEEs all claim to isolate your workload. They are not doing the same job. Here is the map.*

---

There is one question that sorts every isolation technology into place:

**Can the host read your memory?**

The host is whoever runs the machine: the cloud provider, the platform operator, the admin with root. Ask the question at every tier and the map draws itself.

```
plaintext → isolate → container → microVM → TEE
   yes        yes        yes        yes      no
```

Four yeses and one no. Everything below explains why the line flips exactly there, and nowhere earlier.

## Tier 0: Plaintext

No boundary. Your code and data sit in memory, readable by any process with sufficient privilege. This is a workload running directly on a machine, or in a standard VM where you only care about the guest's internals.

- Protects: nobody
- Enforced by: nothing
- Host sees your data: yes

## Tier 1: Runtime isolates

V8 isolates, as used by edge platforms like Cloudflare Workers. Many tenants share a single OS process. The boundary between them is the JavaScript engine's heap and context separation. No separate address space, no separate kernel namespaces.

This is why isolates cold-start in microseconds. It is also why the boundary is thin. You are trusting the correctness of a large JIT-compiling engine, and platforms that run isolates at scale layer additional sandboxing around them, partly because of Spectre-class side channels between tenants in one process.

- Protects: the host and co-tenants, from your code
- Enforced by: the JavaScript engine
- Host sees your data: yes

## Tier 2: Containers and sandboxes

The default unit of cloud deployment. Namespaces, cgroups, and seccomp filters carve one kernel into many apparent machines. Sandboxes like gVisor add a syscall interception layer on top.

Containers do their job well. That job is to stop a workload from escaping, damaging the machine, or touching other workloads. It points inwards. The kernel that enforces the boundary can read every byte inside it, and so can anyone who controls that kernel.

- Protects: the host and other tenants, from your workload
- Enforced by: the OS kernel, the thing you are trusting
- Host sees your data: yes

## Tier 3: MicroVMs

Firecracker, Kata Containers, and similar. Each workload gets its own guest kernel inside a minimal virtual machine. The boundary is enforced with hardware virtualization: VT-x, AMD-V, nested page tables. This is the strongest software-side boundary, and it is why AWS runs Lambda on Firecracker rather than bare containers.

This tier is where people get confused, because "hardware" enters the vocabulary. So be precise:

**Hardware-assisted is not hardware-enforced.**

In a microVM, the CPU's virtualization features work for the hypervisor. The hypervisor builds the page tables, and it can read, dump, snapshot, or live-migrate guest memory whenever it likes. Guest memory is plaintext to the host. The virtualization extensions make the wall cheaper to build. The landlord still holds the master key.

- Protects: the host and other tenants, from your workload
- Enforced by: the CPU, on behalf of the hypervisor
- Host sees your data: yes

## Tier 4: TEEs

Trusted Execution Environments: AMD SEV-SNP, Intel TDX, NVIDIA Confidential Computing on the GPU side. Same virtualization machinery as tier 3, with one inversion that changes everything.

The CPU encrypts the workload's memory with keys generated and held inside the silicon. The hypervisor is outside the trust boundary. It can schedule the workload, allocate its resources, and kill it. It cannot read it. Neither can the OS, the cloud provider, or an admin with root. To every layer of software on the host, your memory is ciphertext.

And you do not have to take anyone's word for it. Remote attestation gives you a cryptographic proof, signed by the chip vendor's keys, of exactly what code booted inside the TEE and that the protections are on. Every other tier asks you to trust the operator. This one lets you verify.

- Protects: your workload, from the host
- Enforced by: the CPU, against the hypervisor
- Host sees your data: no

## The direction of protection

Line the tiers up and the real pattern is not strength. It is direction.

Tiers 1 through 3 all point inwards. They protect the infrastructure from the code. Each one builds a thicker wall, but the wall is always operated by the host, for the host. Climbing from container to microVM changes how hard it is for your workload to break out. It changes nothing about who can look in.

TEEs point outwards. They protect the code and data from the infrastructure. That is not a stronger version of the same guarantee. It is a different guarantee.

Which means the tiers are not competitors. A sandbox inside a TEE gives you both directions at once: the host cannot see the workload, and the workload cannot harm the host. That is the correct architecture for running untrusted code on data that must stay private.

One scoping note for the careful reader: TEEs defend against software on the host. Physical attacks on the machine and microarchitectural side channels are a separate threat model with their own mitigations, and vendors patch that surface continuously. For the threat model that matters in practice, an operator or provider reading your data, the guarantee holds.

Condensed, the whole spectrum collapses to three distinctions:

```
┌───────────────────────┬────────────┬─────────────────┬─────────────────┬───────────────────────┐
│ Model                 │ Isolation  │ Protects        │ Host sees data  │ Enforced by           │
├───────────────────────┼────────────┼─────────────────┼─────────────────┼───────────────────────┤
│ Plaintext VM          │ none       │ nobody          │ yes             │ nothing               │
├───────────────────────┼────────────┼─────────────────┼─────────────────┼───────────────────────┤
│ Sandbox or container  │ software   │ the host        │ yes             │ the OS and hypervisor │
├───────────────────────┼────────────┼─────────────────┼─────────────────┼───────────────────────┤
│ TEE                   │ hardware   │ your workload   │ no              │ CPU with attestation  │
└───────────────────────┴────────────┴─────────────────┴─────────────────┴───────────────────────┘
```

## Why this matters for AI

AI workloads are the worst case for tiers 0 through 3. Prompts, model weights, training data, and agent context all sit in memory, in plaintext, on machines you usually do not own. Every "yes" on the map above is a party that can read them: the cloud provider, the platform, the inference host.

If your threat model includes the infrastructure, and for proprietary weights, regulated data, or agents acting on your behalf it should, then software isolation is not a mitigation. It was never designed to be one.

This is the boundary Confidential builds on. Private inference, private weights, private training, private agents: all of it runs inside TEEs, attested, with the host locked out by the silicon itself.

The host cannot leak what the host cannot read.

---

*Want the short version? Ask one question: can the host read your memory? If the answer is yes, it is not confidential computing.*
