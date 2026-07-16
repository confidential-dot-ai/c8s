# Docs sweep (2026-07-16) — 12 pages of confidential.ai/docs vs our lanes

Full-site read (overview, limitations, install/{installation,azure,cli-reference},
runtime/{pod-vs-node-cvm,kata}, verification/consumer, attestation/{cds,allowlist},
whitepaper, attested-builds) diffed against every lane. What changed, what's
queued, what contradicts what.

## Corrections APPLIED to the flagship (commit a066f0d, verifying)

1. **`cds.node.selector: {}` + `tolerations: []`** (was `null`). Helm `null`
   DELETES the key → chart default (dedicated-CDS selector) can resurface; the
   `{}`/`[]` shape is the contract `c8s install --single-node` sets
   (cli-reference). We were green by template accident.
2. **`nriImagePolicy.enabled: true`, `policy.mode: audit`, `distro: rke2`.**
   Our disable rationale ("guest kernel lacks netfilter") was WRONG for this
   component — netfilter is ratls-mesh's constraint (L4 proxy); the NRI plugin
   is a containerd hook. Audit mode is the chart-blessed bring-up (logs
   would-be denials, admits all — zero brick risk). Enforce mode is roadmap:
   needs operator-keyed allowlist (see backlog).

## Corrections PENDING (recorded, not yet applied)

- **Golden semantics**: `cds.measurements` gates *attesters* (workloads/peers),
  not CDS's own digest (that's client-side `--cds-measurements`). Coincides on
  our single node — document, don't change. Our runtime-self-discovery seeding
  is the docs' "inspect, then pin" mode; blessed production path is *predicted*
  (`sev-snp-measure --vcpus 1` / published manifest). We proved manifest.json's
  digest wrong for the KubeVirt boot twice — recompute-with-our-boot-params
  remains the open hardening item; the seeded runtime golden + drift warning is
  the honest interim.
- **Flagship runs allowlist-writes-disabled without acknowledgment** (no
  `cds.operatorKeys`; the CLI would have demanded `--force`). Fine for now
  (audit mode), must change when enforce lands.
- **Consumption proof relies on undocumented behavior**: install docs scope the
  `c8s-cert` injection to `--kata`; node-CVM injection works (lane green) but
  isn't doc-promised. Regression-pin it; consider asking docs/team to bless it.
- **attestation-go vs attestation-rs**: CDS verdicts come from the in-process
  Go port; our 263/263 suite proves the Rust engine. Cross-engine parity is
  unowned.

## Blessed CLI replacements (adopt as c8s binaries become CI-available)

The c8s CLI embeds the chart (`make install` at a sha = chart at that sha) —
our chartContent-from-source stays only because we install in-guest via
helm-controller. When a c8s release binary exists (or we ship it via the
nextest-archive-style vehicle):
- `c8s render-values --distro rke2 --single-node --cvm-mode node --image-tag <sha>`
  → replaces our hand-rolled VALS block; `--resolve-digests` replaces the
  ancestry walk with digest pinning + auto-allowlist.
- `c8s cds verify <host:8443> --measurements <golden> -o json` — exit-code
  contract 0/2/3; the ONLY way to spot an operatorKeys swap (not measured!).
  Wants: in payload once a binary ships.
- `c8s allowlist add/export/diff/upload --dry-run` + `--allowlist-seed` chart
  value — the whole allowlist lifecycle, no custom REST.
- `c8s install --workload-ref nginx=default/deployment/nginx:80` — blessed
  workload adoption (alternative consumption proof).
- `c8s probe-file --wait` (kata init gate), `c8s uninstall --host-sweep-only`
  (kata teardown) — for the kata lane.

## Azure lane — design addendum (see DESIGN-cloud-azure)

- Blessed: `c8s install --single-node --cvm-mode aks --operator-keys op.pub`.
  aks = **vTPM `/dev/tpm0`** (NOT sevGuest — do not copy flagship teeDevices);
  `--hardware-platform` ignored; **aks+tdx REFUSED** → az_tdx_live splits to a
  standalone DCesv5 CVM mini-lane (c8s aks TDX "in progress").
- **ratlsMesh + nriImagePolicy expected ON** for AKS Ubuntu nodes (privileged
  DaemonSets patch containerd/iptables) — the Azure lane is the FIRST place
  mesh + enforcement are testable. Do not copy flagship disables.
- **Per-run operator EC keypair** (P-256): allowlist write tokens carry no
  cluster binding — same key across clusters = 5-min cross-cluster replay.
- Sizes: `Standard_DC2as_v5` for smokes (cheap), DC4as_v5 dev; preflight
  `az vm list-skus -l <region> --size Standard_DC`; region example northeurope.
  System-pool-refuses-CVM-size fallback: user pool + label/taint, drop
  `--single-node`.
- Bare-evidence verify on DCasv5 pins `generation: milan` (not default genoa).
- Docs claim component images private + PAT scopes needed — we VERIFIED the
  ghcr chain anonymous-public; re-verify at lane build, docs may lag or lead.
- Fetch `/docs/c8s/tutorials/azure-e2e` at build time — it's the lane script.

## TDX unblock (moved to DESIGN-tdx-metal)

**kata gives a TDX pod-CVM path TODAY**: `c8s install --kata
--hardware-platform=tdx` renders kata-qemu-tdx; tdx-dev-host-1 already has the
qemu-tdx shims (confidential-metal group_vars). confos PR#51 gates only the
node-CVM TDX cell. One lane on existing hardware covers BOTH the maintainer's
"least-tested" pod-CVM ask AND the TDX priority.

## Coverage backlog (no lane asserts these today — ranked)

1. **Allowlist enforcement** (flagship audit→enforce; deny non-allowlisted
   digest; policy-monitor SIGKILL on kata; multi-arch index-digest pitfall).
2. **`c8s cds verify` exit codes** (0 golden / 2 wrong-pin / 3 CDS-down) +
   UNSAFE-warning string on unpinned mode (the Azure policy-only posture makes
   this string a pinnable golden).
3. **Consumer verification e2e** (tlsLb.attest + c8s-verify-js C8sClient in
   Node ≥20: 5-check fail-closed chain + typed error negatives + wrong-mesh-CA
   cluster-identity test). Blocked on flagship by ratlsMesh; Azure-first?
   NOTE: needs pinned launch digests — policy-only AKS runs it documented-UNSAFE;
   may be snp-metal-only once mesh unblocks.
4. **CDS lifecycle**: restart invalidates leaves (singleton in-memory CA);
   /readyz CA-validity gate; handoff (`cds.handoff.enabled` — measurements
   reused as handoff gate, two-replica testable on one node); challenge replay
   + CSR-key-binding negatives; renewal-as-revocation (remove measurement →
   pod drops from mesh at expiry).
5. **Token replay negative** (cross-cluster, 5-min cap) — pairs with the
   per-run keypair mitigation on Azure.
6. **Debug-guest measurement divergence** (`--kata --debug` must FAIL
   verification vs locked golden).
7. **Composed per-pod evidence** (two pods on one node → distinct certs rooted
   in the same node report).
8. **dm-verity tamper → boot-fail** + published-image→digest offline derivation
   (base-image→boot-c8s lane candidates).
9. **Kettle→manifest admission** (provenance-verified digest appears in
   CDS-signed manifest) — docs say "planned, not wired"; don't claim it.

## Docs↔maintainer-call contradictions (surface to João)

- Whitepaper: pod-level is the DEFAULT boundary + "CDS runs inside a CVM and
  is itself attested" + attested LB. Call: node-CVM is the developed path,
  pod-CVM least-tested, "LB/CDS/OCI not necessarily CVMs". Docs overclaim vs
  today's reality — our lanes should regression-pin reality and flag the gap.
- Install docs say component images are private; the whole chain verified
  anonymous-public on ghcr (2026-07-15).
- Docs name the injected container `get-cert` (overview) vs `c8s-cert`
  (install verify snippet — matches our green assertion).
