# Monitoring & operations

Commands to watch the confidential CI runners on the GKE host (`arc-host`,
project `conf-500518`, zone `us-central1-a`).

## One-time: point kubectl at the host

```bash
gcloud container clusters get-credentials arc-host --zone us-central1-a --project conf-500518
```

## Runners & jobs

```bash
# runner pods spawn here, ephemeral (one per job, torn down after)
kubectl -n arc-runners get pods -w

# the actual CI job output (live cargo compile etc.)
kubectl -n arc-runners logs -f <runner-pod-name>

# scale set + autoscaling state
kubectl -n arc-runners get autoscalingrunnerset,ephemeralrunnerset
kubectl get nodes
```

## Listener (the scaling brain)

The listener polls GitHub and decides how many runners to start. If jobs sit
`queued` with no pods, check it here first.

```bash
kubectl -n arc-systems get pods
kubectl -n arc-systems logs -f <confidential-e2e-...-listener>
# healthy: "Calculated target runner count ... assigned job=N"
# 'assigned job=0' while a job is queued = GitHub isn't routing it (see gotchas)
```

## GitHub side

```bash
gh run list  --repo cifrai/attestation-rs-ci
gh run watch <id> --repo cifrai/attestation-rs-ci
gh run view  <id> --repo cifrai/attestation-rs-ci --log
# per-job status:
gh run view  <id> --repo cifrai/attestation-rs-ci --json jobs \
  --jq '.jobs[]|"\(.name): \(.status)/\(.conclusion)"'
```

## GCP Cloud Logging (no kubectl)

```bash
gcloud logging read \
  'resource.type=k8s_container AND resource.labels.namespace_name="arc-runners"' \
  --project conf-500518 --limit 30 --freshness=15m
```

## Gotchas (learned the hard way)

- **Forks can't use self-hosted runners** — and **detaching a fork doesn't fix
  it** (GitHub's Actions backend keeps the fork's runner-ineligibility cached;
  `assigned job=0` forever). Use a **born-non-fork** repo. Symptom: jobs queued,
  listener `assigned job=0`, no runner pods.
- **`pull_request` from a fork-of-this-repo** never gets self-hosted runners
  (security). Same-repo PRs on a non-fork repo are fine.
- **Chart/controller version must match** (`gha-runner-scale-set` ==
  controller version, e.g. `0.14.2`) or no `AutoscalingRunnerSet` is created.
- **Same scale-set name on two clusters** → uninstalling one deregisters the
  other's scale set in GitHub (listener 404s). One name = one cluster.
- **Node SA needs `roles/artifactregistry.reader`** to pull the runner image.
- **`kubectl`/`helm` need `gke-gcloud-auth-plugin`** locally; pin `--kube-context`.
- **YAML:** a colon-space in an unquoted `run:` one-liner is a startup_failure
  (0 jobs). Use `run: |` blocks.

## Cost / teardown

The host bills continuously (~$25-35/mo for `e2-medium` + autoscaling). Tear down
when idle:

```bash
helm uninstall confidential-e2e -n arc-runners
gcloud container clusters delete arc-host --zone us-central1-a --project conf-500518
```
